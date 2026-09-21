//! Fixed 64 KiB streaming chunk I/O for the `.ac` data area.
//!
//! [`ChunkWriter`] seals plaintext into fixed [`CHUNK_SIZE`] chunks with
//! per-chunk HKDF content subkeys and appends them to the container's data
//! area; [`ChunkReader`] locates and decrypts those chunks back to a writer.
//! Each chunk is bound to `(file_id, chunk_idx, generation)` by the AEAD AAD
//! enforced in [`autocipher_core::content`].

use std::io::{Read, Seek, SeekFrom, Write};

use autocipher_core::content::{self, CHUNK_SIZE};
use autocipher_core::subkeys::derive_subkey;

use crate::error::Result;
use crate::manifest::ChunkRef;

/// HKDF purpose tag for per-chunk content subkeys.
pub const CONTENT_PURPOSE: &[u8] = b"content";

/// Read + seek capability over the container file.
pub trait ReadSeek: Read + Seek {}

impl<T: Read + Seek> ReadSeek for T {}

/// Streaming context that appends sealed chunks to the container's data area.
pub struct ChunkWriter<'a> {
    sink: &'a mut dyn Write,
    master: &'a [u8],
    file_id: &'a [u8],
    generation: &'a [u8],
    chunk_idx: u64,
    next_offset: u64,
}

impl<'a> ChunkWriter<'a> {
    /// Create a writer appending to `sink`, starting at `start_offset`.
    ///
    /// `master` is the unwrapped vault master key; `file_id` and `generation`
    /// are bound into every chunk's AAD.
    pub fn new(
        sink: &'a mut dyn Write,
        master: &'a [u8],
        file_id: &'a [u8],
        generation: &'a [u8],
        start_offset: u64,
    ) -> Self {
        Self {
            sink,
            master,
            file_id,
            generation,
            chunk_idx: 0,
            next_offset: start_offset,
        }
    }

    /// Seal `plaintext` (at most [`CHUNK_SIZE`] bytes) and append it to the
    /// data area, returning its [`ChunkRef`].
    pub fn write_chunk(&mut self, plaintext: &[u8]) -> Result<ChunkRef> {
        let offset = self.next_offset;
        let subkey = derive_subkey(self.master, CONTENT_PURPOSE, self.file_id, self.chunk_idx);
        let subkey_arr: [u8; 32] = subkey
            .as_ref()
            .try_into()
            .expect("derive_subkey always returns a 32-byte subkey");
        let sealed = content::seal_chunk(
            &subkey_arr,
            self.generation,
            self.file_id,
            self.chunk_idx,
            plaintext,
        )?;
        self.sink.write_all(&sealed)?;
        let len = sealed.len() as u32;
        self.next_offset += u64::from(len);
        self.chunk_idx += 1;
        Ok(ChunkRef { offset, len })
    }

    /// The absolute offset at which the next chunk will be written.
    pub fn offset(&self) -> u64 {
        self.next_offset
    }
}

/// Read the whole `reader` in fixed [`CHUNK_SIZE`] chunks, seal each with the
/// next content subkey, and append the resulting chunks to `writer`, returning
/// the [`ChunkRef`] list in storage order.
pub fn write_stream(writer: &mut ChunkWriter, reader: &mut dyn Read) -> Result<Vec<ChunkRef>> {
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut refs = Vec::new();
    loop {
        let mut filled = 0usize;
        while filled < CHUNK_SIZE {
            let n = reader.read(&mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        refs.push(writer.write_chunk(&buf[..filled])?);
        if filled < CHUNK_SIZE {
            break;
        }
    }
    Ok(refs)
}

/// Streaming context that reads and decrypts chunks from the container's data
/// area.
pub struct ChunkReader<'a> {
    src: &'a mut dyn ReadSeek,
    master: &'a [u8],
    file_id: &'a [u8],
    generation: &'a [u8],
}

impl<'a> ChunkReader<'a> {
    /// Create a reader over the container, positioned by each [`ChunkRef`].
    pub fn new(
        src: &'a mut dyn ReadSeek,
        master: &'a [u8],
        file_id: &'a [u8],
        generation: &'a [u8],
    ) -> Self {
        Self {
            src,
            master,
            file_id,
            generation,
        }
    }

    /// Seek to `chunk`, decrypt it with the content subkey for `chunk_idx`, and
    /// write the plaintext to `writer`.
    pub fn read_chunk(
        &mut self,
        chunk: &ChunkRef,
        chunk_idx: u64,
        writer: &mut dyn Write,
    ) -> Result<()> {
        self.src.seek(SeekFrom::Start(chunk.offset))?;
        let mut sealed = vec![0u8; chunk.len as usize];
        self.src.read_exact(&mut sealed)?;

        let subkey = derive_subkey(self.master, CONTENT_PURPOSE, self.file_id, chunk_idx);
        let subkey_arr: [u8; 32] = subkey
            .as_ref()
            .try_into()
            .expect("derive_subkey always returns a 32-byte subkey");
        let plaintext = content::open_chunk(
            &subkey_arr,
            self.generation,
            self.file_id,
            chunk_idx,
            &sealed,
        )?;
        writer.write_all(plaintext.as_ref())?;
        Ok(())
    }
}

/// Decrypt `chunks` in order (chunk index = position in the slice) and write
/// the concatenated plaintext to `writer`.
pub fn read_stream(
    reader: &mut ChunkReader,
    chunks: &[ChunkRef],
    writer: &mut dyn Write,
) -> Result<()> {
    for (idx, chunk) in chunks.iter().enumerate() {
        reader.read_chunk(chunk, idx as u64, writer)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const MASTER: &[u8] = b"0123456789abcdef0123456789abcdef";
    const FILE_ID: &[u8] = b"file-abc";
    const GENERATION: &[u8] = b"gen-0";
    const DATA_START: u64 = 8192;

    /// Sealed-chunk byte length for a plaintext of `pt_len` bytes.
    fn sealed_len(pt_len: usize) -> usize {
        12 + pt_len + 16
    }

    /// Write `data` into a container buffer, returning (bytes, ChunkRefs).
    fn write_into_container(
        data: &[u8],
        file_id: &[u8],
        generation: &[u8],
    ) -> (Vec<u8>, Vec<ChunkRef>) {
        // Pre-fill the buffer to DATA_START so the 8 KiB header region exists
        // before the data area, matching real `.ac` logical offsets.
        let mut container = Cursor::new(vec![0u8; DATA_START as usize]);
        container.set_position(DATA_START);
        let refs = {
            let mut writer =
                ChunkWriter::new(&mut container, MASTER, file_id, generation, DATA_START);
            write_stream(&mut writer, &mut Cursor::new(data.to_vec())).unwrap()
        };
        (container.into_inner(), refs)
    }

    /// Read chunk data back out of a container buffer.
    fn read_container(
        bytes: &[u8],
        refs: &[ChunkRef],
        file_id: &[u8],
        generation: &[u8],
    ) -> Result<Vec<u8>> {
        let mut src = Cursor::new(bytes.to_vec());
        let mut reader = ChunkReader::new(&mut src, MASTER, file_id, generation);
        let mut out = Vec::new();
        read_stream(&mut reader, refs, &mut out)?;
        Ok(out)
    }

    #[test]
    fn chunking_stream_single_chunk_roundtrip() {
        let data = b"the quick brown fox".repeat(1000);
        let (bytes, refs) = write_into_container(&data, FILE_ID, GENERATION);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].offset, DATA_START);
        assert_eq!(refs[0].len as usize, sealed_len(data.len()));
        let out = read_container(&bytes, &refs, FILE_ID, GENERATION).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn chunking_stream_multi_chunk_roundtrip() {
        let data: Vec<u8> = (0u32..200_000).map(|i| (i % 251) as u8).collect();
        let expected_chunks = data.len().div_ceil(CHUNK_SIZE);
        let (bytes, refs) = write_into_container(&data, FILE_ID, GENERATION);
        assert_eq!(refs.len(), expected_chunks);
        // Offsets must be sequential and contiguous within the data area.
        for w in refs.windows(2) {
            assert_eq!(w[0].offset + u64::from(w[0].len), w[1].offset);
        }
        assert!(refs.last().unwrap().offset + u64::from(refs.last().unwrap().len) > DATA_START);
        let out = read_container(&bytes, &refs, FILE_ID, GENERATION).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn chunking_stream_empty() {
        let mut container = Cursor::new(Vec::new());
        let mut writer = ChunkWriter::new(&mut container, MASTER, FILE_ID, GENERATION, DATA_START);
        let refs = write_stream(&mut writer, &mut Cursor::new(Vec::new())).unwrap();
        assert!(refs.is_empty());
        assert_eq!(writer.offset(), DATA_START);
        assert!(container.into_inner().is_empty());
    }

    #[test]
    fn chunking_stream_exact_chunk_boundary() {
        // Exactly two full chunks: the loop must not produce a trailing empty one.
        let data = vec![7u8; CHUNK_SIZE * 2];
        let (bytes, refs) = write_into_container(&data, FILE_ID, GENERATION);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].len as usize, sealed_len(CHUNK_SIZE));
        assert_eq!(refs[1].offset, refs[0].offset + u64::from(refs[0].len));
        let out = read_container(&bytes, &refs, FILE_ID, GENERATION).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn chunking_aad_binding_wrong_file_id() {
        let data = b"bound to file-abc".repeat(50);
        let (bytes, refs) = write_into_container(&data, FILE_ID, GENERATION);
        assert!(read_container(&bytes, &refs, b"file-other", GENERATION).is_err());
    }

    #[test]
    fn chunking_aad_binding_wrong_generation() {
        let data = b"bound to gen-0".repeat(50);
        let (bytes, refs) = write_into_container(&data, FILE_ID, GENERATION);
        assert!(read_container(&bytes, &refs, FILE_ID, b"gen-1").is_err());
    }

    #[test]
    fn chunking_aad_binding_wrong_master() {
        let data = b"secret payload".repeat(10);
        let (bytes, refs) = write_into_container(&data, FILE_ID, GENERATION);
        let other_master = b"ffffffffffffffffffffffffffffffff";
        let mut src = Cursor::new(bytes);
        let mut reader = ChunkReader::new(&mut src, other_master, FILE_ID, GENERATION);
        let mut out = Vec::new();
        assert!(read_stream(&mut reader, &refs, &mut out).is_err());
    }

    #[test]
    fn chunking_tamper_fails() {
        let data = b"tamper me".repeat(20);
        let (mut bytes, refs) = write_into_container(&data, FILE_ID, GENERATION);
        let last = bytes.last_mut().unwrap();
        *last ^= 0x01;
        assert!(read_container(&bytes, &refs, FILE_ID, GENERATION).is_err());
    }
}
