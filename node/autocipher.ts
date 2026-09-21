// Placeholder for the Node.js wrapper around the autocipher C ABI.
//
// Planned: `native_ts` renders a `koffi`/`ffi-napi` binding from the same
// `#[ac_fn]` definition set as the C/Dart/Swift wrappers. Until then, this
// module documents the ABI surface it will expose.
//
// Load order mirrors the other wrappers:
//   1. AUTOCIPHER_FFI_LIB env var,
//   2. ./node_modules/@autocipher/prebuilt's bundled libautocipher_ffi.*,
//   3. the plain system library name.

export const ABI = {
  major: 1,
  minor: 0,
} as const;

/** The stable surface the binding will expose once generated. */
export interface Autocipher {
  version(): { major: number; minor: number; patch: number };
  create(path: string, password: string, kdf: KdfPreset): Promise<number>;
  open(path: string, password: string): Promise<number>;
  destroy(handle: number): void;
  list(handle: number): Promise<FileInfo[]>;
}

export type KdfPreset = { memoryMiB: 128 | 256 | 512; t: number; p: number };

export interface FileInfo {
  name: string;
  sizeBytes: number;
}