/*
 * GENERATED CODE — DO NOT EDIT. Run: just generate-c
 * The authoritative definition set is in rust/bridge/shared/src (the #[ac_fn] list).
 */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle to an open .ac vault. */
typedef void autocipher_vault;

/* Caller-owned I/O buffer for byte payloads.
 * Protocol: on entry the caller may set base to a buffer of len
 * capacity. An op that returns n bytes copies them in when
 * capacity >= n and sets len = n; otherwise it sets base = NULL and
 * len = n so the caller can allocate exactly the reported size and
 * call again. len == 0 means no payload. */
typedef struct autocipher_out_buffer {
  uint8_t* base;
  size_t len;
} autocipher_out_buffer;

#define AUTOCIPHER_ABI_MAJOR 1
#define AUTOCIPHER_ABI_MINOR 0

/* ABI handshake. */
int32_t ac_version(int32_t* out_major, int32_t* out_minor, int32_t* out_patch);
/* Diagnostic text from the most recent failed call. */
int32_t autocipher_error_message(autocipher_out_buffer* out);

/* Opaque handle lifecycle. */
void autocipher_vault_destroy(autocipher_vault* v);

/* Import files/trees; `items` is an encoded AddPaths protobuf. Returns the number of files added. */
/* op */
int32_t autocipher_vault_add_paths(autocipher_vault* me, const uint8_t* items, size_t items_len, uint32_t* count);
/* Re-wrap the master key under a new password and KDF parameters; `params` is encoded KdfParams. */
/* op */
int32_t autocipher_vault_change_password(autocipher_vault* me, const uint8_t* new_password, size_t new_password_len, const uint8_t* params, size_t params_len);
/* Rewrite the vault file to drop garbage space. */
/* op */
int32_t autocipher_vault_compact(autocipher_vault* me);
/* Create a new empty vault at `path` with the given KDF parameters and password. */
/* constructor: writes an opaque handle into out_handle (NULL handles are never written). */
int32_t autocipher_vault_create(const uint8_t* path, size_t path_len, const uint8_t* password, size_t password_len, const uint8_t* params, size_t params_len, void** out_handle);
/* Delete the named stored file. */
/* op */
int32_t autocipher_vault_delete(autocipher_vault* me, const uint8_t* name, size_t name_len);
/* Extract the named stored file to `dest` on the filesystem. */
/* op */
int32_t autocipher_vault_extract(autocipher_vault* me, const uint8_t* name, size_t name_len, const uint8_t* dest, size_t dest_len);
/* Aggregate vault metadata as an encoded VaultInfo protobuf. */
/* op */
int32_t autocipher_vault_info(autocipher_vault* me, autocipher_out_buffer* out);
/* List the files in the vault as an encoded FileInfoList protobuf. */
/* op */
int32_t autocipher_vault_list(autocipher_vault* me, autocipher_out_buffer* out);
/* Open the vault at `path` with the given password. */
/* constructor: writes an opaque handle into out_handle (NULL handles are never written). */
int32_t autocipher_vault_open(const uint8_t* path, size_t path_len, const uint8_t* password, size_t password_len, void** out_handle);
/* Write `data` to the named stored file, creating or overwriting it. */
/* op */
int32_t autocipher_vault_put(autocipher_vault* me, const uint8_t* name, size_t name_len, const uint8_t* data, size_t data_len);
/* Read `len` bytes starting at `offset` from the named stored file. */
/* op */
int32_t autocipher_vault_read_range(autocipher_vault* me, const uint8_t* name, size_t name_len, uint64_t offset, uint64_t len, autocipher_out_buffer* out);
/* Rewrite the sidecar mirrors from the primary vault file. */
/* op */
int32_t autocipher_vault_remirror(autocipher_vault* me);
/* Rename the stored file `old` to `new`. */
/* op */
int32_t autocipher_vault_rename(autocipher_vault* me, const uint8_t* old, size_t old_len, const uint8_t* new_name, size_t new_name_len);
/* Return the uncompressed size in bytes of the named stored file. */
/* op */
int32_t autocipher_vault_size(autocipher_vault* me, const uint8_t* name, size_t name_len, uint64_t* out);

#ifdef __cplusplus
}
#endif
