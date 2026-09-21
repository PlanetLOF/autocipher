// Placeholder for the JVM wrapper around the autocipher C ABI.
//
// Planned: `autocipher-bridge-codegen` produces this binding from the same
// `#[ac_fn]` definition set that drives the C, Dart, Swift and Node wrappers;
// until the `native_kt` generator lands, the Rust engine is reached from
// Kotlin/Java through the JNI shim crate (`rust/bridge/codegen/jni`) back to
// the exact functions declared in `include/autocipher_capi.h`.
//
// The JAR loads the library with the same search order as the Dart side:
//   1. `AUTOCIPHER_FFI_LIB` env var (absolute path),
//   2. the bundled `libautocipher_ffi.*` under `src/main/resources/native/`,
//   3. the plain system library name.
package org.autocipher;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Entry point of the org.autocipher JVM wrapper. */
public final class Autocipher {
    private Autocipher() {}

    private static final String LIB_NAME =
        System.mapLibraryName("autocipher_ffi");

    /** Load the native engine, honouring {@code AUTOCIPHER_FFI_LIB}. */
    public static void load() {
        String override = System.getenv("AUTOCIPHER_FFI_LIB");
        if (override != null && !override.isBlank()) {
            System.load(Path.of(override).toAbsolutePath().toString());
            return;
        }
        try {
            System.loadLibrary("autocipher_ffi");
        } catch (UnsatisfiedLinkError e) {
            throw new UnsatisfiedLinkError(
                "autocipher native library not found. Build it with `just "
                    + "build-ffi`, bundle it under native/, or set "
                    + "AUTOCIPHER_FFI_LIB. (" + e.getMessage() + ")");
        }
    }
}