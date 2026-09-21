// swift-tools-version: 5.9
// Swift wrapper around the autocipher C ABI (scaffold).
//
// Planned: `native_swift` (or the existing generator family) renders these
// bindings from the same `#[ac_fn]` definition set. Until then, this module
// exposes the raw C symbols from `include/autocipher_capi.h` (already tracked
// in the repo) so Swift callers can call the engine directly.

import PackageDescription

let package = Package(
    name: "Autocipher",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "Autocipher", targets: ["Autocipher"])
    ],
    targets: [
        .target(
            name: "Autocipher",
            path: "Sources/Autocipher",
            publicHeadersPath: "include",
            cSettings: [.headerSearchPath("../../../include")]
        )
    ]
)