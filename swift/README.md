# swift/ — Swift wrapper (scaffold)

Planned layout:

- `Package.swift` + `Sources/Autocipher` — Swift Package Manager module.
- `Autocipher.podspec` — CocoaPods manifest (iOS).
- `Frameworks/` — the `autocipher_ffi.xcframework` built by the CI matrix
  (`cargo build` per target triple) for iOS/macOS consumers.

Status: **scaffold only**. The typed `Vault` Swift API is pending a
`#[ac_fn]` Swift renderer; callers can already import
`include/autocipher_capi.h` via the umbrella header.

Build: `swift build --package-path swift`