Pod::Spec.new do |s|
  s.name             = "Autocipher"
  s.version          = "0.1.0"
  s.summary          = "Swift/CocoaPods wrapper for the autocipher vault engine."
  s.homepage         = "https://example.invalid/autocipher"
  s.license          = { :type => "GPL-3.0-only" }
  s.author           = { "autocipher" => "noreply@example.invalid" }
  s.source           = { :path => "." }

  s.swift_version    = "5.9"
  s.ios.deployment_target = "15.0"
  s.macos.deployment_target = "13.0"

  s.source_files     = "Sources/Autocipher/**/*.{swift,h}"
  s.public_header_files = "Sources/Autocipher/include/**/*.h"
  s.pod_target_xcconfig = {
    "HEADER_SEARCH_PATHS" => "$(PODS_TARGET_SRCROOT)/../../include"
  }

  # The vendored framework links the native engine.
  s.vendored_frameworks = "Frameworks/autocipher_ffi.xcframework"
end