# Reviewed native framework required

`NEOTHCompanionBridge.xcframework` is supplied by the reviewed Rust bridge
release and linked through `NEOTHCompanionBridge.podspec`. It is deliberately
not manufactured in this candidate. The iOS package must fail closed when the
framework is absent; it must never substitute a Dart network implementation.
