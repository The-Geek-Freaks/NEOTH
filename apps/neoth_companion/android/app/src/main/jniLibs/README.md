# Reviewed native artifacts required

The Android package consumes a prebuilt `libneoth_companion_bridge.so` from
the reviewed Rust bridge release. Place it in one directory per supported ABI:

```text
arm64-v8a/libneoth_companion_bridge.so
armeabi-v7a/libneoth_companion_bridge.so
x86_64/libneoth_companion_bridge.so
```

The official Flutter 3.24.5 generated Android project uses the default
`src/main/jniLibs` source set, so no authored Gradle file is carried here.
The hosted materializer must preserve that generated Groovy project and copy
only hash-verified manifest leaves to these exact paths. They are intentionally
absent from this source candidate: no locally compiled or unverified binary
may be presented as a phone-ready bridge.
