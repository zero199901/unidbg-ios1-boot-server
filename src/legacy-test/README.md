# Legacy test sources

This directory keeps tests that target the original Android-oriented unidbg setup.
They are intentionally outside Maven's default `src/test/java` source root because this
project now builds against `unidbg-ios` and does not include Android emulator dependencies.

`RegisterNativeTest.java` requires Android unidbg classes such as `AndroidEmulator`,
`AndroidResolver`, and the Dalvik VM APIs, as well as an Android APK/native-library fixture.
To run it, move or copy the source into a dedicated Android unidbg module with the matching
Android dependencies and test artifacts.
