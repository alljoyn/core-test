## Directory Structure

* `scl` - contains test programs to exercise AllJoyn Standard Client Library
* `tcl` - contains test programs to exercise AllJoyn Thin Client Library
* `misc` - contains test programs that don't quite classify as `scl` or `tcl`

## Build Instructions for `scl`
Pre-requisites specified at [this link](https://allseenalliance.org/developers/develop/building) need to be installed for the platform on which you are building.

Set environment variable `AJ_CORE_SRC_DIR` to the AllJoyn Core source tree. The SCons variable `AJ_CORE_DIST_DIR` would point to the platform SDK containing the built libraries. _Note: It is assumed that the version of source and the SDK match._

### Linux
If you have pulled down AllJoyn Core source and built it on Linux, the `dist` folder location under `build` directory is essentially set as `AJ_CORE_DIST_DIR`.

### Windows
Using the [14.12a Windows SDK *(zip)*](https://allseenalliance.org/releases/alljoyn/14.12/alljoyn-14.12.00a-win7x64vs2013-sdk.zip):

`setx AJ_CORE_SRC_DIR C:\alljoyn-14.12.00a-src`

`scons OS=win7 CPU=x86_64 VARIANT=debug AJ_CORE_DIST_DIR=C:\alljoyn-14.12.00a-win7x64vs2013-sdk-dbg GTEST_DIR="C:\path\to\gtest"`

`scons OS=win7 CPU=x86_64 VARIANT=release AJ_CORE_DIST_DIR=C:\alljoyn-14.12.00a-win7x64vs2013-sdk-rel GTEST_DIR="T:\path\to\gtest"`

In this example, make sure that the alljoyn and ajtcl projects are built with x86_64.  Your GTEST_DIR path will probably be different.
For normal SCL builds the AJ_CORE_DIST_DIR is something like "C:\path\to\alljoyn\build\win7\x86_64\debug\dist". 
After building the tests, to run the TC-SC interaction tests, run scl\ajtcsctest.exe. 

### Android
Using the [14.12a Android SDK Debug *(zip)*](https://allseenalliance.org/releases/alljoyn/14.12/alljoyn-14.12.00a-android-sdk-dbg.zip):

`export AJ_CORE_SRC_DIR=/path-prefix-to-/alljoyn-14.12.00a-src`

`scons OS=android CPU=arm VARIANT=debug AJ_CORE_DIST_DIR=/path-prefix-to-/alljoyn-android/core/alljoyn-14.12.00a-dbg ANDROID_NDK=/opt/android-tools/android-ndk-r9d`
## Build Instructions for `tcl`
Currently, there is **no** build support currently for the test programs present in `tcl` directory.
