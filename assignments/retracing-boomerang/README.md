# Retracing Boomerang Attack on Five Round AES with Secret S-Boxes

This folder contains an implementation of the retracing boomerang attack on AES reduced to five rounds with secret s-boxes.

## Setup

This code has been tested on Debian 12 (bookworm) and runs on Linux systems. The following packages are required to run this code: `cmake`, `libm4ri`, `libm4rie`, `pkg-config`. Ensure that these packages are available on your system.

## Building

Create a build directory in this folder.

```bash
mkdir build
```

Then, create the makefiles using CMake. You may also specify the build type in the command below using `-DCMAKE_BUILD_TYPE=Type` where `Type` is either `Debug` or `Release`.

```bash
cmake ..
```

Finally, to build the executables, run the following command.

```bash
cmake --build .
```

## Testing

A few tests have been provided in the `tests` directory. These can be run after building using CTest by simply issuing the command

```bash
ctest
```