# Overview

This application can decrypt backups produced by [Wire](https://wire.com/) for iOS using the correct password.

After applying, you get a zip-compressed file containing several other files. The most interesting one are sqlite-databases.

# Compiling

For compiling you need the [meson build system](https://mesonbuild.com/), [ninja](https://ninja-build.org/), a good c++-compiler and [libsodium](https://download.libsodium.org/doc/) installed with its headers.

In the source directory run:

```bash
meson build && cd build && ninja
```

You get the executable named "decrypt".

On MacOS the default clang compiler does not support `std::any`, which was introduced in c++17. At least the headers cannot be found. As a workaround you can install gcc (e.g. with [homebrew](https://brew.sh/)) and run

```bash
CXX=g++-8 meson build && cd build && ninja
```