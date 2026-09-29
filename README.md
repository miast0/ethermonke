# ethermonke

Terminal-native network visualisation tool based on EtherApe.

License: [CC0 1.0 Universal](LICENSE).

## Build

Install a C++20 compiler, CMake, pkg-config, and development packages for libpcap, FTXUI, and toml++.

Fedora:

```sh
sudo dnf install cmake gcc-c++ libpcap-devel ftxui-devel tomlplusplus-devel pkgconf-pkg-config
```

Debian:

```sh
sudo apt install cmake g++ pkg-config libpcap-dev libftxui-dev libtomlplusplus-dev
```

Then build and install:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo cmake --install build
```

Run `ethermonke` to capture on the default interface, or `ethermonke -i INTERFACE` to select one. `ethermonke host` shows incoming traffic. Packet capture requires suitable permissions.

## Packages

Build packages on their target distribution so they link against its libraries.
The files in `releases/` were built on Fedora 44 (x86_64) and Debian 13/trixie (amd64).

Fedora RPM (also install `rpm-build`):

```sh
cpack --config build/CPackConfig.cmake -G RPM -B releases
```

Debian DEB (also install `file` and `dpkg-dev`):

```sh
cpack --config build/CPackConfig.cmake -G DEB -B releases
```
