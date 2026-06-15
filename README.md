# OpenDCDiag

OpenDCDiag is an open-source project designed to identify defects and
bugs in CPUs. It consists of a set of tests built around a
sophisticated CPU testing framework. OpenDCDiag is primarily intended
for, but not limited to, Data Center CPUs.

## License

OpenDCDiag is released under the [Apache 2.0](LICENSE) license. The
OpenDCDiag framework includes some source code from other projects,
released under different licenses.  See
[LICENSE.3rdparty](LICENSE.3rdparty) for more details.

## Building OpenDCDiag

### Prerequisites

#### Ubuntu

OpenDCDiag has been built and tested on Ubuntu, starting with 21.04 and 21.10.
Before building, the following prerequisites must be installed.

```console
sudo apt-get install gcc g++ cmake libeigen3-dev libboost-all-dev libzstd-dev zlib1g-dev libgtest-dev meson
```

#### Fedora

OpenDCDiag has been built and tested on Fedora, starting with 33 and 34.
Before building, the following prerequisites must be installed.

```console
sudo dnf install -y boost-devel eigen3-devel gcc gcc-c++ git gtest-devel meson zlib-devel libzstd-devel
```

### Building

OpenDCDiag is built with the [Meson Build System](https://mesonbuild.com/). For
example, a release build can be easily created as follows.

```console
meson builddir --buildtype=release
ninja -C builddir
```

### Building for GPU

OpoenDCDiag can also be built for other device types by specifying the
`device_type` build option. Currently supported device types are: `cpu`, `gpu`.

OpenDCDiag uses the [oneAPI Level Zero](https://github.com/oneapi-src/level-zero)
interface to interact with the GPU devices. A library implementing the Level Zero
API is required to create OpenDCDiag executable with GPU support.

For example, to install Level Zero loader libraries on Ubuntu, use:

```console
sudo apt-get install libze1 libze-dev intel-ocloc libigdfcl2 libigc2
```

On Fedora:

```console
sudo dnf install -y oneapi-level-zero intel-level-zero intel-level-zero-devel intel-ocloc
```

With the prerequisites installed, OpenDCDiag for GPU devices can be created
using commands as follows.

```console
meson builddir --buildtype=release -Ddevice_type=gpu
ninja -C builddir
```

The GPU binary uses OpenCL Offline Compiler (also known as `ocloc`) to compile
and embed compute kernels for specific devices into the resulting OpenDCDiag
binary. The `target_device` build option can be used to specify the devices that
are to be supported by the created OpenDCDiag executable.

Value specified in the `target_device` option is passed directly to the OpenCL
Offline Compiler used to build the binary. Refer to the documentation of the
offline compiler for the accepted values of the `target_device` option.

## Contributions

The OpenDCDiag project welcomes contributions and pull requests.
Please see [Contributing to OpenDCDiag](CONTRIBUTING.md) for more
details.

## Code of Conduct

The OpenDCDiag project has adopted the Contributor's Covenant as its [Code of
Conduct][coc]. The project requires contributors and users to follow our Code
of Conduct, both in letter and in spirit.

[coc]: CODE_OF_CONDUCT.md

## Writing Tests

The OpenDCDiag framework is designed to make the creation of new CPU
tests as simple as possible. It takes care of much of the boiler
plate code CPU tests need, e.g., test life cycle, threading model, CPU
feature identification, random number generation, etc. This allows test
authors to concentrate on the specific test functionality that
interests them. A detailed guide to writing new OpenDCDiag tests is
presented in [A Guide to Writing OpenDCDiag
tests](docs/writing_tests.md).

## Intel® Data Center Diagnostic Tool

Intel provides a tool called the
[Intel® Data Center Diagnostic Tool](https://www.intel.com/content/www/us/en/support/articles/000058107/processors/intel-xeon-processors.html)
for verifying the functionality of all cores within an Intel® Xeon®
processor.  Intel Data Center Diagnostic Tool is built using the OpenDCDiag framework and is
freely downloadable.  It is not however open-source and it is designed for
use with Intel Xeon processors only. The Intel Data Center
Diagnostic Tool contains additional tests that are not part of the OpenDCDiag project.
