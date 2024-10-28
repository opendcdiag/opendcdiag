# OpenDCDiag Support for Devices

OpenDCDiag's test content is primarily meant for traditional CPUs but the
framework could very well be used for other compute devices.

Target device type can be selected at build time by using `device_type` option:

```bash
meson setup builddir -Ddevice_type=cpu
ninja -C builddir
```

Supported values:

- `cpu`, default; build OpenDCDiag for CPU devices

Both framework and tests require certain information about hardware they run on.
Commonly needed data include:

- number of devices; for scheduling and memory allocation
- topology of the devices: which logical devices (execution units) belong to which
  physical device (e.g., which cores/logical CPUs belong to a CPU package)
- cache/memory sizes and structure
- feature flags

Other device types may require additional or different set of information.

> [!NOTE]
> Implementation of device-specific code is work in progress and will
> differ from description in this document for a while.
>
> On that note, this document is work in progress as well.

## File Structure

Implementation of device-specific interfaces is placed under `devicedeps/`
directory. Since implementation of such interfaces is likely to differ between
operating systems, `devicedeps/<device_type>` is further split into OS-specific
sub-directories which contain device-specific implementations.

Example directory structure for `cpu` device type:

```shell
framework
├── devicedeps/
│  ├── cpu/
│  │  ├── darwin/
│  │  ├── freebsd/
│  │  ├── generic/
│  │  ├── linux/
│  │  ├── unix/
│  │  ├── windows/
│  │  ├── cpu_device.h
│  │  ├── ...
│  │  ├── meson.build
│  │  └── topology.h
│  └── devices.h
├── forkfd/
├── fp_vectors/
├── scripts/
├── sysdeps/
└── unit-tests/
```

Subdirectory with device specific code shall contain a `meson.build` file;
higher-level Meson files expect to find a build file under
`devicedeps/<device_type>/`.

## Implementation of Device-Specific Code

Device-specific code shall be guarded by `SANDSTONE_DEVICE_<device_type>`
preprocessor flag, created at build time in device's build file, e.g.:

```meson
default_c_flags += [
    '-DSANDSTONE_DEVICE_CPU',
]

default_cpp_flags += [
    '-DSANDSTONE_DEVICE_CPU',
]
```

### Common Interface

While different, compute devices share certain properties which can be used
to describe them - at a very high level. Device specific code shall implement -
at minimum - following functions.

```c
/// Returns the number of physical instances of a device available for use
/// by tests (e.g., number of CPU packages, number of compute accelerator
/// devices, etc.).
int num_devices() __attribute__((pure));

/// Returns the number of logical compute execution units (e.g., CPU cores)
/// available to a test. Normally, this value is equal to the total number of
/// execution units in the device under test but the value can be lower
/// if --cpuset option is used, the tests specifies a value for test.max_threads
/// or the OS/other software restricts the number of visible devices.
int num_units() __attribute__((pure));

/// Set of feature flags associated with a device, where each bit in the variable
/// indicates support for specific instructions, availability of additional
/// IP blocks, etc.
/// Code shall also provide means for semantically decoding that value, like
/// structure with definition of each bit.
extern uint64_t device_features;
```

Device initialization code shall be called from `main()` early, before command
line option processing. Additional steps may of course be taken later on,
as needed by the device.

Initialization code shall implement device discovery routine that determines
total number of available execution units, their configuration, whatever is
needed to successfully run tests on those devices.

### Additional Components

Additional framework components, like `InterruptMonitor`, `FrequencyManager`,
`ThermalMonitor` shall be extended with device-specific implementation.
If any of such components is not applicable to a device, code shall handle this
gracefully, disabling the component and continuing execution.

<!-- TBD more details on each of those components -->
