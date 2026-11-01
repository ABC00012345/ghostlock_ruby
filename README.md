# ghostlock_ruby

Port of the GhostLock exploit for the Redmi Note 12 Pro 5G

- Device: Redmi Note 12 Pro 5G (`ruby`, MT6877)
- Kernel: `4.19.191-ge6429b82e599`
- Build: `ghostlock_ruby`
- Listener: `127.0.0.1:55555`

## Build

```sh
NDK_ROOT=/path/to/android-ndk-r30 make
```

The source files live directly under `src/`; `src/target_ruby.h` is the
single compile-time offset file.  Other device kernels, runtime offset
tables, and the external `offsets.json` override were removed from this copy.

## Run

Push the binary somewhere writable and run it from an adb shell:

```sh
adb push ghostlock_ruby /data/local/tmp/ghostlock_ruby
adb push kernelsu_ruby.ko /data/local/tmp/kernelsu_ruby.ko
adb shell chmod 755 /data/local/tmp/ghostlock_ruby
adb shell /data/local/tmp/ghostlock_ruby
```

At the end of the exploit log:

```text
connect with: nc 127.0.0.1 55555
```
Connect on the device or via adb:

```sh
nc 127.0.0.1 55555
```

## Limitations

- It still sometimes crashes the kernel
- It was only tested via adb, W3 was not confirmed working yet

## Notes

- Only use it for devices you own or have permission to use for this
- I am not responsible for anything that could happen when running this tool on a real device
- Built solely for eductional/testing/demonstrating purposes only
