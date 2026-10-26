# Building and distributing firmware

How to produce a `.bin` other people can flash, and how they flash it.

Nothing user-specific is compiled in. WiFi credentials, the address, ntfy settings and both
passphrases live in NVS on the device, and are entered through the setup portal on first
boot. That is what makes the binary shareable.

---

## 1. Prerequisites (you, the builder)

[arduino-cli](https://arduino.github.io/arduino-cli/) plus the ESP32 core (3.1.1 or newer;
built and tested with 3.3.10) and one library:

```bash
arduino-cli core install esp32:esp32
```

```bash
arduino-cli lib install ArduinoJson
```

`WebServer`, `DNSServer`, `NetworkClientSecure`, `HTTPClient`, `LittleFS` and `Preferences`
all ship with the core.

## 2. Build

```bash
arduino-cli compile --fqbn "esp32:esp32:esp32s3:FlashSize=16M,PSRAM=opi,PartitionScheme=custom" --export-binaries ESP32-AdBlocker
```

That build sends the serial log to UART0, for a board reached through its UART port or a
USB-serial adapter (CP2102, CH343, FTDI on TX/RX). For one reached through its native USB port,
add `,CDCOnBoot=cdc` to the FQBN. Releases ship both; the native-USB files carry `-usbcdc`.

The artifacts land in `ESP32-AdBlocker/build/esp32.esp32.esp32s3/`:

| File | Size | Purpose |
| --- | --- | --- |
| `ESP32-AdBlocker.ino.bin` | 1.32 MB | the application (released as `…-app.bin`) |
| `ESP32-AdBlocker.ino.bootloader.bin` | 20 KB | second-stage bootloader |
| `ESP32-AdBlocker.ino.partitions.bin` | 3 KB | partition table (from `partitions.csv`) |
| `boot_app0.bin` | 8 KB | OTA selector |
| `ESP32-AdBlocker.ino.merged.bin` | **16 MB** | all of the above, pre-combined (released as `adblocker-vX.Y.Z-esp32s3-n16r8.bin`) |

`PSRAM=opi` is not optional. Without it the blocklist has nowhere to live, and the device
only forwards queries.

`PartitionScheme=custom` makes the build use the sketch's `partitions.csv`. Check that it
did:

```bash
cat ESP32-AdBlocker/build/esp32.esp32.esp32s3/partitions.csv
```

It should show `spiffs` at `0x410000` with size `0xBE0000`.

## 3. Confirm the binary carries no secrets

```bash
strings ESP32-AdBlocker/build/esp32.esp32.esp32s3/ESP32-AdBlocker.ino.bin | grep -iE "your-ssid|your-wifi-password|your-topic"
```

Substitute your own network name, password and topic. Expect **no output**. The core embeds a
couple of its own source paths, which include your macOS username. Those are not credentials.

Publish checksums alongside the binaries:

```bash
shasum -a 256 *.bin > SHA256SUMS.txt
```

---

## 4. Instructions for the person flashing

```bash
pip install esptool
```

| Connected through | macOS | Linux | Windows |
| --- | --- | --- | --- |
| native USB port | `/dev/cu.usbmodem*` | `/dev/ttyACM0` | `COMx` |
| UART port / USB-serial adapter | `/dev/cu.usbserial-*` or `/dev/cu.SLAB_USBtoUART` | `/dev/ttyUSB0` | `COMx` |

Native USB needs no driver. A bridge chip may: [CP210x](https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers),
[CH340/CH343](https://www.wch-ic.com/downloads/CH341SER_ZIP.html), FTDI (built into macOS).

Check the download first:

```bash
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
```

Erase first, so no settings are inherited from whatever was on the board:

```bash
esptool --port /dev/cu.usbmodem101 erase-flash
```

The simplest way to write is one file at `0x0`:

```bash
esptool --port /dev/cu.usbmodem101 --baud 921600 write-flash 0x0 adblocker-v1.0.3-esp32s3-n16r8-usbcdc.bin
```

To update a board that already runs it, write only the application. Settings and the
blocklist stay:

```bash
esptool --port /dev/cu.usbmodem101 --baud 921600 write-flash 0x10000 adblocker-v1.0.3-esp32s3-n16r8-usbcdc-app.bin
```

Faster, the four pieces at their offsets. On the S3 the bootloader goes at `0x0`:

```bash
esptool --port /dev/cu.usbmodem101 --baud 921600 write-flash 0x0 ESP32-AdBlocker.ino.bootloader.bin 0x8000 ESP32-AdBlocker.ino.partitions.bin 0xe000 boot_app0.bin 0x10000 ESP32-AdBlocker.ino.bin
```

The offsets are also in `flash_args` in the build folder. That file is authoritative if a
future core changes them.

Then follow **Quick start → Set it up** in the README.

## 5. Notes

- **Reflashing keeps settings and the blocklist.** NVS and LittleFS live outside the app
  partition. Use `erase-flash` for a true clean start.
- **The first boot after an erase formats LittleFS.** On a 12 MB partition this adds a few
  seconds before the device comes up.
- **To wipe only the settings over USB**, erase the NVS partition:

  ```bash
  esptool --port /dev/cu.usbmodem101 erase-region 0x9000 0x5000
  ```

- **To wipe only the blocklist and custom list**, erase LittleFS:

  ```bash
  esptool --port /dev/cu.usbmodem101 erase-region 0x410000 0xBE0000
  ```
