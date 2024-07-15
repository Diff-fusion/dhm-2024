# ESP32 Reversing Challenge: Flag Generator

## Building the Challenge
1. Install [esp-idf](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/get-started/linux-macos-setup.html) (version: v5.2.1)
2. Apply `ulp-combi.patch` to the repository
3. Activate the environment with the 'export.sh' script
4. Go to the `challenge` directory
5. Build the challenge with `idf.py build`
6. Optionally flash the build with `idf.py -p /dev/ttyACM0 flash`

### Create Flat Image
The IDF creates 3 separate images for bootloader, partition table and the application.
The files are placed inside the `build` directory.
They can be merged with `esptool`:
```
esptool.py --chip esp32s3 merge_bin --output merged.bin --flash_mode dio --flash_freq 80m --flash_size 16MB 0x0 bootloader/bootloader.bin 0x8000 partition_table/partition-table.bin 0x10000 flag-generator.bin
```
The binary can then be flashed with:
```
esptool.py --port /dev/ttyACM0 write_flash 0 merged.bin
```
