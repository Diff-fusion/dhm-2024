# Flag Generator
The participants would install the challenge on the provided hardware.
To make testing possible without access to the hardware some extra files and log output are helpful.
These would be easily accessible from the device.

The files are in this directory:
1. `index.html`: The file served by the webserver on the device
2. `boot.log`: Log from booting the device
3. `request-<type>.log`: Log from sending a decryption request of type `<type>` to the device

This data should be enough to solve the challenge.
Also the same firmware applies to all three variants of the challenge (`extended`, `fininte` and `riscy`)
