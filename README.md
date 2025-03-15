# xcore.boot

A bootloader for [xCore microcontroller boards](https://core.x-tech.online/), consisting of a microcontroller-side firmware written in C and a host-side utility written in Python for uploading images over the network.

## Introduction

`xcore.boot` is a network-based bootloader designed for [xCore microcontroller boards](https://core.x-tech.online/). It allows users to upload firmware images to the microcontroller over TCP/IP, facilitating easy updates and deployment.

The bootloader is split into two components:
- **Microcontroller Firmware (C):** Runs on the STM32 microcontroller and handles network communication, image verification, and programming.
- **Host Utility (Python):** A command-line tool that runs on a host PC to discover devices on the network and upload firmware images.

## Features

- **Network Discovery:** Automatically discovers xCore devices on the local network.
- **Secure Image Transfer:** Uses SHA256 checksums to verify the integrity of the uploaded image.
- **Progress Feedback:** Displays upload progress with a progress bar.
- **Flexible Interface Selection:** Allows specifying a network interface for communication.



## Usage

### Docker
The host software is provided as docker image, so uploading a firmware file is as easy as running:
```bash
docker run --rm -it --network=host -v/path/to/your/firmware:/workdir ghcr.io/xtech/fw-xcore-boot:main upload /workdir/firmware.bin
```

### Without Docker

To upload a firmware image without Docker, use the `upload` command followed by the path to the image file:

```bash
./xcore-boot.py upload path/to/your/image.bin
```
#### Prerequisites

- **Python 3.x:** The host utility requires Python 3.
- **Python Packages:**
    - `tqdm`: For displaying progress bars.
- **Operating System:** Unix/Linux (due to the use of specific system calls like `fcntl.ioctl`).

## Script Options

- **`-i`, `--interface`:** Specify the network interface to use for communication.

  ```bash
  ./xcore-boot.py -i eth0 upload firmware.bin
  ```

- **`--target-ip`:** Specify the IP address of the target board to skip service discovery.

  ```bash
  ./xcore-boot.py --target-ip 192.168.1.100 upload firmware.bin
  ```

## How It Works

1. **Service Discovery:**
    - The host utility sends a broadcast message (`DISCOVER_REQUEST`) over the network.
    - The microcontroller responds with its IP address.

2. **Establishing Connection:**
    - The host connects to the microcontroller using TCP on port `8007`.

3. **Handshake Protocol:**
    - The microcontroller sends variable pairs (if any) and requests the SHA256 checksum.
    - The host computes the SHA256 checksum of the image and sends it.
    - Upon verification, the microcontroller requests the file length.
    - The host sends the file length.
    - The microcontroller acknowledges and requests the data.
    - The host uploads the image data while displaying a progress bar.

4. **Completion:**
    - After successful upload, the connection is closed.

## Manual Installation
If you want to run the host-software without docker, follow these steps:

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/ClemensElflein/xcore.boot.git
   cd xcore.boot/host-software
   ```

2. **Install Required Python Packages:**

   ```bash
   pip install tqdm
   ```

3. **Make the Host Utility Executable:**

   ```bash
   chmod +x xcore-boot.py
   ```

## License

This project is licensed under the [MIT License](LICENSE).  This project uses ChibiOS (GPL version), so the final executable is also licensed under the GPL license.
When purchasing a commercial version of ChibiOS it is possible to use the sources according to ChibiOS commerical license terms.
