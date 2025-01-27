#!/usr/bin/env python3

import argparse
import hashlib
import socket
import struct
import time
import sys
from tqdm import tqdm

BROADCAST_PORT = 8007
TCP_PORT = 8007
TIMEOUT = 0.5  # seconds

def read_file(filename):
    """Reads the contents of the file.

    Args:
        filename (str): The path to the file.

    Returns:
        bytes: The contents of the file.

    Raises:
        IOError: If the file cannot be read.
    """
    with open(filename, 'rb') as f:
        return f.read()

def compute_sha256(file_contents):
    """Computes the SHA256 checksum of the file contents.

    Args:
        file_contents (bytes): The contents of the file.

    Returns:
        str: The SHA256 checksum as a hex string.
    """
    sha256 = hashlib.sha256()
    sha256.update(file_contents)
    return sha256.hexdigest()

def get_interface_address(interface_name):
    """Gets the IP address associated with a network interface.

    Args:
        interface_name (str): The name of the network interface.

    Returns:
        str: The IP address of the interface.

    Raises:
        ValueError: If the interface cannot be found or has no IP.
    """
    # Unix/Linux implementation
    import fcntl
    import struct
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        iface_bytes = interface_name.encode('utf-8')
        addr = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', iface_bytes[:15])
        )[20:24])
        return addr
    except IOError:
        print(f"Interface {interface_name} not found or has no IP address")
        return None

def discover_boards(timeout, interface_ip=None):
    """Sends a broadcast request and listens for boards to advertise themselves.

    Args:
        timeout (float): The timeout in seconds.
        interface_ip (str): The IP address of the network interface to use.

    Returns:
        str: The IP address of the first board that responds, or None if no boards respond.
    """
    try:
        # Create the UDP socket for transmitting and receiving packets.
        # These need to be different because receiving socket needs to bind to any IP while sending socket
        # should bind to interface_ip
        tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        # Allow multiple sockets to use the same PORT number
        try:
            tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass  # Some systems don't support SO_REUSEPORT

        # Bind to the port and interface IP if provided
        if interface_ip:
            tx_sock.bind((interface_ip, BROADCAST_PORT))
        else:
            tx_sock.bind(('0.0.0.0', BROADCAST_PORT))

        # rx needs to listen for any ip
        rx_sock.bind(('0.0.0.0', BROADCAST_PORT))


        # Set a timeout so the socket does not block indefinitely
        rx_sock.settimeout(timeout)
        tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Send the multicast request
        request_message = b'DISCOVER_REQUEST'

        # Listen for responses
        try_count = 25
        try_number = 0
        sent = False
        while try_number < try_count:
            try:
                if not sent:
                    # only resend on timeout
                    tx_sock.sendto(request_message, ('<broadcast>', BROADCAST_PORT))
                    sent = True
                data, address = rx_sock.recvfrom(1024)
                # Ignore messages from ourselves
                message = data.decode().strip()
                if message == 'DISCOVER_REQUEST':
                    continue
                print(f"Received advertisement from {address[0]}: {data.decode().strip()}")
                # Return the IP of the first board that responds
                return address[0]
            except socket.timeout:
                # No more responses
                try_number += 1
                sent = False
                print(f"Timeout ({try_number}/{try_count})")
                continue
            except Exception as e:
                print(f"Error receiving data: {e}")
                return None
    finally:
        rx_sock.close()
        tx_sock.close()

def read_protocol_line(sock_file):
    """Reads a line from the socket, handling lines that start with '>'.

    Args:
        sock_file (file-like object): The socket file object.

    Returns:
        str: The line read from the socket that does not start with '>'.

    Raises:
        EOFError: If the socket is closed.
    """
    try:
        while True:
            line = sock_file.readline()
            if not line:
                raise EOFError("Connection closed by remote host")
            line = line.decode().strip()
            if line.startswith('>'):
                # Print the message to console and continue reading
                print(line)
                continue
            return line
    except Exception as e:
        print(f"Error reading line: {e}")
        return None

def upload_file(filename, ip, interface_ip=None):
    """Uploads the file to the board via TCP.

    Args:
        filename (str): The path to the file to upload.
        ip (str): The IP address of the board.
        interface_ip (str): The IP address of the network interface to use.
    """
    try:
        # Read the file contents
        file_contents = read_file(filename)
        # Compute the SHA256 sum
        sha256_hex = compute_sha256(file_contents)
        file_length = len(file_contents)
        print(f"File SHA256: {sha256_hex}")
        print(f"File Length: {file_length}")

        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind to the interface IP if provided
        if interface_ip:
            sock.bind((interface_ip, 0))

        sock.connect((ip, TCP_PORT))
        print(f"Connected to {ip}:{TCP_PORT}")

        # Wrap the socket with a file-like object
        sock_file = sock.makefile('rwb')

        # Read variable pairs from the remote
        variables = {}
        while True:
            line = read_protocol_line(sock_file)
            if line is None:
                return
            if variables.get("BOOTLOADER VERSION") == "xcore-boot v1.0" and line == "SEND HASH":
                break
            if line == 'SEND COMMAND':
                break  # End of variables section
            if ':' in line:
                name, value = line.split(':', 1)
                variables[name.strip()] = value.strip()
            else:
                print(f"Invalid variable line: {line}")

        print("Variables received from board:")
        for name, value in variables.items():
            print(f"{name}: {value}")

        if variables.get("BOOTLOADER VERSION") != "xcore-boot v1.0":
            print("Sending UPLOAD command")
            # Send the UPLOAD command
            sock_file.write("UPLOAD\n".encode())
            sock_file.flush()
            # Wait for "SEND HASH" as response
            response = read_protocol_line(sock_file)
            if response != 'SEND HASH':
                print(f"Unexpected response after sending command: {response}")
                return
            print("Received SEND HASH")

        # Send SHA256 as hex string
        sock_file.write((sha256_hex + '\n').encode())
        sock_file.flush()
        print("Sent SHA256 to board")

        # Wait for "HASH OK" response
        response = read_protocol_line(sock_file)
        if response != 'HASH OK':
            print(f"Unexpected response after sending SHA256: {response}")
            return
        print("Received HASH OK")

        # Wait for "SEND LENGTH" response
        response = read_protocol_line(sock_file)
        if response != 'SEND LENGTH':
            print(f"Unexpected response after sending SHA256: {response}")
            return

        # Send file length
        sock_file.write((str(file_length) + '\n').encode())
        sock_file.flush()
        print("Sent file length to board")

        # Wait for "LENGTH OK" response
        response = read_protocol_line(sock_file)
        if response != 'LENGTH OK':
            print(f"Unexpected response after sending file length: {response}")
            return

        # Wait for "SEND DATA" response
        response = read_protocol_line(sock_file)
        if response != 'SEND DATA':
            print(f"Unexpected response after sending file length: {response}")
            return

        # Send file content as binary data with progress bar
        print("Uploading file...")

        # Send the file in chunks
        chunk_size = 1024  # 1KB
        total_sent = 0
        with tqdm(total=file_length, unit='B', unit_scale=True) as pbar:
            for i in range(0, file_length, chunk_size):
                chunk = file_contents[i:i+chunk_size]
                sock_file.write(chunk)
                sock_file.flush()
                total_sent += len(chunk)
                pbar.update(len(chunk))
        print("File content sent")

    except Exception as e:
        print(f"Error during file upload: {e}")
    finally:
        sock.close()
        print("Connection closed")

def set_developer_mode(enable_developer_mode, ip, interface_ip=None):
    """Enables the developer mode for the bootloader

    Args:
        enable_developer_mode (bool): The new value for the developer mode
        ip (str): The IP address of the board.
        interface_ip (str): The IP address of the network interface to use.
    """
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind to the interface IP if provided
        if interface_ip:
            sock.bind((interface_ip, 0))

        sock.connect((ip, TCP_PORT))
        print(f"Connected to {ip}:{TCP_PORT}")

        # Wrap the socket with a file-like object
        sock_file = sock.makefile('rwb')

        # Read variable pairs from the remote
        variables = {}
        while True:
            line = read_protocol_line(sock_file)
            if line is None:
                # timeout
                return
            if variables.get("BOOTLOADER VERSION") == "xcore-boot v1.0":
                print("Developer mode not supported on bootloader v1.0")
                return
            if line == 'SEND COMMAND':
                break  # End of variables section
            if ':' in line:
                name, value = line.split(':', 1)
                variables[name.strip()] = value.strip()
            else:
                print(f"Invalid variable line: {line}")

        print("Variables received from board:")
        for name, value in variables.items():
            print(f"{name}: {value}")

        sock_file.write('SET_DEV_MODE\n'.encode())
        sock_file.flush()
        print("Sent SET_DEV_MODE to board")

        # Wait for "SEND DEV_MODE_ENABLED" response
        response = read_protocol_line(sock_file)
        if response != 'SEND DEV_MODE_ENABLED':
            print(f"Unexpected response after sending SET_DEV_MODE: {response}")
            return
        print("Received HASH OK")

        if enable_developer_mode:
            sock_file.write('1\n'.encode())
        else:
            sock_file.write('0\n'.encode())
        sock_file.flush()

        print("Sent new value to board")

        # read back for CLI output
        read_protocol_line(sock_file)
    except Exception as e:
        print(f"Error during set dev mode: {e}")
    finally:
        sock.close()
        print("Connection closed")

def service_discovery(interface_name, target_ip):
    """
    Discovers xcore boards in the network and returns the board's IP and
    optionally an interface IP, if a non-standard network interface was requests
    Args:
        interface_name: The name of the interface to bind to or None for automatic mode
        target_ip: The IP address of the board to skip service discovery or None for automatic mode

    Returns:
        a tuple with (board_ip, interface_ip|None) | None
    """
    interface_ip = None
    # If target IP is provided, skip service discovery
    if target_ip:
        return target_ip, None

    # If interface_name is specified, get the IP address, so that we can bind to the requested interface
    if interface_name:
        interface_ip = get_interface_address(interface_name)
        if interface_ip is not None:
            print(f"Using interface {interface_name} with IP {interface_ip}")
        else:
            print(f"Error binding to interface with name {interface_name}")
            return None, None
    # Discover boards
    board_ip = discover_boards(TIMEOUT, interface_ip)
    if board_ip is None:
        print("No boards found")
        return None, None
    else:
        print(f"Found board at {board_ip}")
        return board_ip, interface_ip


def upload_command(args):
    """Handles the upload command."""
    filename = args.filename
    interface_name = args.interface
    target_ip = args.target_ip

    board_ip, interface_ip = service_discovery(interface_name, target_ip)
    if board_ip is None:
        return
    # Upload file to board
    try:
        upload_file(filename, board_ip, interface_ip)
    except Exception as e:
        print(f"Error uploading file: {e}")
        return

def set_dev_mode_command(args):
    """Handles the set_dev_mode command"""
    interface_name = args.interface
    target_ip = args.target_ip

    if (args.enable and args.disable) or (not args.enable and not args.disable):
        print("Illegal Argument: Need to either specify enable or disable")
        return
    enable = args.enable

    board_ip, interface_ip = service_discovery(interface_name, target_ip)
    if board_ip is None:
        return

    set_developer_mode(enable, board_ip, interface_ip)



def main():
    """Main function to parse arguments and execute commands."""
    parser = argparse.ArgumentParser(description='xcore-upload utility')
    parser.add_argument('-i', '--interface', help='Network interface to use for communication')
    parser.add_argument('--target-ip', help='IP address of the target board (skip service discovery)')
    subparsers = parser.add_subparsers(dest='command')

    # upload command
    upload_parser = subparsers.add_parser('upload', help='Upload an image to the board')
    upload_parser.add_argument('filename', help='Image file to upload')

    # Set dev mode command
    set_dev_mode_parser = subparsers.add_parser('set_dev_mode', help="Set the development mode")
    set_dev_mode_parser.add_argument('--enable', help="Enable development mode", action='store_true')
    set_dev_mode_parser.add_argument('--disable', help="Disable development mode", action='store_true')

    args = parser.parse_args()

    if args.command == 'upload':
        upload_command(args)
    elif args.command == 'set_dev_mode':
        set_dev_mode_command(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
