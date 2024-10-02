import socket
import signal
import sys

# Define the IP address and port to listen on
UDP_IP = "0.0.0.0"  # Listen on all available interfaces
UDP_PORT = 8987
BUFFER_SIZE = 65535  # Max size for a UDP packet

# Flag to stop the capture
stop_flag = False

# Signal handler to gracefully exit on Ctrl+C
def signal_handler(sig, frame):
    global stop_flag
    print("\nExiting...")
    stop_flag = True

# Setup signal handler for graceful termination
signal.signal(signal.SIGINT, signal_handler)

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the IP and port
sock.bind((UDP_IP, UDP_PORT))

print(f"Listening for UDP packets on {UDP_IP}:{UDP_PORT}...")

try:
    while not stop_flag:
        # Wait to receive data (blocking call)
        data, addr = sock.recvfrom(BUFFER_SIZE)
        print(f"Received packet from {addr}: {len(data)} bytes")

        # Optionally, process the data here or write to a file
        # with open("captured_packets.txt", "a") as f:
        #     f.write(f"Packet from {addr}: {data}\n")

finally:
    sock.close()
    print("Socket closed. Capture stopped.")

