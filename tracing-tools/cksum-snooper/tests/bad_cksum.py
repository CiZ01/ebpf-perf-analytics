import socket
import random
import sys
from time import sleep


def send_udp_packets(ip_address, port):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Crea un buffer con i dati del ping.
    data = bytearray(8)
    data[0] = 8
    data[1] = 0
    data[2] = 1
    data[3] = 0
    data[4] = 0
    data[5] = 0
    data[6] = 0
    data[7] = 0

    # Modifica il valore del checksum.
    data[6] = 12345 & 0xFF
    data[7] = (12345 >> 8) & 0xFF

    # Invia il ping.
    udp_socket.sendto(data, (ip_address, port))


# parametri: indirizzo IP e numero di pacchetti da inviare
if len(sys.argv) < 2:
    print("Usage: bad_cksum.py <ip_address> [port] [count]")
    exit(1)

ip_address = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 else 4000
count = int(sys.argv[3]) if len(sys.argv) > 3 else 1

for i in range(count):
    send_udp_packets(ip_address, port)
    print(f"Sent packet n. {i+1} to {ip_address}:{port}")
    sleep(0.5)

print("Done")
