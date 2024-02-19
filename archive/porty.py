import socket
import ipaddress

def scan_network(ip_range, port):
    network = ipaddress.ip_network(ip_range)
    for ip in network.hosts():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            connection = s.connect((str(ip), port))
            print(f'Port {port} is open on {ip}')
            s.close()
        except:
            pass

ip_range = input("Enter the IP range in CIDR format (e.g., '192.168.1.0/24'): ")
port = int(input("Enter the port number to check (e.g., 80): "))

scan_network(ip_range, port)
