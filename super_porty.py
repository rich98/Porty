import socket
import ipaddress
import concurrent.futures

def scan_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((str(ip), port))
            return f'Port {port} is open on {ip}'
        except:
            return None

def scan_network(ip_range, port):
    try:
        network = ipaddress.ip_network(ip_range)
    except ValueError as e:
        return f'Error with IP range: {e}'

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {executor.submit(scan_port, ip, port): ip for ip in network.hosts()}
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            if result is not None:
                print(result)

ip_range = input("Enter the IP range in CIDR format (e.g., '192.168.1.0/24'): ")
port = input("Enter the port number to check (e.g., 80) or 'all' to check all well-known ports: ")

if port.lower() == 'all':
    for port in range(1024):
        scan_network(ip_range, port)
else:
    try:
        port = int(port)
        scan_network(ip_range, port)
    except ValueError as e:
        print(f'Error with port number: {e}')

