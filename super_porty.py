import socket
import ipaddress
import concurrent.futures

def scan_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((str(ip), port))
            return port
        except:
            return None

def scan_network(ip_input, ports):
    try:
        if '/' in ip_input:  # If the input is an IP range
            network = ipaddress.ip_network(ip_input)
            ips = network.hosts()
        else:  # If the input is a single IP address
            ips = [ipaddress.ip_address(ip_input)]
    except ValueError as e:
        return f'Error with IP input: {e}'

    with concurrent.futures.ProcessPoolExecutor() as executor:
        for port in ports:
            future_to_ip = {executor.submit(scan_port, ip, port): ip for ip in ips}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                result = future.result()
                if result is not None:
                    print(f'Port {result} is open on {ip}')

if __name__ == '__main__':
    ip_input = input("Enter the IP address or IP range in CIDR format (e.g., '192.168.1.0/24' or '192.168.1.1'): ")
    port_input = input("Enter the port number to check (e.g., 80) or 'all' to check all well-known ports: ")

    if port_input.lower() == 'all':
        ports = range(1024)
    else:
        try:
            ports = [int(port_input)]
        except ValueError as e:
            print(f'Error with port number: {e}')
            ports = []

    scan_network(ip_input, ports)
