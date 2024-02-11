import socket
import ipaddress
import concurrent.futures
import tkinter as tk
from tkinter import messagebox
import os
import random
import pyfiglet
from termcolor import colored

os.system('cls' if os.name == 'nt' else 'clear')

text = "Super Porty"

ascii_banner = pyfiglet.figlet_format(text)

color = "red"

print(colored(ascii_banner, color))
print("By Rich98 super_potty03 https://github.com/rich98/Porty ")


def scan_port(ip, port, protocol='both'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol.lower() == 'tcp' else socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        try:
            s.connect((str(ip), port))
            return port
        except:
            return None


def scan_network(ip_input, ports, protocol='both'):
    try:
        if '-' in ip_input:  # Check if the input is a range
            ip_start, ip_end = ip_input.split('-')
            start = ipaddress.IPv4Address(ip_start)
            end = ipaddress.IPv4Address(ip_end)
            ips = (ipaddress.IPv4Address(ip) for ip in range(int(start), int(end) + 1))
        elif '/' in ip_input:
            network = ipaddress.ip_network(ip_input)
            ips = network.hosts()
        else:
            ips = [ipaddress.IPv4Address(ip_input)]
    except ValueError as e:
        print(f'Error with IP input: {e}')
        return

    # Initialize a set to store the IPs where an open port is found
    ips_with_open_ports = set()

    with concurrent.futures.ThreadPoolExecutor(60) as executor:
        future_to_ip = {executor.submit(scan_port, ip, port, protocol): (ip, port) for ip in ips for port in ports}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip, port = future_to_ip[future]
            result = future.result()
            if result is not None:
                print(f'Port {result} is open on {ip}')
                # Add the IP to the set if an open port is found
                ips_with_open_ports.add(ip)

    # Print the total number of IPs where an open port was found
    print(f'Total IPs where an open port was found: {len(ips_with_open_ports)}')


def main():
    print(colored("Enter the IP address or IP range", 'green'))
    print(colored("Enter IP range in this format 192.168.0.1-192.168.0.254", 'green'))
    print(colored("Enter the IP address or IP range in CIDR format (e.g., '192.168.1.0/24'", 'green'))
    ip_input = input("Enter your info here - ")

    if not ip_input:
        print("Error: IP input cannot be empty.")
        return

    print(colored('Enter a single port number (e.g)', 'green') + colored('80', 'yellow'))
    print(colored('Enter ', 'green') + colored('email ', 'yellow') + colored(
        'to scan these ports 25, 465, 587, 110, 995, 143, 993', 'green'))
    print(colored('Enter ', 'green') + colored('ads ', 'yellow') + colored(
        'to scan these ports 389, 636, 3268, 3269', 'green'))
    print(colored('Enter ', 'green') + colored('web ', 'yellow') + colored('to scan these ports 80, 443', 'green'))
    print(colored('Enter ', 'green') + colored('remote ', 'yellow') + colored('to scan these ports 3389, 5900',
                                                                                'green'))
    print(colored('Enter ', 'green') + colored('smb ', 'yellow') + colored(
        'to scan these ports 445, 139, 135', 'green'))
    print(colored('Enter ', 'green') + colored('xbox ', 'yellow') + colored(
        'to scan these ports 88, 3074, 53, 80, 500, 3544, 4500', 'green'))
    print(colored('To scan 200 random ports enter ', 'green') + colored('random ', 'yellow') + colored(
        'Great for network monitoring practice', 'green'))
    print(colored('Enter ', 'green') + colored('well-known ', 'red') + colored('to scan ports 0-1023', 'green'))
    print(colored('Enter ', 'green') + colored('services ', 'red') + colored(
        'checks the ports found in the MS Services file', 'green'))
    print(colored('To start a 65,535 port scan enter ', 'green') + colored('all ', 'red') + colored(
        'Great for network monitoring practice', 'green'))
    port_input = input("Enter your choice: ")

    if not port_input:
        print("Error: Port input cannot be empty.")
        return

    protocol_input = input("Enter the protocol. Default is set to 'both' (TCP/UDP/both): both") 

    if not protocol_input:
        protocol_input = 'both'

    if port_input.lower() == 'well-known':
        ports = range(1024)
    elif port_input.lower() == 'email':
        ports = [25, 465, 587, 110, 995, 143, 993]
    elif port_input.lower() == 'db':
        ports = [1433, 3306, 5432, 1521, 27017]
    elif port_input.lower() == 'xbox':
        ports = [88, 3074, 53, 80, 500, 3544, 4500]
    elif port_input.lower() == 'ads':
        ports = [389, 636, 3268, 3269]
    elif port_input.lower() == 'web':
        ports = [80, 443]
    elif port_input.lower() == 'remote':
        ports = [3389, 5900]
    elif port_input.lower() == 'smb':
        ports = [445, 139, 135]
    elif port_input.lower() == 'infra':
        ports = [53, 67, 68, 161, 162]
    elif port_input.lower() == 'random':
        ports = random.sample(range(1, 65536), 200)
    elif port_input.lower() == 'services':
        ports = [7, 9, 11, 13, 17, 19, 20, 21, 22, 23, 25, 37, 39, 42, 43, 53, 67, 68, 69, 70, 79, 80, 81, 88, 101, 107, 109,
                 110, 111, 113, 117, 118, 119, 123, 135, 137, 138, 139, 143, 150, 156, 158, 161, 162, 170, 179, 194, 213, 322,
                 349, 389, 443, 445, 464, 500, 507,
                 512, 513, 514, 515, 518, 520, 522, 525, 526, 529, 530, 531, 532, 533, 540, 543, 544, 546, 547, 548, 550,
                 554, 556, 560, 561, 563, 560, 561, 563, 565, 568, 569, 593,
                 612, 613, 636, 666, 691, 749, 750, 800, 989, 990, 992, 993, 994, 995, 1109, 1110, 1155, 1034, 1167, 1270,
                 1433, 1434, 1477, 1478, 1512, 1524, 1607, 1701, 1711, 1723, 1731, 1745, 1755, 1801, 1812, 1913, 1863, 1900,
                 1944,
                 2049, 2053, 3106, 2177, 2234, 2382, 2383, 2393, 2394, 2460, 2504, 2525, 2701, 2701, 2702, 2703, 2704, 2725,
                 2869, 3020, 3074, 3126, 3132, 3268, 3343, 3389,
                 3535, 3540, 3544, 3587, 3702, 3776, 3847, 3882, 3935, 4350, 4500, 5355, 5357, 5358, 5679, 5720, 6073, 7680,
                 9535, 9753, 11320, 47624]
    elif port_input.lower() == 'all':
        root = tk.Tk()
        root.withdraw()
        MsgBox = tk.messagebox.askquestion('Are you really sure?', 'Are you sure you want to scan all 65,535 ports?',
                                           icon='warning')
        if MsgBox == 'yes':
            ports = range(65535)
        else:
            print("Scanning cancelled.")
            root.destroy()
            os.system('cls' if os.name == 'nt' else 'clear')
            return main()
        root.destroy()
    else:
        try:
            ports = [int(port_input)]
        except ValueError as e:
            print(f'Error with port number: {e}')
            ports = []

    scan_network(ip_input, ports, protocol_input)


if __name__ == '__main__':
    main()
