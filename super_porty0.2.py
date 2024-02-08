import socket
import ipaddress
import concurrent.futures
import tkinter as tk
from tkinter import messagebox
import os
import random

os.system('cls' if os.name == 'nt' else 'clear')  # Clear the console screen

# Define color codes
YELLOW = '\033[93m'
ENDC = '\033[0m'

# Print the banner
print(YELLOW + "****************************************")
print("*                                      *")
print("*            SUPER PORTY               *")
print("*            By Rich98                 *")
print("****************************************" + ENDC)

def scan_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(3)  # Hardcode timeout to 3 seconds
        try:
            s.connect((str(ip), port))
            return port
        except:
            return None

def is_active(ip):
    # Use the ping command to check if the IP is active
    response = os.system("ping -c 1 -w2 " + str(ip) + " > /dev/null 2>&1")
    return response == 0

def scan_network(ip_input, ports):
    try:
        if '/' in ip_input:  # If the input is an IP range
            network = ipaddress.ip_network(ip_input)
            ips = [ip for ip in network.hosts() if is_active(ip)]
        else:  # If the input is a single IP address
            ips = [ipaddress.ip_address(ip_input)] if is_active(ip_input) else []
    except ValueError as e:
        return f'Error with IP input: {e}'

    with open('port_scan_results.txt', 'w') as f:
        with concurrent.futures.ThreadPoolExecutor() as executor:  # Use ThreadPoolExecutor
            future_to_ip = {executor.submit(scan_port, ip, port): (ip, port) for ip in ips for port in ports}  # Scan ports concurrently
            for future in concurrent.futures.as_completed(future_to_ip):
                ip, port = future_to_ip[future]
                result = future.result()
                if result is not None:
                    print(f'Port {result} is open on {ip}')  # Print to console
                    f.write(f'Port {result} is open on {ip}\n')  # Write to file

def main():
    ip_input = input("Enter the IP address or IP range in CIDR format (e.g., '192.168.1.0/24' or '192.168.1.1'): ")
    port_input = input("Enter the port number to check (e.g., 80), 'email' to check all default email ports, 'db' to check all default database ports, 'ads' to check all default LDAP and Active Directory ports, 'web' to check all default web and major web service ports, 'well-known' to check well-known ports, 'smb' to check all SMB ports, 'infra' to check infrastructure ports, 'random' to check 20 random ports, or 'all' to check all 65,535 ports: ")

    if port_input.lower() == 'well-known':
        ports = range(1024)
    elif port_input.lower() == 'email':
        ports = [25, 465, 587, 110, 995, 143, 993]
    elif port_input.lower() == 'db':
        ports = [1433, 3306, 5432, 1521, 27017]
    elif port_input.lower() == 'ads':
        ports = [389, 636, 3268, 3269]
    elif port_input.lower() == 'web':
        ports = [80, 443]
    elif port_input.lower() == 'smb':
        ports = [445, 139, 135]  # Default SMB & RPC ports
    elif port_input.lower() == 'infra':
        ports = [53, 67, 68, 161, 162]  # Default DNS, DHCP, SNMP ports
    elif port_input.lower() == 'random':
        ports = random.sample(range(1, 65536), 20)  # Randomly select 20 ports from 1 to 65535
    elif port_input.lower() == 'all':
        root = tk.Tk()
        root.withdraw()
        MsgBox = tk.messagebox.askquestion ('Are you really sure?','Are you sure you want to scan all 65,535 ports?',icon = 'warning')
        if MsgBox == 'yes':
            ports = range(65535)
        else:
            print("Scanning cancelled.")
            root.destroy()
            os.system('cls' if os.name == 'nt' else 'clear')  # Clear the console screen
            return main()
        root.destroy()
    else:
        try:
            ports = [int(port_input)]
        except ValueError as e:
            print(f'Error with port number: {e}')
            ports = []

    scan_network(ip_input, ports)  # Pass timeout to scan_network

if __name__ == '__main__':
    main()
