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


def scan_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(3)  
        try:
            s.connect((str(ip), port))  
            return port  
        except:
            return None  


def scan_network(ip_input, ports):
    try:
        if '/' in ip_input: 
            network = ipaddress.ip_network(ip_input)
            ips = network.hosts()  
        else:  
            ips = [ipaddress.ip_address(ip_input)]
    except ValueError as e:
        return f'Error with IP input: {e}'

    # Initialize a set to store the IPs where an open port is found
    ips_with_open_ports = set()

    with concurrent.futures.ThreadPoolExecutor(60) as executor:
        future_to_ip = {executor.submit(scan_port, ip, port): (ip, port) for ip in ips for port in ports}
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
        ports = [445, 139, 135]  
    elif port_input.lower() == 'infra':
        ports = [53, 67, 68, 161, 162] 
    elif port_input.lower() == 'random':
        ports = random.sample(range(1, 65536), 20)  
    elif port_input.lower() == 'all':
        root = tk.Tk()
        root.withdraw()
        MsgBox = tk.messagebox.askquestion ('Are you really sure?','Are you sure you want to scan all 65,535 ports?',icon = 'warning')
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

    scan_network(ip_input, ports)  

if __name__ == '__main__':
    main()
