#!/usr/bin/env python
import nmap
import subprocess
import re
import os, sys

# Make sure NMAP is installed, if not... grab it
def check_nmap():
    proc_result = subprocess.run("which nmap", 
        shell=True, capture_output=True, text=True)
    if proc_result:
        print(f"nmap found... {proc_result.stdout}")
    elif (subprocess.run("make")):
        try:
            print("nmap doesnt exist... gathering")
            subprocess.run("curl -O https://nmap.org/dist/nmap-7.98.tar.bz2", 
            shell=True, capture_output=True, text=True)
            subprocess.run("bzip2 -cd nmap-7.98.tar.bz2 | tar xvf - ", 
            shell=True, capture_output=True, text=True)
            subprocess.run("cd nmap-7.98 && ./configure && make", 
            shell=True, capture_output=True, text=True)
            nmap_location = f"{os.getcwd()}/nmap-7.98"

            sys.path.append(nmap_location) # Append to PATH
            return 
        except Exception as e:
            print(f"ERROR: {e}... Exiting")
            exit
    else:
        print("Unable to execute, nmap nor make exists, exiting...")
        exit
        

# Pulls IP Address schema from network connections
def define_network():
    network_config = subprocess.run("ip addr", shell=True, capture_output=True, text=True)
    matches = re.findall(r"inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", str(network_config))
    ip_capture = []
    for ip in matches:
        if ip != "127.0.0.1":
            ip_capture.append(ip)
    return ip_capture

# Checks if user is running as root/has root privelages 
def is_root() -> bool:
    return os.geteuid() == 0

# Executes scan and returns results
def nmap_scan(ip_range, root_flag) -> list:
    scanner = nmap.PortScanner()
    hosts = []
    
    if root_flag:
        scanner.scan(hosts=ip_range, arguments='-sS -p-') # Stealth scan **Requires Root
    else: 
        scanner.scan(hosts=ip_range, arguments='-sT -p-') # Ping scan w/ports

    for host in scanner.all_hosts():
        print(f"\nChecking potential IP: {host}")
        if scanner[host].state() == 'up':
            print(f"Found up host: {host}")
            for protocol in scanner[host].all_protocols():
                print(f"Protocol: {protocol}")
                lport = list(scanner[host][protocol].keys())
                lport.sort()

                for port in lport:
                    print(f"Port: {port}")
                    print(f"Service Name: {scanner[host][protocol][port]['name']}")

            hosts.append(host)
    return hosts
    
# Main definition
def main():
    hosts = []
    potential_ips = define_network()
    root_flag = is_root()
    cider = "/24"
    nmap_location = check_nmap()

    print(f"IP's detected from host: {potential_ips}")
    for ip in potential_ips:
        print(f"scanning IP with {cider}")
        network_range = f"{ip}{cider}"
        hosts.append(nmap_scan(network_range, root_flag))
        print(f"\nHosts Scanned: {hosts}")

if __name__ == "__main__":
    main()