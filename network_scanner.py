#!/usr/bin/env python
import nmap
import subprocess
import re
import os

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

    print(f"IP's detected from host: {potential_ips}")
    for ip in potential_ips:
        print(f"scanning IP with {cider}")
        network_range = f"{ip}{cider}"
        hosts.append(nmap_scan(network_range, root_flag))
        print(f"\nHosts Scanned: {hosts}")
if __name__ == "__main__":
    main()