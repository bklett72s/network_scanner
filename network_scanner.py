#!/usr/bin/env python
import nmap
import subprocess
import re

def define_network():
    network_config = subprocess.run("ip addr", shell=True, capture_output=True, text=True)
    matches = re.findall(r"inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", str(network_config))
    ip_capture = []
    for ip in matches:
        if ip != "127.0.0.1":
            ip_capture.append(ip)
    return ip_capture


def nmap_scan(ip_range):
    scanner = nmap.PortScanner()
    hosts = []
    
    scanner.scan(hosts=ip_range, arguments='sn') # Ping scan w/ports

    for host in scanner.all_hosts():
        if scanner[host].state() == 'up':
            hosts.append(host)
    return hosts
    

def main():
    potential_ips = define_network()
    for ip in potential_ips:
        network_range = ip
        #hosts = nmap_scan(network_range)

if __name__ == "__main__":
    main()