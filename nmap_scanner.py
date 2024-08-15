import nmap
import time
import ipaddress

def scan_ip(ip_address, port_range):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip_address, port_range)
    except nmap.PortScannerError as e:
        print(f"Error scanning IP {ip_address}: {e}")
        return []
    
    open_ports = []
    if ip_address in nm.all_hosts(): # Check if the IP address exists in the scan results
        for proto in nm[ip_address].all_protocols():
            ports = nm[ip_address][proto].keys()
            for port in ports:
                if nm[ip_address][proto][port]['state'] == 'open':
                    open_ports.append((proto, port))
    return open_ports


def log_results(ip_address, open_ports):
    try:
        with open('open_ports_log.txt', 'a') as logfile:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            logfile.write(f'{timestamp} - {ip_address} - {open_ports}\n')
    except IOError as e:
        print(f"Error writing to log file: {e}")

def ip_range(start_ip, end_ip):
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    return (str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1))

def main():
    start_ip = '192.168.1.1' # Replace with the starting IP address of the range you want to scan
    end_ip = '192.168.1.255' # Replace with the ending IP address of the range you want to scan
    ip_list = ip_range(start_ip, end_ip)
    port_range = '1-1024' # Define the port range you want to scan

    for ip_address in ip_list:
        open_ports = scan_ip(ip_address, port_range)
        if open_ports:
            log_results(ip_address, open_ports)
            print(f'Open ports for {ip_address}: {open_ports}')
        else:
            print(f'No open ports for {ip_address}')

if __name__ == '__main__':
    main()
