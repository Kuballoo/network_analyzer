from scapy.all import *
from tqdm import tqdm
from colorama import Fore, Back, Style
from os import system, name

import ipaddress, logging

# Turned of warinings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


''' 
    Define our clear function
'''
def clear():
    # for windows
    if name == 'nt':
        _ = system('cls')
    # for mac and linux(here, os.name is 'posix')
    else:
        _ = system('clear')


'''
    Generating list of ips from start to end
'''
def generate_ips_list(start_IP, end_IP):
    start_IP = ipaddress.IPv4Address(start_IP)
    end_IP = ipaddress.IPv4Address(end_IP)
    ip_to_save = start_IP
    IPs_list = []
    while ip_to_save <= end_IP:
        IPs_list.append(str(ip_to_save))
        ip_to_save+=1
    return IPs_list


'''
    Scanning port with TCP (3 handshake)
'''
def port_scanner(dst_IPs, start_port, end_port):
    clear()
    # Checking type of data (single/range/list of ips) and generating list of them
    dst_IPs = dst_IPs.split()
    if ':' in dst_IPs:
        dst_IPs = generate_ips_list(dst_IPs[0], dst_IPs[2])

    # Creating dictionary which save ips and opened ports
    opened_ports={}
    # Iterating on dstIPs list (tqdm shows nice processing bar)
    for ip in tqdm(dst_IPs, desc='IPs processing: '):
        ip_packet = IP(dst=ip)
        # Checking whether the provided IP address is available 
        if sr1(ip_packet, timeout=1, verbose=0) != None:
            # Ports save every opened port
            ports=" "
            with tqdm(total=end_port-start_port+1, desc=f'Scanning {ip}', leave=False) as pbar:
                # Start scannig ports from start to end
                for port in range(start_port, end_port+1):
                    syn_packet = ip_packet / TCP(dport=port, flags='S')
                    response = sr1(syn_packet, timeout=1, verbose=0)
                    # Checking whether the recipient responded on a given port
                    if response != None:
                        if response.getlayer(TCP).flags == 'SA':
                            ports += (str(port) + ' ')
                    pbar.update(1)
            # Append every opened ports to their ip in dictionary
            opened_ports[ip] = ports
    
    
    # Here we will printing our results
    clear()
    print(Back.RED + '----- Open ports -----' + Style.RESET_ALL)
    for ip, ports in opened_ports.items():
        ports = ports.split()
        print('* ' + Fore.BLUE + f'{ip}: ' + Style.RESET_ALL)
        for port in ports:
            print('\t- ' + Fore.GREEN + f'{port}' + Style.RESET_ALL)
    input(Fore.RED + '\nPress enter to continue...' + Style.RESET_ALL)


'''
    Scanning availabe IPS
'''
def IPs_scanner(IPs):
    clear()
    # Checking type of data (single/range/list of ips) and generating list of them
    IPs = IPs.split()
    if ':' in IPs:
        IPs = generate_ips_list(IPs[0], IPs[2])

    # Scanning for available IPs and append them to list
    available_IPs = []
    for ip in tqdm(IPs, desc='IPs scanning: '):
        response = sr1(IP(dst=str(ip))/ICMP(), timeout=1, verbose=0)
        if response:
            available_IPs.append(ip)
    
    # Printing results
    clear()
    print(Back.RED + '----- Available IPs -----' + Style.RESET_ALL)
    for ip in available_IPs:
        print('- ' + Fore.GREEN + ip + Style.RESET_ALL)
    input(Fore.RED + '\nPress enter to continue...' + Style.RESET_ALL)


    


def menu():
    while True:
        clear()
        print(Fore.GREEN + '----- NETWORK ANALYZER -----' + Style.RESET_ALL)
        print('1. Available addresses')
        print('2. Port scanner')
        print('0. Exit')
        choice = int(input(Fore.CYAN + '\nEnter your choice: ' + Style.RESET_ALL))

        match choice:
            case 1:
                IPs = input('IPs to scan: ')
                IPs_scanner(IPs)
            case 2:
                IPs = input('IPs to scan: ')
                start_port = int(input('Start port: '))
                end_port = int(input('End port: '))
                port_scanner(IPs, start_port, end_port)
            case 0:
                break


menu()
clear()