#!usr/bin/env python

import scapy.all as scapy
import platform
import os
import shutil
import subprocess
import colored

def become_persistent():
	file_location = os.environ["appdata"] + "\\mitm_detector.py"
	if not os.path.exists(file_location):
		persistent_answer = input("You want to make it persistent or not(yes/no)? > ")
		if persistent_answer == 'yes':
			shutil.copy(__file__, file_location)
			subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\run /v update /t REG_SZ /d "' + file_location + '"', shell=True)
		else:
			pass

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    (answered_list, unanswered_list) = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    clients_list = []
    for element in answered_list:
        client_dict = {"MAC": element[1].hwsrc, "IP": element[1].psrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(result_list):
    print("\nMAC Address\t\t\tIP\n--------------------------------------------------")
    for client in result_list:
        print(client["MAC"] + "\t\t" + client["IP"])

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    (answered_list, unanswered_list) = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    return answered_list[0][1].hwsrc


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
	if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
		try:
			real_mac = get_mac(packet[scapy.ARP].psrc)
			response_mac = packet[scapy.ARP].hwsrc
			if real_mac != response_mac:
				color = colored.fg("red")
				reset = colored.attr("reset")
				background = colored.bg("red")
				print(color + "[+] You're Under Attack" + reset)
				print(background + "[+] This(" + response_mac + ") MAC Address is Trying to be Man-In-The-Middle." + reset)
		except IndexError:
			pass


print(''' __  __ ___ _____ __  __   ____       _            _             
|  \/  |_ _|_   _|  \/  | |  _ \  ___| |_ ___  ___| |_ ___  _ __ 
| |\/| || |  | | | |\/| | | | | |/ _ \ __/ _ \/ __| __/ _ \| '__|
| |  | || |  | | | |  | | | |_| |  __/ ||  __/ (__| || (_) | |   
|_|  |_|___| |_| |_|  |_| |____/ \___|\__\___|\___|\__\___/|_|   
                                                                 
''')
print("##### Man In The Middle Attack Detector #####\n")
user_os = platform.system()

print("#### Instructions ####\n")
print("-> Give IP Address in input, and Program will give you the appropriate MAC Address to that IP Address\n")
print("-> If you want to know all IP Address in your subnet and also want to know Appropriate MAC Address then you have to put your subnet's Gateway IP Address and put '/24' behind it to specify it's type.\n")
print("-> It will give you all connected devices' IP Address and Appropriate MAC Address of that IP Address\n\n")
user_response = input("Are you Ready to Go Further and Use the Tool?(yes/no) > ")

if user_response == "yes":
	if user_os == 'Windows':
		print("\n*** You are using Windows Operating System ***\n")
		become_persistent()
		
	elif user_os == 'Linux':
		print("\n*** You are using Linux Operating System ***\n")
		
	elif user_os == "Drawin":
		print("\n*** You are using Mac Operating System ***\n")

	ip_address = input("IP Address>")
	scan_result = scan(ip_address)
	print_result(scan_result)
else:
	exit()
	
print("\n\n***** Network Scanning has Done! *****\n")

print("***** MITM Detector now will be Started! *****\n")
user_response = input("Are you Ready to Go Further and Use the Tool?(yes/no) > ")
print("\n\nAttacker Information:")

if user_response == "yes":
	color = colored.fg("green")
	reset = colored.attr("reset")
	print(color + "[+] You're Safe!" + reset)
	sniff("Wi-Fi")
else:
	exit()