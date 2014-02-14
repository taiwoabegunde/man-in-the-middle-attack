from threading import Thread
from scapy.all import *
class PacketSniffer(Thread):

	def __init__(self,targets,gateway_mac,interface):
		Thread.__init__(self)
		self.targets = targets
		self.gateway_mac = gateway_mac
		self.interface = interface
		self.f = open('log.txt', 'w')
		self.setDaemon(True)

	def redirect_to_router(self,pkt):
		pkt[Ether].dst = self.gateway_mac
		sendp(pkt,verbose = 0)

	def log_packet(self,pkt):
		if ARP not in pkt:
			self.f.write(pkt.summary()+"\n")

	def sniff_callback(self,pkt):
		self.redirect_to_router(pkt)
		self.log_packet(pkt)

	def sniff_packets(self):
		sniff_filter = "src " + " or src ".join( [ target[0] for target in self.targets] )
		sniff(iface=self.interface , filter=sniff_filter , prn=self.sniff_callback , store = 0 )

	def run(self):
		self.sniff_packets()
