from scapy.all import IP, DNS, sniff


interface = "wlo1"

def DNSsniff(packet):
	if IP in packet:
		ip_src = packet[IP].src
		ip_dst = packet[IP].dst # most likely router gateway
		if packet.haslayer(DNS):
			dns_layer = packet.getlayer(DNS)
			# parse only DNS queries
			
			if dns_layer.qr == 0:
				print("[*] SRC:",ip_src,"-->",dns_layer.qd.qname)

print("[+] Starting DNSSniffer x1 ...")
sniff(iface=interface, filter="port 53", prn=DNSsniff, store=0)
