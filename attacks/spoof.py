from scapy.all import *

packet = IP(src="1.2.3.4", dst="10.0.0.1")/ICMP()
send(packet, iface="veth-ue", count=15, verbose=1)
