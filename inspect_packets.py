from pcapfile import savefile
#import pyshark
import sys
import scapy.all as scapy
from scapy.all import sr1,IP,ICMP
packetCount = 0
packets = []

"""
For each sampled packet, we extract its source and destination IP addresses, and
other information such as times-tamps, sequence numbers, and ACK sequence
numbers. When the router samples any outgoing TCP SYN segment, the module checks
if a timeout has elapsed. Depending on the result, it either resets the source
and destination IP lists and allows the segment to pass or it increases request
counter \$R_{src}\$ corresponding to the particular source IP address by a
positive integer. If there are more unacknowledged SYN segments originating from
the specific source IP address and \$R_{src}>R_{src}^{max}\$, then this module
decides that the segments are parts of portscan activity and inserts the source
IP address in the filter blacklist. Moreover, the module increases request
counter \$R_{dst}\$ by a positive integer for a particular destination IP
address. If \$R_{dst}>R_{dst}^{max}\$, it means that there is an excessive
number of connections to the destination address. Then, as this behavior may
indicate host scan activity or a SYN flooding attack, the module updates the
filter blacklist to block packets that follow.
"""
def history_check(packet):
  packets.append(packet)
  src = packet[0][1].src
  dst = packet[0][1].dst
  seq = packet["TCP"].seq if "TCP" in packet else 0
  return "Packet src: %s, dst: %s, seqno: %s" % (src, dst, seq)
  

def customAction(packet):
    global packetCount
    packetCount += 1
    packets.append(packet)
    return "Packet #%s: %s ==> %s" % (packetCount,packet[0][1].src, packet[0][1].dst)

def main(argv):
    if len(argv) < 1:
      print "Error: please pass in pcap file."
      sys.exit(1)
    testcap = open(argv[0], 'rb')
    capfile = savefile.load_savefile(testcap, verbose=True)
    print capfile
    #cap = pyshark.FileCapture(argv[0])
    #print cap
    a=scapy.rdpcap(argv[0])
    scapy.sniff(offline=argv[0], prn=history_check)
    print packets[0][1].summary()
    print packets[0].show()
    print packets[0]["TCP"].seq
    

if __name__ == '__main__':
    main(sys.argv[1:])
