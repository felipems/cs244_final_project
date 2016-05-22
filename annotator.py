import dpkt
import socket

def main():
    f = open('syn_attack.pcap')
    pcap = dpkt.pcap.Reader(f)

    evil_ips = set()
    good_ips = set()

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        # print tcp.sport
        # print tcp.dport
        

        if ip.p == dpkt.ip.IP_PROTO_TCP:
            syn_flag =  (tcp.flags & dpkt.tcp.TH_SYN ) != 0
            ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
            ip_source = socket.inet_ntoa(ip.src) # get source ip address

            if(syn_flag):
                evil_ips.add(ip_source)
            if(ack_flag):
                good_ips.add(ip_source)
                # print ip_source 

            # print syn_flag
        
        # print 

    #This runs in n^2 time, but it doesn't really matter. 

    # print evil_ips
    print "Evil ips size",len(evil_ips)
    print "Good ips size",len(good_ips)
    print

    for addr in good_ips:
        if addr in evil_ips:
            evil_ips.remove(addr)

    for evil_ip in evil_ips:
        print evil_ip
        # print
    print    
    print "Evil ips size trimmed",len(evil_ips)           
    print
if __name__ == "__main__": main()