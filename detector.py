
import dpkt
import socket
import sys

sampling_rates = [0.005, 0.01, 0.02, 0.04, 0.08, 0.016, 0.03, 0.06, 0.0125, 0.25, 1, 2, 10, 50, 100]
def update_beliefs(bad_ips, good_ips):
    #This runs in n^2 time, but it doesn't really matter for such a small N. 
    print "Evil ips size",len(bad_ips)
    print "Good ips size",len(good_ips)

    for addr in good_ips:
        if addr in bad_ips:
            bad_ips.remove(addr)

    # for evil_ip in bad_ips:
    #     print evil_ip

    # print    
    print "Evil ips size trimmed",len(bad_ips)           
    print
def calculate_stats(sample_bad_ips, sample_good_ips, bad_ips, good_ips):
    

    total_bad_ips = 0;  # find true positive rate
    total_good_ips_bad = 0; # find false positive rate

    for addr in sample_bad_ips:
        if addr in bad_ips:
            total_bad_ips += 1
        if addr in good_ips:
            total_good_ips_bad += 1
    
    print total_bad_ips, total_good_ips_bad

    true_positive_rate = total_bad_ips / len(sample_bad_ips)        
    false_positive_rate = total_good_ips_bad / len(sample_bad_ips)       
    return true_positive_rate, false_positive_rate             

    
def systematic_sampling(all_packets, bad_ips, good_ips):
    print "Systematic_sampling"
    for rate in sampling_rates:
        # print "Rate is", rate
        num_packets_to_sample = round((rate/100.0) * len(all_packets))
        
        print "Sampling ", num_packets_to_sample, "packets"
        if num_packets_to_sample == 0.0: 
            print "Pcap file to small to sample, num packets = 0 !"
            continue

        sample_good_ips = set()
        sample_bad_ips = set()

        for i in xrange(0,len(all_packets), int(round(len(all_packets)/num_packets_to_sample))):
            sample_packet(all_packets[i], sample_bad_ips, sample_good_ips)

        update_beliefs(sample_bad_ips, sample_good_ips)
        tp, fp = calculate_stats(sample_good_ips, sample_good_ips, bad_ips, good_ips)   
        print "TP = ",  tp , "FP = ",  fp   
    print


def sample_packet(ip_packet, bad_ips, good_ips):
    tcp = ip_packet.data

    if ip_packet.p == dpkt.ip.IP_PROTO_TCP:
        syn_flag =  (tcp.flags & dpkt.tcp.TH_SYN ) != 0
        ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
        ip_source = socket.inet_ntoa(ip_packet.src) # get source ip address

        if(syn_flag):
            bad_ips.add(ip_source)
        if(ack_flag):
            good_ips.add(ip_source)



def main(argv):
    
    try: 
        f = open(argv[0])
    except IOError: 
        print "Cannot open file provided"
        return 0

    pcap = dpkt.pcap.Reader(f)

    bad_ips = set()
    good_ips = set()
    all_packets = []

    # creates the ground truth for the rest of the expermient.
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        all_packets.append(ip)
        sample_packet(ip,bad_ips,good_ips);
    
    update_beliefs(bad_ips, good_ips)     
    
    systematic_sampling(all_packets,good_ips, bad_ips) 


if __name__ == "__main__": main(sys.argv[1:])