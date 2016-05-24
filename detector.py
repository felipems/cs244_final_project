import dpkt
import socket
import sys
import random
import time

sampling_rates = [0.005, 0.01, 0.02, 0.04, 0.08, 0.016, 0.03, 0.06, 0.0125, 0.25, 1, 2, 10, 50, 100]
def update_beliefs(bad_ips, good_ips):
    #This runs in n^2 time, but it doesn't really matter for such a small N. 
    # print "Evil ips size",len(bad_ips)
    # print "Good ips size",len(good_ips)

    for addr in good_ips:
        if addr in bad_ips:
            bad_ips.remove(addr)

    # for evil_ip in bad_ips:
    #     print evil_ip

    # print    
    # print "Evil ips size trimmed",len(bad_ips)           
    print
def calculate_stats(sample_bad_ips, sample_good_ips, bad_ips, good_ips):
    
    if len(sample_bad_ips) == 0:
            return -1, -1

    total_bad_ips = 0;  # find true positive rate
    total_good_ips_in_bad = 0; # find false positive rate

    for addr in sample_bad_ips:
        if addr in bad_ips:
            total_bad_ips += 1
        if addr in good_ips:
            total_good_ips_in_bad += 1
    
    print "total_bad_ips: ", total_bad_ips, "total_good_ips_in_bad: ", total_good_ips_in_bad, "Total len", len(sample_bad_ips)

    true_positive_rate = float(total_bad_ips) / float(len(sample_bad_ips))        
    false_positive_rate = float(total_good_ips_in_bad) / float(len(sample_bad_ips))       
    return true_positive_rate, false_positive_rate             

    
def systematic_sampling(all_packets, bad_ips, good_ips):
    print "******Systematic_sampling******"
    print
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
        tp, fp = calculate_stats(sample_bad_ips, sample_good_ips, bad_ips, good_ips)   
        print "TP = ",  tp , "FP = ",  fp   
    print

def random_sampling(all_packets, bad_ips, good_ips):
    print "******Random_sampling******"
    print
    for rate in sampling_rates:
        # print "Rate is", rate
        num_packets_to_sample = round((rate/100.0) * len(all_packets))
        
        print "Sampling ", num_packets_to_sample, "packets"
        if num_packets_to_sample == 0.0: 
            print "Pcap file to small to sample, num packets = 0 !"
            continue

        sample_good_ips = set()
        sample_bad_ips = set()

        n = int(round(len(all_packets)/num_packets_to_sample))
        for i in xrange(0,len(all_packets), n):
            modifier = random.randrange(0, n)
            # print "index ",i , "modifier", modifier,"size of list", len(all_packets)
            if i + modifier >= len(all_packets): # TODO this can introduce an error of one packet! For large N it might not matter... 
                continue
            sample_packet(all_packets[i + modifier ], sample_bad_ips, sample_good_ips)

        update_beliefs(sample_bad_ips, sample_good_ips)
        tp, fp = calculate_stats(sample_bad_ips, sample_good_ips, bad_ips, good_ips)   
        print "TP = ",  tp , "FP = ",  fp   
    print    

def uniform_prob_sampling(all_packets, bad_ips, good_ips):
    print "******Uniform_prob_sampling******"
    print
    for rate in sampling_rates:
        # print "Rate is", rate
        prob_choosing_a_packet = rate/100.0
        num_packets_to_sample = prob_choosing_a_packet *  len(all_packets)
        
        print "Sampling ", num_packets_to_sample, "packets"
        if num_packets_to_sample == 0.0: 
            print "Pcap file to small to sample, num packets = 0 !"
            continue

        sample_good_ips = set()
        sample_bad_ips = set()

        n = int(round(len(all_packets)/num_packets_to_sample))
        for i in xrange(0,len(all_packets)):
            threshold = random.uniform(0,1);

            if threshold < prob_choosing_a_packet:
                sample_packet(all_packets[i], sample_bad_ips, sample_good_ips)

        update_beliefs(sample_bad_ips, sample_good_ips)
        tp, fp = calculate_stats(sample_bad_ips, sample_good_ips, bad_ips, good_ips)   
        print "TP = ",  tp , "FP = ",  fp   
    print    

def sample_packet(ip_packet, bad_ips, good_ips):
    if ip_packet.p == dpkt.ip.IP_PROTO_TCP:
        tcp = ip_packet.data
        syn_flag =  (tcp.flags & dpkt.tcp.TH_SYN ) != 0
        ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
        ip_source = socket.inet_ntoa(ip_packet.src) # get source ip address

        if(syn_flag):
            bad_ips.add(ip_source)
        if(ack_flag):
            good_ips.add(ip_source)



def main(argv):
    time_start =time.asctime( time.localtime(time.time()) )
    if len(argv) < 1:
        print "Please include pcap file."
        return 0

    bad_ips = set()
    good_ips = set()
    all_packets = []

    print "Using these files:"
    for pcap_file in argv:
        print pcap_file
    
    for pcap_file in argv:
        try: 
            f = open(pcap_file)
        except IOError: 
            print "Cannot open file provided", pcap_file
            return 0

        raw_ip = False
        pcap = dpkt.pcap.Reader(f)
        if pcap.datalink() == 101:
            print "Raw IP"
            raw_ip = True

        
        # creates the ground truth for the rest of the expermient.
        for ts, buf in pcap:
            if raw_ip:
                try:
                    ip = dpkt.ip.IP(buf)
                except :
                    continue           
            else:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
            all_packets.append(ip)
            sample_packet(ip,bad_ips,good_ips);
    
    print "Updating beliefs"
    update_beliefs(bad_ips, good_ips)     
    
    print "Done reading files, now calculating!"
    systematic_sampling(all_packets,bad_ips, good_ips) 
    random_sampling(all_packets,bad_ips, good_ips) 
    uniform_prob_sampling(all_packets,bad_ips, good_ips)
    time_end = time.asctime( time.localtime(time.time()) )

    print "experiment started at:", time_start
    print "experiment ended at:", time_end
    # print "experiment took" 

if __name__ == "__main__": main(sys.argv[1:])
