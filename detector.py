import dpkt
import socket
import sys
import random
import time
# import matplotlib
import matplotlib.pyplot as plt
import gc

sampling_rates = [0.005, 0.01, 0.02, 0.04, 0.08, 0.016, 0.03, 0.06, 0.0125, 0.25, 1, 2, 10, 50, 100]

def delete_negatives(stats):
    for key in stats.keys():
      if (stats[key] < 0):
        del stats[key]

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
            return -1.0, -1.0

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

    results_tp ={}
    results_fp ={}

    for rate in sampling_rates:
        # print "Rate is", rate
        num_packets_to_sample = round((rate/100.0) * len(all_packets))
        
        print "Sampling ", num_packets_to_sample, "packets at rate ", rate
        if num_packets_to_sample == 0.0: 
            print "Pcap file to small to sample, num packets = 0 !"
            continue

        sample_good_ips = set()
        sample_bad_ips = set()

        for i in xrange(0,len(all_packets), int(round(len(all_packets)/num_packets_to_sample))):
            sample_packet(all_packets[i], sample_bad_ips, sample_good_ips)

        update_beliefs(sample_bad_ips, sample_good_ips)
        tp, fp = calculate_stats(sample_bad_ips, sample_good_ips, bad_ips, good_ips)
        results_tp[rate] = tp
        results_fp[rate] = fp
        print "TP = ",  tp , "FP = ",  fp   
    print
    return results_tp, results_fp


def random_sampling(all_packets, bad_ips, good_ips):
    print "******Random_sampling******"
    print
    results_tp ={}
    results_fp ={}
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
        results_tp[rate] = tp
        results_fp[rate] = fp
    print
    return results_tp, results_fp    

def uniform_prob_sampling(all_packets, bad_ips, good_ips):
    print "******Uniform_prob_sampling******"
    print
    results_tp ={}
    results_fp ={}
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
        results_tp[rate] = tp
        results_fp[rate] = fp
    print
    return results_tp, results_fp    

def sample_packet(ip_packet, bad_ips, good_ips):
    try:
        if ip_packet.p == dpkt.ip.IP_PROTO_TCP:
            tcp = ip_packet.data
            syn_flag =  (tcp.flags & dpkt.tcp.TH_SYN ) != 0
            ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
            ip_source = socket.inet_ntoa(ip_packet.src) # get source ip address

            if(syn_flag):
                bad_ips.add(ip_source)
            if(ack_flag):
                good_ips.add(ip_source)
    except AttributeError:
        return            

def graph(out_stats, y_label):
    # rates = []
    # tps = []
    # for rate, tp in out_stats_tp["SS"].items():
    #     rates.append(rate)
    #     tps.append(tp)
    #     # print tp

    

    # print len(rates)

    # print len(tps)
    # print rates
    # print tps     

    # for elem in tps:
    #     print elem
    plt.plot( out_stats["SS"].keys(), out_stats["SS"].values(), \
        marker='o', linestyle='--', color='r', label="Systematic Sampling")
    """
    plt.legend()
    plt.scatter( out_stats["RS"].keys(), out_stats["RS"].values(), \
        marker='^', linestyle='--', color='b', label="Random 1 in N Sampling")
    plt.legend()
    plt.scatter( out_stats["US"].keys(), out_stats["US"].values(), \
        marker='+', linestyle='--', color='g', label="Uniform Sampling")
    plt.legend()
  """
    plt.xlabel('Sampling Rate')
    plt.ylabel(y_label)
    plt.xscale('log')
    plt.show()

def graph_ind(out_stats, y_label):
    for key in out_stats:
         delete_negatives(out_stats[key])
         plt.figure() 
         plt.title(key)
         ax1 = plt.axes()
         ax1.scatter( out_stats[key].keys(), out_stats[key].values(), \
             marker='o', linestyle='--', color='r')
         plt.xlabel('Sampling Rate')
         plt.ylabel(y_label)
         plt.xscale('log')
         ax1.set_ylim([0, 1.1])
         ax1.set_xlim([0, 100.0])
         plt.show()

def main(argv):
    time_start = time.time()
    if len(argv) < 1:
        print "Please include pcap file."
        return 0

    bad_ips = set()
    good_ips = set()
    all_packets = []
    out_stats_tp = {}
    out_stats_fp = {}


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
            print "Raw IP on file", pcap_file
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
            if len(all_packets)%1000000 ==0:             
                print len(all_packets)/1000000," million"
                gc.collect()
        
    print bad_ips        
    print "Updating beliefs"
    update_beliefs(bad_ips, good_ips)     
    
    print bad_ips
    print "Done reading files, now calculating!"
    out_stats_tp["SS"], out_stats_fp["SS"]  = systematic_sampling(all_packets,bad_ips, good_ips) 
    out_stats_tp["RS"], out_stats_fp["RS"]  = random_sampling(all_packets,bad_ips, good_ips) 
    out_stats_tp["US"], out_stats_fp["US"]  = uniform_prob_sampling(all_packets,bad_ips, good_ips)
    time_end = time.time()

    print "experiment started at:", time_start
    print "experiment ended at:", time_end
    print "experiment took:", time_end - time_start
    print "experiment processed ", len(all_packets)
    graph_ind(out_stats_tp, "True Positive Rate [%]")
    graph_ind(out_stats_fp, "False Positive Rate [%]")

if __name__ == "__main__": main(sys.argv[1:])
