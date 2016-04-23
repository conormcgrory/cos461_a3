import sys
import threading
from subprocess import call
from scapy.all import sniff as scasniff, sendp
from scapy.all import *

def fprint(x):
    print x
    sys.stdout.flush()

class PacketHandler:
        
    def __init__(self, intf_list, conn_intf_dict, ip_map):
        
        # Fields passed as arguments
        self.intf_list = intf_list
        self.conn_intf_dict = conn_intf_dict
        self.ip_map = ip_map
        
        # Global dict mapping hosts to query IDs
        self.queries = {}

        # Lock for queries dict
        self.queries_lock = threading.Lock()

        # Global dict mapping hosts to invalid query counts
        self.counts = {}
        
        # Lock for counts dict
        self.counts_lock = threading.Lock()

        # Global dict mapping to keep track of attacked hosts
        self.attacked = {}
        
        # Lock for attacked dict
        self.attacked_lock = threading.Lock()

        # Populate dicts with host names
        for ip_list in ip_map.values():
            for ip in ip_list:
                self.queries[ip] = []
                self.counts[ip] = 0
                self.attacked[ip] = False
        
		
    def start(self):
        for (in_intf, out_intf) in self.intf_list:
            t = threading.Thread(target = self.sniff, args = (in_intf, out_intf))
            t.start()
    
    def incoming(self, pkt, in_intf, out_intf):
        mac1 = self.conn_intf_dict[in_intf]
        mac2 = self.conn_intf_dict[out_intf]

        res = (pkt[Ether].src in mac1 or
               pkt[Ether].dst in mac2 or
                pkt[Ether].dst == "ff:ff:ff:ff:ff:ff")
        return res


    def handle_dns_query(self, pkt):
        
        # Determine host
        src_host = pkt[IP].src
        
        # Determine query id
        query_id = pkt[DNS].id
        
        # Add host and id to global dict
        self.queries_lock.acquire()
        self.queries[src_host].append(query_id)
        self.queries_lock.release()

    
    def handle_dns_reply(self, pkt):
        
        # Determine host
        dst_host = pkt[IP].dst
                
        # Determine query id
        query_id = pkt[DNS].id

        # If this is not a valid query, increment count and check for attack
        if query_id not in self.queries[dst_host]:

            # Increment count 
            self.counts_lock.acquire()
            self.counts[dst_host] += 1
            self.counts_lock.release()

            # Check for attack
            if (self.counts[dst_host] > 200) and (self.attacked[dst_host] == False):
                self.handle_attack(dst_host)
                

    def handle_attack(self, host):
        
        # Print message if we have detected an attack (debugging)
        fprint('DNS Reflection attack detected!!')        
        fprint('Host: {0}'.format(host))

        # Mark host as attacked
        self.attacked_lock.acquire()
        self.attacked[host] = True
        self.attacked_lock.release()

        ## Define commands -- we couldn't quite get these to work 
        
        # Command 1 should create the queueing discipline
        #cmd_1 = ('tc qdisc add dev mb-eth0 root handle 1: '
        #         'cbq avpkt 1000 bandwidth 10mbit')

        # Command 2 should create the class with reduced rate
        #cmd_2 = ('tc class add dev mb-eth0 parent 1: classid 1:1 cbq rate 512kbit'
        #         'allot 1500 prio 5 bounded isolated')

        # Command 3 should create that filter that matches only 
        # Right now, it is just a catch-all filter we were using for debugging purposes
        #cmd_3 = ('tc filter add dev mb-eth0 parent 1: protocol ip prio 16 u32'
        #         'match u32 0 0 at 0 flowid 1:1')

        # Call commands -- this should establish rate limiting
        #call(cmd_1)
        #call(cmd_2)
        #call(cmd_3)
        

    def handle_packet(self, in_intf, out_intf, pkt):

        # Handling ARP (DO NOT CHANGE)
        if (pkt[Ether].dst == "ff:ff:ff:ff:ff:ff"): 
            if(pkt[Ether].type == 2054 and
                pkt[ARP].psrc in self.ip_map[in_intf] and
                pkt[ARP].pdst in self.ip_map[out_intf]):
                arp_header = pkt[ARP]
                arp_header.op = 2
                arp_header.hwdst = arp_header.hwsrc
                pdst = arp_header.pdst
                hwsrc =  "00:00:00:00:00:0%s" % pdst[-1]
                arp_header.hwsrc = hwsrc               
                arp_header.pdst = arp_header.psrc
                arp_header.psrc = pdst
                pkt = Ether(src=hwsrc, dst=pkt[Ether].src)/arp_header    
                sendp(pkt, iface=in_intf, verbose = 0)
            return
	
        # TODO: process the packet beforing sending it out
        fprint("received from %s" % in_intf)

        # Packet is DNS message
        if pkt.haslayer(DNS):
            
            # Packet is DNS query
            if pkt[DNS].qr == 0:
                self.handle_dns_query(pkt)

            # Packet is DNS reply
            elif pkt[DNS].qr == 1:
                self.handle_dns_reply(pkt)
                
            
        # Forwarding the traffic to the target network (DO NOT CHANGE)
        sendp(pkt, iface=out_intf, verbose = 0)

    def sniff(self, in_intf, out_intf):
        scasniff(iface=in_intf, prn = lambda x : self.handle_packet(in_intf, out_intf, x),
                  lfilter = lambda x : self.incoming(x, in_intf, out_intf)) 
    
if __name__ == "__main__":
    intf1 = "mb-eth0"
    conn_mac1 = ["00:00:00:00:00:01", "00:00:00:00:00:04"]
    ip_list_1 = ["10.0.0.1", "10.0.0.4"]
    intf2 = "mb-eth1"
    ip_list_2 = ["10.0.0.2", "10.0.0.3"]
    conn_mac2 = ["00:00:00:00:00:02", "00:00:00:00:00:03"]
    
    intf_list = [(intf1, intf2), (intf2, intf1)]
    conn_intf_dict = {intf1 : conn_mac1, intf2 : conn_mac2}
    ip_map = {intf1 : ip_list_1, intf2 : ip_list_2}
    handler = PacketHandler(intf_list, conn_intf_dict, ip_map)
    handler.start() 

