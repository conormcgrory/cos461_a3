import sys
import threading
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

        # Populate queries and counts dicts
        for ip_list in ip_map.vals():
            for ip in ip_list:
                self.queries[ip] = []
                self.counts[ip] = 0
        
		
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
                
                # Determine host
                src_host = pkt[IP].src

                # Determine query id
                query_id = pkt[DNS].id
                
                # Add host and id to global dict
                self.queries_lock.acquire()
                self.queries[src_host].append(query_id)
                self.queries_lock.release()

            # Packet is DNS response
            elif pkt[DNS].qr == 1:

                # Determine host
                dst_host = pkt[IP].dst
                
                # Determine query id
                query_id = pkt[DNS].id

                # If this is not a valid query, increment the count for its host
                if query_id not in self.queries[dst_host]:
                    self.counts_lock.acquire()
                    self.counts[dst_host]++
                    self.counts_lock.release()

            
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

