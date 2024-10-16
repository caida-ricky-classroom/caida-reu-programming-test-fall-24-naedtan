#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>


int main(int argc, char *argv[]) {
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t *handle;
   const unsigned char *packet;
   struct pcap_pkthdr header;
   struct iphdr *ip_header;
   int packet_count = 0;


   if (argc != 2) {
       fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
       return 1;
   }


   handle = pcap_open_offline(argv[1], errbuf);
   if (handle == NULL) {
       fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
       return 1;
   }


   while ((packet = pcap_next(handle, &header)) != NULL) {
      
       //checking whether the amount of packet length is enough for ip + ethernet header(always 14)
       if(header.len < sizeof(struct iphdr) + 14){
           ++packet_count;
           fprintf(stderr, "skipping packet");
           continue;
       }


       ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
       //checking for correct address
       if(ip_header->version != 4){
           fprintf(stderr,"wrong address version");
           ++packet_count;
           continue;
       }
       struct in_addr d_ip;
       d_ip.s_addr = ip_header->daddr;
       printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(d_ip));
  
   }


   pcap_close(handle);
   return 0;
}





