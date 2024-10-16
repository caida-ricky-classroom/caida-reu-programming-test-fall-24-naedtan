#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>


int strilength(const char *str){
   int len = 0;
   while(str[len] != '\0'){
       ++len;
   }
   return len;
}


int main(int argc, char *argv[]) {
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t *handle;
   const unsigned char *packet;
   struct pcap_pkthdr header;
   struct iphdr *ip_header;
   int packet_count = 0;
   int last_octet_arr[256] = {0};


   if (argc != 2) {
       fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
       return 1;
   }


   handle = pcap_open_offline(argv[1], errbuf);
   if (handle == NULL) {
       fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
       return 1;
   }




   while ((packet = pcap_next(handle, &header)) != NULL & packet_count < 50){
      
       //checking whether the amount of packet length is enough for ip + ethernet header(always 14)
       if(header.len < sizeof(struct iphdr) + 14){
           ++packet_count;
           fprintf(stderr, "skipping packet");
           continue;
       }


       ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
       if(ip_header->version != 4){
           fprintf(stderr,"wrong address version");
           ++packet_count;
           continue;
       }




       struct in_addr d_ip;
       d_ip.s_addr = ip_header->daddr;


       // ip address to str
       char ip_str[INET_ADDRSTRLEN];
       inet_ntop(AF_INET, &d_ip, ip_str, sizeof(ip_str));


       char lastOctet[4] = {0};
       int len = strilength(ip_str);
       int start_index = 7;
      
       int j = 0;


       for (int i = start_index; i < len; ++i, ++j) {
           //copying last octet over
           lastOctet[j] = ip_str[i];
       }
      
       lastOctet[j] = '\0'; // null terminate


       //turning the string of ascii values into integer
       int num = 0;
       for(int j = 0; j < 3 && lastOctet[j] != '\0'; ++j){
           int digit = lastOctet[j] - 48;
           num = num * 10 + digit;
       }
       //using array, increment for number of times ip octet appears
       ++last_octet_arr[num];
       printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(d_ip));




      
   }
   //loop through the array and print occurences of each octet
   for(int i = 0;i < 256; ++i){
            if(last_octet_arr[i] >= 1){
                printf("Last Octet %d: %d\n",i,last_octet_arr[i]);
            }
    }
   pcap_close(handle);
   return 0;
}







