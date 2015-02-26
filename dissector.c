#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>

#include "libpcap_sniffex.h"

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /*
      FILL HERE
      calculate time since first captured packet using 
      struct timeval substract(const struct timeval*, const struct timeval*)
      provided in libpcap_sniffex.h
    */
	struct pcap_pkthdr* last;
	u_char **input = (u_char **)args;
	u_char *user = *input;
	last = (struct pcap_pkthdr*) user;
	//printf("\n%ld %ld\n\n",last->ts.tv_sec, last->ts.tv_usec);	
	struct timeval startTime;
	struct timeval endTime;
	struct timeval tm_from_capture;
	startTime = header->ts;
	//printf("\n%ld %ld\n\n",header->ts.tv_sec, header->ts.tv_usec);
	if(last->ts.tv_sec == 0 && last->ts.tv_usec == 0){
		last->ts.tv_sec = header->ts.tv_sec;
		last->ts.tv_usec = header->ts.tv_usec;
	}
	endTime = last->ts;
	tm_from_capture = substract( &startTime, &endTime);
    /* print time since first captured packet */
    printf("%ld.%06ld  ", tm_from_capture.tv_sec, tm_from_capture.tv_usec);

    /* declare pointers to packet headers */
    const struct sniff_wlan *wlan;          /* 802.11 header  */
    const struct sniff_ip *ip;              /* The IP header  */
    const struct sniff_udp *udp;		    /* The UDP header */
    const struct sniff_tcp *tcp;            /* The TCP header */

    int size_ip;
    int layer2_size = 0;

    /* define wlan header */
    wlan = (struct sniff_wlan*)(packet + SIZE_AVS);
    const u_char* source;
    const u_char* destination;

    /*
      FILL HERE
      print source MAC addr, destination MAC addr in hex format using 
      void print_wlan_addr(const u_char*) provided in libpcap_sniffex.h
      NOTE: You need to analyze the wlan header to figure out which address field is source addr, which is dest addr
    */
	/*wlan->wlan_svt = wlan;
	wlan->wlan_flags = wlan+1;
	wlan->wlan_duration = wlan+2;
	wlan->wlan_addr1 = wlan+4;
	wlan->wlan_addr2 = wlan+10;
	wlan->wlan_addr3 = wlan+16;
	wlan->wlan_frag_seq = wlan+22;*/
	int toDS = (wlan->wlan_flags & 0x10000000)>> 7;
	int fromDS = (wlan->wlan_flags & 0x01000000)>> 6;
	//printf("%d %d\n", toDS, fromDS);
	if(fromDS == 0 && toDS == 0 ){
		source = wlan->wlan_addr2;
		destination = wlan->wlan_addr1;
	}else if(fromDS == 1 && toDS == 0 ){
		source = wlan->wlan_addr3;
		destination = wlan->wlan_addr2;
	}else if(fromDS == 0 && toDS == 1 ){
		source = wlan->wlan_addr1;
		destination = wlan->wlan_addr3;
	}
	printf("SA:");
	print_wlan_addr(source);
	printf("DA:");
	print_wlan_addr(destination);

    layer2_size = SIZE_AVS + SIZE_WLAN + SIZE_WLAN_LLC;

    /* this is to address the issue when subtype version is 8, 8 is actually a
     * reserved subtype, it seems to have 802.11e */
    if (WLAN_SUBTYPE(wlan) == 8)
	    layer2_size = layer2_size + 2;

    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + layer2_size);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

	/* determine protocol */
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            /*
              FILL HERE
              print source IP addr, source TCP port, destination IP addr, destination TCP port, IP length
              e.g., SA:00:1b:63:00:63:43  DA:00:25:bc:4c:8a:de  S_IP:74.125.211.85  S_PORT:80  D_IP:10.0.2.4  D_PORT:49186  IP_LEN:1500 
            */
			tcp = (struct sniff_tcp*)(packet+layer2_size+size_ip);
			printf("S_IP:%s  ", inet_ntoa(ip->ip_src));
			printf("S_PORT:%d  ", ntohs(tcp->th_sport));
			printf("D_IP:%s  ", inet_ntoa(ip->ip_dst));
			printf("D_PORT:%d  ", ntohs(tcp->th_dport));
			printf("IP_LEN:%d\n", ntohs(ip->ip_len));
			//printf("S_IP:%hu S_PORT:%hu  D_IP:%hu  D_PORT:%hu  IP_LEN:%hu\n", ip->ip_src.s_addr, tcp->th_sport, ip->ip_dst.s_addr, tcp->th_dport, ip->ip_len);
            break;
        case IPPROTO_UDP:
            /*
              FILL HERE
              print source IP addr, source UDP port, destination IP addr, destination UDP port, IP length
              e.g., SA:00:25:bc:4c:8a:de  DA:00:1b:63:00:63:43  S_IP:10.0.2.4  S_PORT:80  D_IP:98.180.194.181  D_PORT:1377  IP_LEN:60 
            */
			udp =(struct sniff_udp*)((packet+layer2_size+size_ip));
			printf("S_IP:%s  ", inet_ntoa(ip->ip_src));
			printf("S_PORT:%d  ", ntohs(udp->th_sport));
			printf("D_IP:%s  ", inet_ntoa(ip->ip_dst));
			printf("D_PORT:%d  ", ntohs(udp->th_dport));
			printf("IP_LEN:%d\n", ntohs(ip->ip_len));
			//printf("S_IP:%hu  S_PORT:%hu  D_IP:%hu  D_PORT:%hu  IP_LEN:%hu\n", ip->ip_src.s_addr, udp->th_sport, ip->ip_dst.s_addr, udp->th_dport, ip->ip_len);
	    break;
        default:
            return;
    }

    return;
}

int main(int argc, char **argv)
{
    /* Read from .pcap FILE */
    if (argc != 2) {
	    printf("Usage: packet_info <file name>\n");
	    exit(EXIT_FAILURE);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);

    if (handle == NULL) {
	    fprintf(stderr, "Could not open file %s\n", argv[1]);
	    exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    char filter_exp[] = "";		/* filter expression [3] */
    struct bpf_program fp;		/* compiled filter program (expression) */
    bpf_u_int32 netmask = 0; 	/* ip */
    int optimize=0;				/* Do not optimize the compiled expression in pcap_compile*/

    if (pcap_compile(handle, &fp, filter_exp, optimize, netmask) == -1) {
	    fprintf(stderr, "Could not parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
	    exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
	    fprintf(stderr, "Could not install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
	    exit(EXIT_FAILURE);
    }

    struct pcap_pkthdr first_pkthdr;
    first_pkthdr.ts.tv_sec = 0;
    first_pkthdr.ts.tv_usec = 0;
    u_char* user = (u_char*)&first_pkthdr;

    /* process the packet-capture file */
    int num_packets = -1;		/* The number of packets to capture; -1 indicates that pcap_loop should loop over all packets in the data file */
    u_char **user_input=&user; 	/* The "user_input" field allow data to be passed to the got_packet function*/
    pcap_loop(handle, num_packets, got_packet, (u_char*)user_input);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}

