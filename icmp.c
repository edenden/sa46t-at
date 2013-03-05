#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <pthread.h>
#include <linux/if_tun.h>

#include "main.h"
#include "session.h"
#include "translate.h"
#include "icmp.h"

void process_icmpv6_packet(char *buf, int len){
	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buf;
	struct icmp *icmp = (struct icmp *)buf;

	switch (icmp6->icmp6_type) {
		case ICMP6_ECHO_REQUEST :       
			icmp->icmp_type = ICMP_ECHO;
			break;

		case ICMP6_ECHO_REPLY :
			icmp->icmp_type =  ICMP_ECHOREPLY;
			break;

		case ICMP6_TIME_EXCEEDED :
			icmp->icmp_type = ICMP_TIMXCEED;
			break;

		case ICMP6_PARAM_PROB :
			icmp->icmp_type = ICMP_PARAMPROB;
			break;

		case ICMP6_DST_UNREACH :
			translate_icmpv6_unreach(buf);
			break;

		default:
			icmp->icmp_type = 0xff;
			break;
        }

	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = ip_checksum((unsigned short *)icmp, len);

	return;
}

void process_icmp_packet(struct ip6_hdr *header, char *buf, int len){
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buf;
        struct icmp *icmp = (struct icmp *)buf;

	switch (icmp->icmp_type) {
		case ICMP_ECHOREPLY :
	                icmp6->icmp6_type = ICMP6_ECHO_REPLY;
	                break;
	
	        case ICMP_ECHO :
	                icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	                break; 

	        case ICMP_UNREACH :
	                translate_icmp_unreach(buf);
	                break; 
	
	        case ICMP_TIMXCEED :
	                icmp6->icmp6_type = ICMP6_TIME_EXCEED_TRANSIT;
	                break;
	
	        case ICMP_PARAMPROB :
	                icmp6->icmp6_type = ICMP6_PARAM_PROB;
	                break;
	
	        default :
	                icmp6->icmp6_type = 0xff;       /* UnKnown */
	                break;
        }

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = ip6_transport_checksum(header, (unsigned short *)buf, len);

	return;
}

void translate_icmpv6_unreach(char *buf){
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buf;
        struct icmp *icmp = (struct icmp *)buf;
	icmp->icmp_type = ICMP_UNREACH;

        switch (icmp6->icmp6_code) {
	        case ICMP6_DST_UNREACH_NOROUTE :
	                icmp->icmp_code = ICMP_UNREACH_NET;
	                break;

	        case ICMP6_DST_UNREACH_ADMIN :
	                icmp->icmp_code = ICMP_UNREACH_FILTER_PROHIB;
	                break;

	        case ICMP6_DST_UNREACH_ADDR :
	                icmp->icmp_code = ICMP_UNREACH_HOST;
	                break;

	        case ICMP6_DST_UNREACH_NOPORT :
	                icmp->icmp_code = ICMP_UNREACH_PORT;
	                break;

	        default :
	                icmp->icmp_code = 0xff;
	                break;
        }

	return;
}

void translate_icmp_unreach(char *buf){
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buf;
        struct icmp *icmp = (struct icmp *)buf;
        icmp6->icmp6_type = ICMP6_DST_UNREACH;
	
        switch (icmp->icmp_code) {
	        case ICMP_UNREACH_NET :
	                icmp6->icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
	                break;
	
	        case ICMP_UNREACH_HOST :
	                icmp6->icmp6_code = ICMP6_DST_UNREACH_ADDR;
	                break;
	
	        case ICMP_UNREACH_PORT :
	                icmp6->icmp6_code = ICMP6_DST_UNREACH_NOPORT;
	                break;
	
	        case ICMP_UNREACH_TOSHOST       :
	        case ICMP_UNREACH_NET_PROHIB    :
	        case ICMP_UNREACH_HOST_PROHIB   :
	                icmp6->icmp6_code = ICMP6_DST_UNREACH_ADMIN;
	                break;
	
	        default:
	                icmp6->icmp6_code = 0xFF;       /* UnKnown */
	                break;
        }
	
        return;
}

