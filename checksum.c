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
#include "checksum.h"

unsigned short ip6_transport_checksum(struct ip6_hdr *ip6, unsigned short *payload, int payloadsize){
        unsigned long sum = 0;

        struct pseudo_ipv6_header p;
        unsigned short *f = (unsigned short *)&p;
        int pseudo_size = sizeof(p);

        memset(&p, 0, sizeof(struct pseudo_ipv6_header));
        p.src_address = ip6->ip6_src;
        p.dst_address = ip6->ip6_dst;
        p.upper_layer_size = htonl(payloadsize);
        p.ip6_p_nxt = ip6->ip6_nxt;

        while (pseudo_size > 1) {
                sum += *f;
                f++;
                pseudo_size -= 2;
        }

        while (payloadsize > 1) {
                sum += *payload;
                payload++;
                payloadsize -= 2;
        }

        if (payloadsize == 1) {
		sum += htons(*(unsigned char *)payload << 8);
        }

        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);

        return ~sum;
}

unsigned short ip4_transport_checksum(struct ip *ip, unsigned short *payload, int payloadsize){
        unsigned long sum = 0;

        struct pseudo_ipv4_header p;
        unsigned short *f = (unsigned short *)&p;
        int pseudo_size = sizeof(p);

        memset(&p, 0, sizeof(struct pseudo_ipv4_header));
        p.src_address = ip->ip_src;
        p.dst_address = ip->ip_dst;
        p.ip_p_nxt = ip->ip_p;
	p.ip_p_len = htons(payloadsize);

        while (pseudo_size > 1) {
                sum += *f;
                f++;
                pseudo_size -= 2;
        }

        while (payloadsize > 1) {
                sum += *payload;
                payload++;
                payloadsize -= 2;
        }

        if (payloadsize == 1) {
		sum += htons(*(unsigned char *)payload << 8);
        }

        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);

        return ~sum;
}

unsigned short ip_checksum(unsigned short *buf, int size){
        unsigned long sum = 0;

        while (size > 1) {
                sum += *buf++;
                size -= 2;
        }
        if(size){
		sum += htons(*(unsigned char *)buf << 8);
	}

        sum  = (sum & 0xffff) + (sum >> 16);    /* add overflow counts */
        sum  = (sum & 0xffff) + (sum >> 16);    /* once again */

        return ~sum;
}

