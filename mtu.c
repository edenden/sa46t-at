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
#include "mtu.h"

void fragment_4to6(struct ip6_hdr *ip6, struct ip *ip, char *payload, int payload_size){
	int i, last_flag = 0;
	int fragmented_size;
	char *ptr = payload;
	struct ip6_frag ip6f;
	uint8_t proto;
	struct iovec iov[4];
	struct tun_pi pi;
	int offset = 0;

        if((ip->ip_off & htons(IP_DF)) > 0){
		/* send packet too big and drop */
		send_packet_too_big(ip);
                return;
        }

	memset(&ip6f, 0, sizeof(struct ip6_frag));
	proto = ip6->ip6_nxt;
	ip6->ip6_nxt = IPPROTO_FRAGMENT;

	while(payload_size > 0){
		memset(&ip6f, 0, sizeof(struct ip6_frag));
		if(payload_size > MIN_MTU - (sizeof(struct ip6_hdr) + sizeof(struct ip6_frag))){
			fragmented_size = MIN_MTU - (sizeof(struct ip6_hdr) + sizeof(struct ip6_frag));
			payload_size -= fragmented_size;
		}else{
			fragmented_size = payload_size;
			payload_size = 0;
			last_flag = 1;
		}

		ip6->ip6_plen = htons(fragmented_size + sizeof(struct ip6_frag));
		ip6f.ip6f_nxt = proto;
		ip6f.ip6f_offlg = htons(offset);
		if(!last_flag){
			ip6f.ip6f_offlg |= IP6F_MORE_FRAG;
		}
		ip6f.ip6f_ident = ip->ip_id;
		
		tun_set_af(&pi, AF_INET6);
		iov[0].iov_base = &pi;
		iov[0].iov_len = sizeof(pi);
		iov[1].iov_base = ip6;
		iov[1].iov_len = sizeof(struct ip6_hdr);
		iov[2].iov_base = &ip6f;
		iov[2].iov_len = sizeof(struct ip6_frag);
		iov[3].iov_base = ptr;
		iov[3].iov_len = fragmented_size;

		send_iovec(iov, 4);

		offset += fragmented_size;
		ptr = ptr + fragmented_size;
	
	}
}

void send_packet_too_big(struct ip *received){
	struct too_big tb;
	struct sockaddr_in dst;

	memset(&tb, 0, sizeof(struct too_big));

	tb.icmp.icmp_type = ICMP_DEST_UNREACH;
	tb.icmp.icmp_code = ICMP_FRAG_NEEDED;
	tb.icmp.icmp_nextmtu = htons(MTU - (sizeof(struct ip6_hdr) - sizeof(struct ip)));

	memcpy(&(tb.icmp.icmp_ip), received, sizeof(struct ip) + 64);

        tb.icmp.icmp_cksum = 0;
        tb.icmp.icmp_cksum = ip_checksum((unsigned short *)&tb, sizeof(struct too_big));

	memset(&dst, 0, sizeof(struct sockaddr_in));
	dst.sin_family = AF_INET;
	dst.sin_addr = received->ip_src;

	send_raw(&tb, sizeof(tb), (struct sockaddr *)&dst);
}
