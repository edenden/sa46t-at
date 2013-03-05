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
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <linux/if_tun.h>
#include <syslog.h>

#include "main.h"
#include "session.h"
#include "translate.h"
#include "icmp.h"
#include "checksum.h"

struct in6_addr sa46t_map_4to6_addr(struct in6_addr sa46t_prefix, u_int32_t plane_id, struct in_addr ip){
        struct in6_addr sa46t_addr;

        sa46t_addr.s6_addr32[0] = sa46t_prefix.s6_addr32[0];
        sa46t_addr.s6_addr32[1] = sa46t_prefix.s6_addr32[1];
        sa46t_addr.s6_addr32[2] = htonl(plane_id);
        sa46t_addr.s6_addr32[3] = ip.s_addr;

        return sa46t_addr;
}


struct in_addr sa46t_extract_6to4_addr(struct in6_addr sa46t_addr){
        struct in_addr addr;
        addr.s_addr = sa46t_addr.s6_addr32[3];

        return addr;
}

void process_ipv4_packet(char *buf, int len){
	struct ip *ip = (struct ip *)buf;
	struct mapping *result;

	if((result = search_mapping_table_v4(ip->ip_dst)) != NULL){
		reset_ttl(result);
		translate_4to6(result, buf, len);
	}

}

void process_ipv6_packet (char *buf, int len){
	struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
	struct mapping *result;
	char log_ipv6[256];
	char log_ipv4[256];

	if((result = search_mapping_table_v6(ip6->ip6_src)) != NULL){
		reset_ttl(result);
		translate_6to4(result, buf, len);
	}else{
		result = (struct mapping *)malloc(sizeof(struct mapping));
		memset(result, 0, sizeof(struct mapping));
		
		reset_ttl(result);
		result->source_ipv6_addr = ip6->ip6_src;
		if(insert_new_mapping(result) < 0){
			return;
		}

                inet_ntop(AF_INET6, &(result->source_ipv6_addr), log_ipv6, sizeof(log_ipv6));
                inet_ntop(AF_INET, &(result->mapped_ipv4_addr), log_ipv4, sizeof(log_ipv4));
                syslog_write(LOG_INFO, "session created: %s <-> %s", log_ipv6, log_ipv4);
		
		translate_6to4(result, buf, len);
	}
}

void translate_6to4(struct mapping *st, char *buf, int len){
	struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
	struct ip ip;
        struct tun_pi pi;
        struct iovec iov[3];

	memset(&ip, 0, sizeof(struct ip));

        ip.ip_v = 4;
        ip.ip_hl = 5;
        ip.ip_len = htons(len - sizeof(struct ip6_hdr) + sizeof(struct ip));
        ip.ip_id = ip6->ip6_flow;
	ip.ip_off = htons(IP_DF);
        ip.ip_ttl = ip6->ip6_hlim;
        ip.ip_p = ip6->ip6_nxt;

        ip.ip_src = st->mapped_ipv4_addr;
	ip.ip_dst = sa46t_extract_6to4_addr(ip6->ip6_dst);

        if(ip6->ip6_nxt == IPPROTO_FRAGMENT){
                /* drop already fragmented packet */
		return;
        }

	if(ip6->ip6_nxt == IPPROTO_ICMPV6){
		ip.ip_p = IPPROTO_ICMP;
		process_icmpv6_packet(buf + sizeof(struct ip6_hdr), len - sizeof(struct ip6_hdr));
	}

	if(ip6->ip6_nxt == IPPROTO_TCP){
		process_tcp_packet(AF_INET, &ip, buf + sizeof(struct ip6_hdr), len - sizeof(struct ip6_hdr));
	}

	if(ip6->ip6_nxt == IPPROTO_UDP){
		process_udp_packet(AF_INET, &ip, buf + sizeof(struct ip6_hdr), len - sizeof(struct ip6_hdr));
	}

        ip.ip_sum = 0;
        ip.ip_sum = ip_checksum((unsigned short *)&ip, sizeof(struct ip));

        tun_set_af(&pi, AF_INET);
        iov[0].iov_base = &pi;
        iov[0].iov_len = sizeof(pi);
        iov[1].iov_base = &ip;
        iov[1].iov_len = sizeof(ip);
        iov[2].iov_base = buf + sizeof(struct ip6_hdr);
        iov[2].iov_len = len - sizeof(struct ip6_hdr);

	send_iovec(iov, 3);
}

void translate_4to6(struct mapping *st, char *buf, int len){
	struct ip *ip = (struct ip *)buf;
	struct ip6_hdr ip6;
	struct tun_pi pi;
	struct iovec iov[4];

	memset(&ip6, 0, sizeof(struct ip6_hdr));

        ip6.ip6_vfc = 0x60;
        ip6.ip6_plen = htons(len - sizeof(struct ip));
        ip6.ip6_nxt = ip->ip_p;
        ip6.ip6_hlim = ip->ip_ttl;
	ip6.ip6_src = sa46t_map_4to6_addr(sa46t_addr, plane_id, ip->ip_src);
        ip6.ip6_dst = st->source_ipv6_addr;

        if((ip->ip_off & htons(IP_MF)) > 0){
                /* drop already fragmented packet */
                return;
        }

        if(sizeof(ip6) + len - sizeof(struct ip) > MTU){
                fragment_4to6(&ip6, ip, buf + sizeof(struct ip), len - sizeof(struct ip));
                return;
        }

        if(ip->ip_p == IPPROTO_ICMP){
		ip6.ip6_nxt = IPPROTO_ICMPV6;
                process_icmp_packet(&ip6, buf + sizeof(struct ip), len - sizeof(struct ip));
        }

	if(ip->ip_p == IPPROTO_TCP){
		process_tcp_packet(AF_INET6, &ip6, buf + sizeof(struct ip), len - sizeof(struct ip));
	}

	if(ip->ip_p == IPPROTO_UDP){
		process_udp_packet(AF_INET6, &ip6, buf + sizeof(struct ip), len - sizeof(struct ip));
	}

        tun_set_af(&pi, AF_INET6);

        iov[0].iov_base = &pi;
       	iov[0].iov_len = sizeof(pi);
       	iov[1].iov_base = &ip6;
       	iov[1].iov_len = sizeof(ip6);
       	iov[2].iov_base = buf + sizeof(struct ip);
       	iov[2].iov_len = len - sizeof(struct ip);

        send_iovec(iov, 3);
}

void process_tcp_packet(int family, void *header, void *payload, int payload_size){
	struct tcphdr *tcp = (struct tcphdr *)payload;
	tcp->check = 0;

	if(family == AF_INET){
		tcp->check = ip4_transport_checksum((struct ip *)header, (unsigned short *)payload, payload_size);
	}

	if(family == AF_INET6){
		tcp->check = ip6_transport_checksum((struct ip6_hdr *)header, (unsigned short *)payload, payload_size);
	}

	return;
}

void process_udp_packet(int family, void *header, void *payload, int payload_size){
	struct udphdr *udp = (struct udphdr *)payload;
	udp->check = 0;

	if(family == AF_INET){
		udp->check = ip4_transport_checksum((struct ip *)header, (unsigned short *)payload, payload_size);
	}

	if(family == AF_INET6){
		udp->check = ip6_transport_checksum((struct ip6_hdr *)header, (unsigned short *)payload, payload_size);	
	}

	return;
}




