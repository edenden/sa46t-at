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
#include <linux/if_tun.h>
#include <sys/socket.h>
#include <net/if.h>
#include <pthread.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <signal.h>
#include <syslog.h>
#include <stdarg.h>

#include "main.h"
#include "session.h"
#include "translate.h"

uint32_t pool_num;
struct in_addr network_addr;
struct in6_addr sa46t_addr;
int prefix = 0;
uint32_t plane_id = 0x0000;

struct mapping **v4table;
struct mapping **v6table;
struct mapping *mapping_table;

int tun_fd;
int raw_fd;
pthread_t thread_id_ttl;
pthread_mutex_t mutex_session_table = PTHREAD_MUTEX_INITIALIZER;
int syslog_facility = SYSLOG_FACILITY;
char *optarg;

void clean_up(int signal){
        close(tun_fd);
	close(raw_fd);
        exit (0);
}

void usage(){
	printf("\n");
	printf(" Usage:\n");
	printf("\tsa46t -6 [SA46T ADDRESS] -4 [IPv4 POOL / PREFIX]\n");
	printf("\n");
	printf(" Option:\n");
	printf("\t-6 : SA46T address\n");
	printf("\t-4 : IPv4 pool address / prefix\n");
	printf("\t-p : SA46T plane ID(HEX)\n");
	printf("\t-d : Debug mode\n");
	printf("\t-h : Show this help\n");
	printf("\n");
	return;
}

int main(int argc, char *argv[]){
        char buf[2048];
        struct tun_pi *pi = (struct tun_pi *)buf;
	int read_len;
	char tun_name[] = DEV_NAME;
	int ether_type;
	int ch;
	int debug_mode = 0;
	char ipv4_pool_arg[255];
	int ipv6_configured = 0;
	int ipv4_configured = 0;

	while ((ch = getopt(argc, argv, "dh6:4:p:")) != -1) {
		switch (ch) {
			case 'd' :
				debug_mode = 1;
				break;

			case '6' :
				if (inet_pton(AF_INET6, optarg, &sa46t_addr) < 1){
					printf ("Invalid IPv6 prefix\n");
					return -1;
				}

				ipv6_configured = 1;

				break;

			case '4' :
				strcpy(ipv4_pool_arg, strtok(optarg, "/"));
                                prefix = atoi(strtok(NULL, ""));

				if(prefix < 8){
					printf("IPv4 prefix is too short\n");
					return -1;
				}else if(prefix > 30){
					printf("IPv4 prefix is too long\n");
					return -1;
				}

				if(inet_pton(AF_INET, ipv4_pool_arg, &network_addr) < 1){
					printf("Invalid IPv4 prefix\n");
					return -1;
				}

				ipv4_configured = 1;

				break;

			case 'p' : 
				if(sscanf(optarg, "%x", &plane_id) < 1){
					printf ("Invalid plane ID\n");
					return -1;
				}

				break;

			case 'h' :
				usage();
				return 0;

			default :
				usage();
				return -1;
		}
	}

	if((ipv4_configured & ipv6_configured) == 0){
		usage();
		return -1;
	}

	mapping_table = init_mapping_table(network_addr, prefix);

        if ((tun_fd = tun_alloc (tun_name)) < 0){
		err(EXIT_FAILURE, "failt to tun_alloc");
	}

        if (tun_up (tun_name) < 0){
		err(EXIT_FAILURE, "failt to tun_up");
	}

        if((raw_fd = create_raw_socket()) < 0){
                err(EXIT_FAILURE, "fail to create raw socket");
        }

        if (signal (SIGINT, clean_up)  == SIG_ERR){
                err(EXIT_FAILURE, "failt to register SIGINT");
	}

        if(!debug_mode){
                if(daemon(0, 1) != 0){
                        err(EXIT_FAILURE, "fail to run as a daemon\n");
                }
        }

	/* start session ttl service */
        if (pthread_create(&thread_id_ttl, NULL, count_down_ttl, NULL) != 0 ){
                exit(1);
        }

        while ((read_len = read(tun_fd, buf, sizeof(buf))) >= 0){
                ether_type = ntohs(pi->proto);

                switch (ether_type) {
                	case ETH_P_IP :
                       		process_ipv4_packet(buf + sizeof(struct tun_pi), read_len - sizeof(struct tun_pi));
                       		break;
                	case ETH_P_IPV6 :
                       		process_ipv6_packet(buf + sizeof(struct tun_pi), read_len - sizeof(struct tun_pi));
                        	break;
                	default :
                        	break;
                }
        }

}

int create_raw_socket(){
        int fd;

        /* create Raw Socket */
        if((fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
                perror("rawsocket");
                return -1;
        }

        return fd;
}

int tun_alloc (char * dev){
	int fd;
	struct ifreq ifr;

	if ((fd = open ("/dev/net/tun", O_RDWR)) < 0)
		err (EXIT_FAILURE, 
		     "cannot create a control cahnnel of the tun intface.");

	memset (&ifr, 0, sizeof (ifr));
	ifr.ifr_flags = IFF_TUN;
	strncpy (ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl (fd, TUNSETIFF, (void *) &ifr) < 0) {
		close (fd);
		err (EXIT_FAILURE, 
		     "cannot create %s interface.", dev);
	}

	return fd;

}

int tun_up (char * dev){
	int udp_fd;
	struct ifreq ifr;

	/* Make Tunnel interface up state */

	if ((udp_fd = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
		err (EXIT_FAILURE,
		     "failt to create control socket of tun interface.");

	memset (&ifr, 0, sizeof (ifr));
	ifr.ifr_flags = IFF_UP;
	strncpy (ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl (udp_fd, SIOCSIFFLAGS, (void *)&ifr) < 0) {
		err (EXIT_FAILURE,
		     "failed to make %s up.", dev);
		close (udp_fd);
		return -1;
	}

	close (udp_fd);

	return 0;
}

int tun_set_af(void *buf, uint32_t af){
	assert(buf != NULL);

	uint16_t ether_type;

	switch(af) {
	case AF_INET:
		ether_type = ETH_P_IP;
		break;
	case AF_INET6:
		ether_type = ETH_P_IPV6;
		break;
	default:
		warnx("unsupported address family %d", af);
		return (-1);
	}

	struct tun_pi *pi = buf;
	pi->flags = 0;
	pi->proto = htons(ether_type);

	return (0);

	uint32_t *af_space = buf;

	*af_space = htonl(af);

	return (0);
}

void send_iovec(struct iovec *iov, int item_num){
	if(writev(tun_fd, iov, item_num) < 0){
		warn("writev failed");
	}
}

void send_raw(void *buf, int size, struct sockaddr *dst){
	if(sendto(raw_fd, buf, size, 0, dst, sizeof(struct sockaddr_in)) < 0){
		warn("sendto failed");
	}
}

void syslog_write(int level, char *fmt, ...){
        va_list args;
        va_start(args, fmt);

        syslog_open();
        vsyslog(level, fmt, args);
        syslog_close();

        va_end(args);
}

void syslog_open(){
    openlog(PROCESS_NAME, LOG_CONS | LOG_PID, syslog_facility);
}

void syslog_close(){
    closelog();
}
