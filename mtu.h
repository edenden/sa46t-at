struct too_big {
	struct icmp	icmp;
	char 		data[64];
};

void fragment_4to6(struct ip6_hdr *ip6, struct ip *ip, char *payload, int payload_size);
void send_packet_too_big(struct ip *received);
