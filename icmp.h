void process_icmpv6_packet(char *buf, int len);
void process_icmp_packet(struct ip6_hdr *header, char *buf, int len);
void translate_icmpv6_unreach(char *buf);
void translate_icmp_unreach(char *buf);
