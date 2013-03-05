void process_ipv4_packet(char *buf, int len);
void process_ipv6_packet (char *buf, int len);
void translate_6to4(struct mapping *st, char *buf, int len);
void translate_4to6(struct mapping *st, char *buf, int len);
void process_tcp_packet(int family, void *header, void *payload, int payload_size);
void process_udp_packet(int family, void *header, void *payload, int payload_size);
