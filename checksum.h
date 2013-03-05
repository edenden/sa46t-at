struct pseudo_ipv6_header{
        struct in6_addr src_address,
                        dst_address;
        u_int32_t       upper_layer_size;
        u_int8_t        ip6_p_pad[3];
        u_int8_t        ip6_p_nxt;
};

struct pseudo_ipv4_header{
	struct in_addr	src_address,
			dst_address;
	uint8_t		ip_p_pad;
	uint8_t		ip_p_nxt;
	uint16_t	ip_p_len;
};
