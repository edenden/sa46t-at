struct mapping {
	struct in_addr	mapped_ipv4_addr;
	struct in6_addr	source_ipv6_addr;
	uint32_t	ttl;
	struct mapping 	*next;
	int		permanent_flag;
};

struct mapping *init_mapping_table(struct in_addr, int prefix);
struct mapping *search_mapping_table_v6(struct in6_addr);
struct mapping *search_mapping_table_v4(struct in_addr);
int insert_new_mapping(struct mapping *result);
void *reset_ttl(struct mapping *target);
void *count_down_ttl(void *arg);
