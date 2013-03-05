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
#include <pthread.h>
#include <syslog.h>

#include "main.h"
#include "session.h"

uint32_t create_table_key(int family, void *address){
	struct in_addr *ip = (struct in_addr *)address;
	struct in6_addr *ip6 = (struct in6_addr *)address;
	int sum = 0;

	if(family == AF_INET){
		sum = ip->s_addr;
	}else if(family == AF_INET6){
		int i;
		for(i = 0; i < 4; i++){
			sum += ip6->s6_addr32[i];
		}
	}

	return sum % pool_num;
}

struct mapping *init_mapping_table(struct in_addr network_addr, int prefix){
	int i;
	uint32_t mask = 0;
	struct in_addr broadcast_addr;

	/* add network address entry */
	struct mapping *ptr = (struct mapping *)malloc(sizeof(struct mapping));
	memset(ptr, 0, sizeof(struct mapping));
	ptr->mapped_ipv4_addr = network_addr;
	ptr->permanent_flag = 1;

	/* add broadcast address entry */
	ptr->next = (struct mapping *)malloc(sizeof(struct mapping));
	memset(ptr->next, 0, sizeof(struct mapping));

	for(i = 0; i < 32 - prefix; i++){
		mask = mask << 1;
		mask++;
	}

	broadcast_addr.s_addr = htonl(mask) | network_addr.s_addr;
	ptr->next->mapped_ipv4_addr = broadcast_addr;
	ptr->next->permanent_flag = 1;

	pool_num = ntohl(broadcast_addr.s_addr) - ntohl(network_addr.s_addr);
	if(pool_num > MAX_SESSION){
		pool_num = MAX_SESSION;
	}

	v4table = (struct mapping **)malloc(sizeof(struct mapping *) * pool_num);
	memset(v4table, 0, sizeof(struct mapping *) * pool_num);
	v6table = (struct mapping **)malloc(sizeof(struct mapping *) * pool_num);
	memset(v6table, 0, sizeof(struct mapping *) * pool_num);

	return ptr;
}

int add_mapping_to_hash(struct mapping *result){
	/* this method called where mapping table is locked */
	uint32_t v4key = create_table_key(AF_INET, &(result->mapped_ipv4_addr));
	uint32_t v6key = create_table_key(AF_INET6, &(result->source_ipv6_addr));
	int count;

	count = 0;
	while(v4table[v4key] != NULL){
		v4key++;
                if(v4key == pool_num){
                        v4key = 0;
                }

		count++;
		if(count == pool_num){
			return -1;
		}
	}

	v4table[v4key] = result;

	count = 0;
	while(v6table[v6key] != NULL){
		v6key++;
                if(v6key == pool_num){
                        v6key = 0;
                }

		count++;
		if(count == pool_num){
			return -1;
		}
	}

	v6table[v6key] = result;

	return 0;
}

void delete_mapping_from_hash(struct mapping *result){
	/* this method called where mapping table is locked */
        uint32_t v4key = create_table_key(AF_INET, &(result->mapped_ipv4_addr));
        uint32_t v6key = create_table_key(AF_INET6, &(result->source_ipv6_addr));

	while(1){
		if(v4table[v4key] != NULL){
			if(!memcmp(&(v4table[v4key]->mapped_ipv4_addr), &(result->mapped_ipv4_addr), 4)){
				break;
			}
		}

                v4key++;
		if(v4key == pool_num){
			v4key = 0;
		}
        }

        v4table[v4key] = NULL;

        while(1){
                if(v6table[v6key] != NULL){
                        if(!memcmp(&(v6table[v6key]->source_ipv6_addr), &(result->source_ipv6_addr), 16)){
                                break;
                        }       
		}

                v6key++;
                if(v6key == pool_num){
                        v6key = 0;
                }
        }

        v6table[v6key] = NULL;

        return;
}

struct mapping *search_mapping_table_v6(struct in6_addr ipv6_addr){
	uint32_t key = create_table_key(AF_INET6, &ipv6_addr);
	int count = 0;

        /* lock session table */
        if(pthread_mutex_lock(&mutex_session_table) != 0){
                err(EXIT_FAILURE, "failed to lock session table");
        }

	while(++count <= pool_num){
		if(v6table[key] != NULL){
			if(!memcmp(&(v6table[key]->source_ipv6_addr), &ipv6_addr, 16)){
        			/* unlock session table */
        			if(pthread_mutex_unlock(&mutex_session_table) != 0){
        			        err(EXIT_FAILURE, "failed to unlock session table");
        			}
				return v6table[key];
			}
		}

		key++;
                if(key == pool_num){
                        key = 0;
                }
	}

        /* unlock session table */
        if(pthread_mutex_unlock(&mutex_session_table) != 0){
                err(EXIT_FAILURE, "failed to unlock session table");
        }

	return NULL;

}

struct mapping *search_mapping_table_v4(struct in_addr ipv4_addr){
        uint32_t key = create_table_key(AF_INET, &ipv4_addr);
        int count = 0;

        /* lock session table */
        if(pthread_mutex_lock(&mutex_session_table) != 0){
                err(EXIT_FAILURE, "failed to lock session table");
        }

        while(++count <= pool_num){
		if(v4table[key] != NULL){
                	if(!memcmp(&(v4table[key]->mapped_ipv4_addr), &ipv4_addr, 4)){
        			/* unlock session table */
        			if(pthread_mutex_unlock(&mutex_session_table) != 0){
        			        err(EXIT_FAILURE, "failed to unlock session table");
        			}
                        	return v4table[key];
                	}
		}

		key++;
                if(key == pool_num){
                        key = 0;
                }
        }

        /* unlock session table */
        if(pthread_mutex_unlock(&mutex_session_table) != 0){
                err(EXIT_FAILURE, "failed to unlock session table");
        }

        return NULL;

}

int insert_new_mapping(struct mapping *result){
	struct mapping *ptr = (struct mapping *)mapping_table;
	int succeed_in_assign = 0;

	/* lock session table */
	if(pthread_mutex_lock(&mutex_session_table) != 0){
        	err(EXIT_FAILURE, "failed to lock session table");
        }

	while(ptr->next != NULL){
                uint32_t v4addr = *(uint32_t *)&(ptr->mapped_ipv4_addr);
                v4addr = htonl(ntohl(v4addr) + 1);

                if(v4addr != *(uint32_t *)&(ptr->next->mapped_ipv4_addr)){
                        result->mapped_ipv4_addr = *(struct in_addr *)&v4addr;
			succeed_in_assign = 1;
			break;
                }

		ptr = ptr->next;
	}

	if(succeed_in_assign == 1){
		if(add_mapping_to_hash(result) < 0){
			/* session over flow */
			free(result);

                	/* unlock session table */
                	if(pthread_mutex_unlock(&mutex_session_table) != 0){
                        	err(EXIT_FAILURE, "failed to unlock session table");
                	}
			return -1;
		}

		result->next = ptr->next;
		ptr->next = result;

	        /* unlock session table */
	        if(pthread_mutex_unlock(&mutex_session_table) != 0){
       		         err(EXIT_FAILURE, "failed to unlock session table");
	        }
		return 0;
	}else{
		free(result);
	        /* unlock session table */
	        if(pthread_mutex_unlock(&mutex_session_table) != 0){
	                err(EXIT_FAILURE, "failed to unlock session table");
        	}
		return -1;
	}

}

void *reset_ttl(struct mapping *target){
	/* lock session table */
        if(pthread_mutex_lock(&mutex_session_table) != 0){
                err(EXIT_FAILURE, "failed to lock session table");
        }

	target->ttl = TTL_MAX;

        /* unlock session table */
        if(pthread_mutex_unlock(&mutex_session_table) != 0){
                err(EXIT_FAILURE, "failed to unlock session table");
        }
}

void *count_down_ttl(void *arg){
	struct mapping *ptr;
	struct mapping *prev;
	struct mapping *tmp;
	char log_ipv4[256];
	char log_ipv6[256];

	while(1){
		ptr = (struct mapping *)mapping_table;

		/* lock session table */
		if(pthread_mutex_lock(&mutex_session_table) != 0){
        		err(EXIT_FAILURE, "failed to lock session table");
        	}

		while(ptr != NULL){
			if(ptr->permanent_flag == 1){
				prev = ptr;
				ptr = ptr->next;
				continue;
			}

			ptr->ttl--;
			if(ptr->ttl == 0){
				tmp = ptr;
				prev->next = ptr->next;
				ptr = ptr->next;
				delete_mapping_from_hash(tmp);
				inet_ntop(AF_INET6, &(tmp->source_ipv6_addr), log_ipv6, sizeof(log_ipv6));
				inet_ntop(AF_INET, &(tmp->mapped_ipv4_addr), log_ipv4, sizeof(log_ipv4));
				syslog_write(LOG_INFO, "session deleted: %s <-> %s", log_ipv6, log_ipv4);
				free(tmp);
				continue;
			}

			prev = ptr;
			ptr = ptr->next;
		}

        	/* unlock session table */
        	if(pthread_mutex_unlock(&mutex_session_table) != 0){
                	err(EXIT_FAILURE, "failed to unlock session table");
        	}

		sleep(60);
	}
}






















