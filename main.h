#define TTL_MAX 3
#define MTU 1500
#define MIN_MTU 1280
#define MAX_SESSION 1000
#define DEV_NAME "sa46t-at"
#define PROCESS_NAME "sa46t-at"
#define SYSLOG_FACILITY LOG_DAEMON

void cleanup_sigint (int sig);
int tun_alloc (char * dev);
int tun_up (char * dev);
int tun_set_af(void *buf, uint32_t af);
void send_iovec(struct iovec *iov, int item_num);
void syslog_write(int level, char *fmt, ...);
void syslog_open();
void syslog_close();

extern struct mapping **v4table;
extern struct mapping **v6table;
extern struct mapping *mapping_table;
extern int tun_fd;
extern int raw_fd;
extern struct in_addr network_addr;
extern struct in6_addr sa46t_addr;
extern uint32_t plane_id;
extern int prefix;
extern uint32_t pool_num;
extern pthread_mutex_t mutex_session_table;
extern char *optarg;
