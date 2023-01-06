#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include "thread_pool.h"
#include "dns_id_map.h"
#include "timer.h"

#define SERVER_PORT 53 //服务器端口
#define BUF_LEN 1024 //缓冲区最大长度
#define MAX_CLIENT_LEN 4096 //最大并发数

typedef struct {
    int fd;
    thread_pool* pool;
	dns_id_map* id_map;

	int shutdown;
} server_info;

/* 每个发往远程服务器的dns_id对应一个重传计时器，通过这个结构体来找到对应的计时器 */
typedef struct {
	uint16_t dns_id;
	timer_t* timer;
} dns_id_timer_t;

typedef struct {
	dns_id_timer_t* timers;
	pthread_mutex_t mutex;
} dns_id_timers;

void dns_server_start();
void dns_server_loop(void*);
void dns_server_close(int server_fd);
int server_socket_init();

#endif