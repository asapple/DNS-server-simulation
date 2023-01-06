#ifndef DNS_CLIENT_H
#define DNS_CLIENT_H

#include <winsock2.h>
#include <pthread.h>
#include "dns_types.h"
#include "dns_server.h"

typedef struct {
    char* buf; /* 询问DNS报文缓冲区 */
    int len;  /* 询问DNS报文长度 */
    struct sockaddr_in addr; /* 发送端地址信息 */
    int sock; /* 本程序绑定的套接字 */
	thread_pool* pool; /* 线程池 */
	dns_id_timers* timers; /* 记录DNS ID和对应计时器的数组 */
	dns_id_map* map; /* ID映射表 */
} query_process_info;

typedef struct {
	char* buf; /* 回应DNS报文缓冲区 */
	int len; /* 回应DNS报文长度 */
	struct sockaddr_in addr; /* 中转目的地DNS地址信息 */
	int sock; /* 本程序绑定的套接字 */
	dns_id_timers* timers; /* 记录DNS ID和对应计时器的数组 */
	dns_id_map* map; /* ID映射表 */
} response_relay_info;

typedef struct {
	char* buf; /* 询问DNS报文缓冲区 */
	int len; /* 询问DNS报文长度 */
	int sock; /* 本程序绑定的套接字 */
	thread_pool* pool; /* 线程池 */
	int is_callback; /* 是否是回调函数 */
	dns_id_timers* timers; /* 记录DNS ID和对应计时器的数组 */
	dns_id_map* map;
} send_remote_info;

/* 对询问报文处理的工作函数 */
void query_process(void* arg);
/* 转交给远端DNS服务器的工作函数 */
void send_remote_dns(void* arg);
/* 与重传计时器函数配合，提供正确释放参数内部内存的方法 */
void cleanup_send_remote_info(void* arg);
/* 对DNS报文响应进行中转 */
void response_relay(void* arg);

/* 查询本地DNS信息 */
int dns_lookup(dns_query* query, int* ip);
/* 根据返回的ip地址映射获取响应DNS报文的函数 */
int get_dns_response(dns_packet* query_packet, char* sendbuf, unsigned int ip);

#endif