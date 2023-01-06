#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <conio.h>
#include <stdlib.h>
#include <pthread.h>
#include "cache.h"
#include "timer.h"
#include "thread_pool.h"
#include "dns_types.h"
#include "dns_id_map.h"
#include "dns_server.h"
#include "dns_parse.h"
#include "dns_client.h"
#include "db.h"

extern int debug_level;

void dns_server_start()
{
	db_init();
	new_cache();
	thread_pool* pool = create_thread_pool(5, 50, 500);
	dns_id_map* id_map = create_dns_id_map();
	int listen_fd = server_socket_init();
	/* 添加监听子线程 */

	server_info* info = (server_info*)malloc(sizeof(server_info));
	info->fd = listen_fd;
	info->pool = pool;
	info->id_map = id_map;
	info->shutdown = 0;
    thread_pool_add(pool, &dns_server_loop, info);

	if (debug_level >= 1) {
        printf("[server]server created.\n\n");
    }

    /* 主线程暂时阻塞，等待输入ESC结束进程 */
	while (1) {
		if (_getch() == 27) {
			break;
		}
	}

	info->shutdown = 1;
    thread_pool_destroy(pool);
	dns_server_close(listen_fd);
	dns_id_map_destroy(id_map);
	root_of_cache_cacheDestory();
    db_destroy();
	printf("[server]server terminated successfully.\n");
}

int server_socket_init()
{
	/* socket初始化 */
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) == -1) {
		perror("error");
	}
	/* 准备socket的参数 */
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.S_un.S_addr = htonl(ADDR_ANY);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(SERVER_PORT);
	memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

	int listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("[server]bind error");
		exit(1);
	}
	/* 设置为非阻塞模式 */
	u_long mode = 1;
	ioctlsocket(listen_fd, FIONBIO, &mode);
	return listen_fd;
}

void dns_server_loop(void* info)
{
	server_info* server = (server_info*)info;
	dns_id_timers* timers = (dns_id_timers*)calloc(1, sizeof(dns_id_timers));
	timers->timers = (dns_id_timer_t*)calloc(MAX_CLIENT_LEN, sizeof(dns_id_timer_t));
	pthread_mutex_init(&timers->mutex, NULL);
	char recvbuf[MAX_DNS_LEN] = {'\0'};

	while (server->shutdown != 1) {

		/* 等待某个监听的文件准备好 */
		memset(recvbuf, 0, sizeof(recvbuf));
		struct sockaddr_in client_addr;
		int addr_len = sizeof(client_addr);

		int recvlen = recvfrom(server->fd, recvbuf, MAX_DNS_LEN, 0, (struct sockaddr *)&client_addr, &addr_len);
		if (recvlen < 0) continue;

		dns_header* header = (dns_header*)malloc(sizeof(dns_header));
		raw_header_to_packet_header(recvbuf, header, 0);

		if (header->qr == DNS_RESPONSE) {
			/* 传递参数准备 */
			response_relay_info* info = (response_relay_info*)malloc(sizeof(response_relay_info));
			info->len = recvlen;
			info->buf = (char*)malloc(sizeof(char)*(recvlen+1));
			memcpy(info->buf, recvbuf, recvlen);
			info->sock = server->fd;
			info->map = server->id_map;
			info->timers = timers;

			/* 中继响应DNS包 */
			thread_pool_add(server->pool, response_relay, info);
		} else if (header->qr == DNS_QUERY) {
			/* 传递参数准备 */
			query_process_info* info = (query_process_info*)malloc(sizeof(query_process_info));
			info->addr = client_addr;
			info->len = recvlen;
			info->buf = (char*)malloc(sizeof(char)*(recvlen + 1));
			memcpy(info->buf, recvbuf, recvlen);
			info->sock = server->fd;
			info->pool = server->pool;
			info->timers = timers;
			info->map = server->id_map;

			/* 处理询问DNS包 */
			thread_pool_add(server->pool, query_process, info);
		}
		free(header);
		header = NULL;
	}
	pthread_mutex_lock(&timers->mutex);
	for (int i = 0; i < MAX_CLIENT_LEN; ++i) {
		if (timers->timers[i].timer != NULL) {
			stop_timer(timers->timers[i].timer);
			timers->timers[i].timer = NULL;
			timers->timers[i].dns_id = 0;
		}
	}
	pthread_mutex_unlock(&timers->mutex);
	pthread_mutex_destroy(&timers->mutex);
	free(timers->timers);
	free(timers);
	timers = NULL;
}

void dns_server_close(int server_fd)
{
	if (closesocket(server_fd) != 0) {
		perror("[server]close file descriptor error\n");
		exit(1);
	}
    WSACleanup();
	printf("[server]socket close successfully\n");
}