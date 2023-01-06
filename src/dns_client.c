#include <winsock2.h>
#include <ws2tcpip.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "thread_pool.h"
#include "timer.h"
#include "cache.h"
#include "dns_types.h"
#include "db.h"
#include "dns_client.h"
#include "dns_parse.h"

extern char remote_dns[512];
extern int debug_level;
/*
	具体处理每一个请求包，如果在本地查找到对应的请求，则直接返回，否则转发给远程DNS服务器，等待进一步的处理。
*/

void query_process(void* arg)
{
	query_process_info* info = (query_process_info*)arg;
    dns_packet* packet = create_dns_packet();
    dns_raw_to_dns_packet(info->buf, packet, info->len);
    if (debug_level >= 1) {
        printf("[query] received a packet id = 0x%04x\n", ntohs(packet->header.id));
    }
    if (debug_level == 2) {
        printf("[query] detailed query packet info id = 0x%04x\n", ntohs(packet->header.id));
        print_dns_packet(stdout, packet);
    }
	char sendbuf[MAX_DNS_LEN] = { '\0' };
    unsigned int ip_address;
	int send_len = 0;

    if (packet->header.qd_cnt == 1 && dns_lookup(packet->queries->next, &ip_address)) {
		/* 服务器功能，仅对A类UDP的单DNS请求进行处理 */
        if (debug_level >= 1) {
            printf("[client]id 0x%04x query found in db.\n", ntohs(packet->header.id));
        }
        send_len = get_dns_response(packet, sendbuf, ip_address);
		if (debug_level >= 1) {
			printf("[response]ready to send response packet id = 0x%04x\n\n", ntohs(*(uint16_t*)sendbuf));
		}
		if (debug_level == 2) {
			dns_packet* response_packet = create_dns_packet();
			dns_raw_to_dns_packet(sendbuf, response_packet, send_len);
			print_dns_packet(stdout, response_packet);
			destroy_dns_packet(response_packet);
		}
		/* 将答案直接返回给对方程序 */
		int re_cnt = 0;
		while (re_cnt <= 3 && sendto(info->sock, sendbuf, send_len, 0, (struct sockaddr*)&(info->addr), sizeof(info->addr)) == -1) {
			if (debug_level >= 1) {
				fprintf(stderr, "[client]id 0x%04x response send error\n\n", ntohs(packet->header.id));
			}
			Sleep(100);
			re_cnt++;
		}
		if (info->buf != NULL) free(info->buf);
		info->buf = NULL;
    } else {
		/* 中继处理，无法本地处理则转交远程DNS服务器 */
		/* DNS ID映射处理 */
		uint16_t sid = insert_dns_id(packet->header.id, info->addr, info->map);
		*(uint16_t*)info->buf = sid;

		if (debug_level >= 1) {
			printf("[dns id map]id %04x -> %04x\n", ntohs(packet->header.id), ntohs(sid));
		}
        if (debug_level >= 1) {
            printf("[query]id 0x%04x query have to send to remote dns.\n", ntohs(sid));
        }
		/* 参数准备 */
		send_remote_info* send_info = (send_remote_info*)malloc(sizeof(send_remote_info));
		send_info->buf = info->buf;
		send_info->len = info->len;
		send_info->pool = info->pool;
		send_info->is_callback = 0;
		send_info->timers = info->timers;
		send_info->sock = info->sock;
		send_info->map = info->map;
		/* 新线程处理发送+定时机制 */
		thread_pool_add(info->pool, &send_remote_dns, send_info);
	}
	destroy_dns_packet(packet);
}

/*
	根据请求包和查找到的IP地址，产生对应的回应dns包
*/

int get_dns_response(dns_packet* query_packet, char* sendbuf, unsigned int ip)
{
    dns_packet* response_packet = create_dns_packet();
	response_packet->header.id = query_packet->header.id;
    /* 对DNS问题部分进行复制 */
	response_packet->header.qd_cnt = query_packet->header.qd_cnt;
    raw_query_to_packet_query(query_packet->raw_data, DNS_HEADERS_LEN, response_packet->queries, response_packet->header.qd_cnt);
	/* 标志设置 */
    response_packet->header.qr = DNS_RESPONSE;
    response_packet->header.ra = 1;
    response_packet->header.rd = 1;

    if (ip == 0) {
		/* 过滤地址 */
        response_packet->header.an_cnt = 0; /* 回答数为0 */
        response_packet->header.rcode = 3; /* 根据标准，response code = 3 为查询出错 */
    } else {
        response_packet->header.an_cnt = 1;
        response_packet->header.rcode = 0;

        dns_rr* answer = (dns_rr*)malloc(sizeof(dns_rr));
        answer->next = 0;
        answer->rrtype = DNS_TYPE_A;
        answer->rrclass = 1;
        answer->ttl = 120; /* 2 min */
		answer->name.labels = NULL;
		answer->name.label_len = NULL;
		dns_name_cpy(&(answer->name), &(query_packet->queries->qname));
        answer->len = 4;
        answer->data = (uint8_t*)malloc(answer->len*sizeof(uint8_t));
        memcpy(answer->data, &ip, answer->len);
        response_packet->answers->next = answer;
    }
    int len = dns_packet_to_dns_raw(response_packet, sendbuf);
    destroy_dns_packet(response_packet);
    return len;
}
/*
	向远程服务器发送请求
*/
void send_remote_dns(void* arg)
{
	send_remote_info* info = (send_remote_info*)arg;
    
    /* 远程服务器信息 */
    struct sockaddr_in dns_addr;
    dns_addr.sin_port = htons(53);
    dns_addr.sin_family = AF_INET;
    memset(dns_addr.sin_zero, 0, sizeof(dns_addr.sin_zero));
    inet_pton(AF_INET, remote_dns, &(dns_addr.sin_addr));
	int max_cnt = 0;
    while (max_cnt <= 5&&sendto(info->sock, info->buf, info->len, 0, (struct sockaddr *)&dns_addr, sizeof(dns_addr)) == -1)
    {
		Sleep(300);
		++max_cnt;
    }
	if (max_cnt > 3) {
		printf("[query]send busy, id 0x%04x send error\n", *(uint16_t*)(info->buf));
	}
	/* 区分是否是重传回调，若不是重传回调则启动计时器 */
	if (info->is_callback == 0) {
		info->is_callback = 1;
		timer_t* timer = create_timer(500, 1, &send_remote_dns, info, &cleanup_send_remote_info);
		pthread_mutex_lock(&info->timers->mutex);
		for (int i = 0; i < MAX_CLIENT_LEN; ++i) {
			if (info->timers->timers[i].timer == NULL) {
				info->timers->timers[i].dns_id = *(uint16_t*)info->buf;
				info->timers->timers[i].timer = timer;
				break;
			}
		}
		pthread_mutex_unlock(&info->timers->mutex);
		start_timer(timer);
	} else {
		if (debug_level >= 1) {
			printf("[query]id %04x resend to remote.\n", ntohs(*(uint16_t*)(info->buf)));
		}
	}
}

/* 定时结束后处理函数 */
void cleanup_send_remote_info(void* arg)
{
	send_remote_info* info = (send_remote_info*)arg;
	/* 回收对应ID资源 */
	int ret = delete_id(*(uint16_t*)info->buf, info->map);
	if (debug_level >= 1) {
		printf("[client]id %04x timer stop.\n", ntohs(*(uint16_t*)(info->buf)));
	}
	if (info->buf != NULL) free(info->buf);
	info->buf = NULL;
}

/*
	对DNS请求进行查找，首先在cache中进行查找，如果未命中则在数据库中查找
	成功查找返回1，失败返回0
*/
int dns_lookup(dns_query* query, int* ip) {
	char domain_name[MAX_DNS_LEN] = { '\0' };
	int len = dns_labels_to_domain_name(query->qname, domain_name);
	int result;
	result = cache_lookup(domain_name);
	/* cache未命中，则在进行数据库中查找 */
	if (result == -1) {
		result = db_lookup(domain_name);
	}
	if (result == -1) {
		return 0;
	}
	/* 待拦截请求，则无论类型一律重传 */
	if (result == 0) {
		*ip = result;
		return 1;
	}
	/* 非A类请求交由远程处理 */
	if (query->qtype == DNS_TYPE_A) {
		*ip = result;
		return 1;
	} else return 0;
}
/*
	将从远程服务器收到的DNS请求中继给客户端，同时将对应的映射加入cache
*/
void response_relay(void* arg)
{
	response_relay_info* info = (response_relay_info*)arg;
	uint16_t sid = *(uint16_t*)info->buf;
	/* 进行ID映射 */
	uint16_t cid;
	if (get_client_info(sid, &cid, &info->addr, info->map) != -1) {
		if (debug_level >= 1) {
			printf("[response]get response packet id %04x(client id %04x)\n", (unsigned)ntohs(sid), (unsigned)ntohs(cid));
		}
		*(uint16_t*)info->buf = cid;
		/* 停止重传计时 */
		pthread_mutex_lock(&info->timers->mutex);
		for (int i = 0; i < MAX_CLIENT_LEN; ++i) {
			if (info->timers->timers[i].dns_id == sid && info->timers->timers[i].timer != NULL) {
				stop_timer(info->timers->timers[i].timer);
				info->timers->timers[i].timer = NULL;
				info->timers->timers[i].dns_id = 0;
				break;
			}
		}
		pthread_mutex_unlock(&info->timers->mutex);

		/* 此时ID映射表中已完成一个任务，删除对应表项，回收ID资源 */
		delete_id(sid, info->map);

		/* 将回应请求加入cache中 */
		dns_packet* packet = create_dns_packet();
		dns_raw_to_dns_packet(info->buf, packet, info->len);
		dns_rr* answer = packet->answers->next;
		if (answer != NULL) {
			char domain_name[MAX_DNS_LEN] = { '\0' };
			char ip[50] = { '\0' };
			int dnlen = dns_labels_to_domain_name(packet->queries->next->qname, domain_name);
			while (answer->next != NULL) answer = answer->next;
			/* 仅存A类地址 */
			if (answer->rrtype == DNS_TYPE_A) {
				inet_ntop(AF_INET, answer->data, ip, 50);
				//cache_insert(domain_name,dnlen,ip,strlen(ip)+1);
				if (debug_level == 2) {
					printf("[client]get map:%s -> %s\n", domain_name, ip);
				}
			}
		}
		destroy_dns_packet(packet);

		if (debug_level == 2) {
			dns_packet* response_packet = create_dns_packet();
			dns_raw_to_dns_packet(info->buf, response_packet, info->len);
			print_dns_packet(stdout, response_packet);
			destroy_dns_packet(response_packet);
		}
		/* 中继响应 */
		int re_cnt = 0; /* 防止糟糕的网络情况下的反复重传 */
		while (re_cnt <= 5 && (sendto(info->sock, info->buf, info->len, 0, (struct sockaddr *)&info->addr, sizeof(info->addr)) == -1))
		{
			Sleep(300);
			re_cnt++;
		}
		if (re_cnt > 5 && debug_level >= 1) printf("[response]id %04x relay send error!\n", *(uint16_t*)info->buf);
	}
	else {
		if (debug_level >= 1) printf("[response]id %04x already send relay\n", *(uint16_t*)info->buf);
	}
	if (info->buf != NULL) free(info->buf);
	info->buf = NULL;
}