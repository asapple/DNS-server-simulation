#ifndef DNS_CLIENT_H
#define DNS_CLIENT_H

#include <winsock2.h>
#include <pthread.h>
#include "dns_types.h"
#include "dns_server.h"

typedef struct {
    char* buf; /* ѯ��DNS���Ļ����� */
    int len;  /* ѯ��DNS���ĳ��� */
    struct sockaddr_in addr; /* ���Ͷ˵�ַ��Ϣ */
    int sock; /* ������󶨵��׽��� */
	thread_pool* pool; /* �̳߳� */
	dns_id_timers* timers; /* ��¼DNS ID�Ͷ�Ӧ��ʱ�������� */
	dns_id_map* map; /* IDӳ��� */
} query_process_info;

typedef struct {
	char* buf; /* ��ӦDNS���Ļ����� */
	int len; /* ��ӦDNS���ĳ��� */
	struct sockaddr_in addr; /* ��תĿ�ĵ�DNS��ַ��Ϣ */
	int sock; /* ������󶨵��׽��� */
	dns_id_timers* timers; /* ��¼DNS ID�Ͷ�Ӧ��ʱ�������� */
	dns_id_map* map; /* IDӳ��� */
} response_relay_info;

typedef struct {
	char* buf; /* ѯ��DNS���Ļ����� */
	int len; /* ѯ��DNS���ĳ��� */
	int sock; /* ������󶨵��׽��� */
	thread_pool* pool; /* �̳߳� */
	int is_callback; /* �Ƿ��ǻص����� */
	dns_id_timers* timers; /* ��¼DNS ID�Ͷ�Ӧ��ʱ�������� */
	dns_id_map* map;
} send_remote_info;

/* ��ѯ�ʱ��Ĵ���Ĺ������� */
void query_process(void* arg);
/* ת����Զ��DNS�������Ĺ������� */
void send_remote_dns(void* arg);
/* ���ش���ʱ��������ϣ��ṩ��ȷ�ͷŲ����ڲ��ڴ�ķ��� */
void cleanup_send_remote_info(void* arg);
/* ��DNS������Ӧ������ת */
void response_relay(void* arg);

/* ��ѯ����DNS��Ϣ */
int dns_lookup(dns_query* query, int* ip);
/* ���ݷ��ص�ip��ַӳ���ȡ��ӦDNS���ĵĺ��� */
int get_dns_response(dns_packet* query_packet, char* sendbuf, unsigned int ip);

#endif