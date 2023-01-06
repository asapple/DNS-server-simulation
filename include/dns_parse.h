#ifndef DNS_PARSE_H
#define DNS_PARSE_H
#include <stdio.h>

#include "dns_types.h"

/* 创建一个DNS解析报文数据包 */
dns_packet* create_dns_packet();

/* 将DNS报文数据转化为解析后的DNS结构 */
void dns_raw_to_dns_packet(char* raw, dns_packet* packet, int size);

int raw_header_to_packet_header(char* raw, dns_header* header, int offset); 
int raw_name_to_packet_name(char* raw, dns_name* name, int offset);
int raw_query_to_packet_query(char* raw, int offset, dns_query* queries, int cnt);
int raw_rr_to_packet_rr(char* raw, int offset, dns_rr* rr, int cnt);

//将DNS结构转化为DNS报文数据
int dns_packet_to_dns_raw(dns_packet* packet, char* raw);
int packet_rr_to_raw_rr(dns_rr* rr, char* raw, int offset);
int packet_query_to_raw_query(dns_query* queries, char* raw, int offset);
int packet_header_to_raw_header(dns_header header, char* raw, int offset);

/* DNS 名字处理 */
void dns_name_cpy(dns_name* des, dns_name* src);
int dns_labels_to_domain_name(dns_name name, char* domain_name);

/* 销毁dns_packet */
void destroy_dns_packet(dns_packet* packet);
void destroy_dns_rr(dns_rr* rr);
void destroy_dns_name(dns_name* name);
void destroy_dns_query(dns_query* query);

/* 输出dns信息 */
#define MAX_DNS_INFO_SIZE 8000
void print_dns_packet(FILE* file, dns_packet* packet);
int print_dns_header(char* buf, int offset, dns_header header);
int print_dns_query(char* buf, int offset, dns_query* queries);
int print_dns_answer(char* buf, int offset, dns_rr* answers);

#endif