#ifndef DNS_TYPES_H 
#define DNS_TYPES_H

#include <stdint.h>

#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_MD 3
#define DNS_TYPE_MF 4
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_MB 7
#define DNS_TYPE_MG 8
#define DNS_TYPE_MR 9
#define DNS_TYPE_NULL 10
#define DNS_TYPE_WKS 11
#define DNS_TYPE_PTR 12
#define DNS_TYPE_HINFO 13
#define DNS_TYPE_MINFO 14
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AXFR 252
#define DNS_TYPE_MAILB 253
#define DNS_TYPE_MAILA 254
#define DNS_TYPE_ASTERISK 255

#define DNS_QUERY 0
#define DNS_RESPONSE 1

#define MAX_LABEL_LEN 63
#define MAX_DNS_LEN 1024
#define MAX_RESOURCE_LEN 32
#define MAX_NAME_LEN 256

#define MAX_QUERY_NUM 1024

#define DNS_HEADERS_LEN 12

typedef struct {
    uint16_t id; //标识字段
    uint8_t qr; //0为查询，1为响应
    uint8_t opcode; //查询类型
    uint8_t aa; //授权回答
    uint8_t tc; //可截断
    uint8_t rd; //期望递归
    uint8_t ra; //可用递归
    uint8_t rcode; //返回码

    uint16_t qd_cnt; //问题数
    uint16_t an_cnt; //资源记录数
    uint16_t ns_cnt; //授权资源记录数
    uint16_t ar_cnt; //额外资源记录数
} dns_header;

typedef struct dns_name{
    uint16_t label_cnt; //名字计数
    uint16_t* label_len;
    char** labels; //名字，以字符串数组的形式表示
} dns_name;

/*
**以带头节点的链表形式表示dns_query和dns_rr
*/

typedef struct dns_query{
    dns_name qname;
    uint16_t qtype;
    uint16_t qclass;

    struct dns_query* next; 
} dns_query;

typedef struct dns_rr {
    dns_name name;
    uint16_t rrtype;
    uint16_t rrclass;
    uint32_t ttl;

    uint16_t len;
    uint8_t* data;

    struct dns_rr* next;
} dns_rr;

typedef struct dns_packet{
    char raw_data[MAX_DNS_LEN];
    int raw_len;

    dns_header header;
    dns_query* queries;
    dns_rr* answers;
    dns_rr* authorities;
    dns_rr* additionals;
} dns_packet;

#endif