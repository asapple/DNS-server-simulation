#ifndef DNS_ID_MAP_H
#define DNS_ID_MAP_H
#include <WinSock2.h>
#include <stdint.h>
#include"rbtree.h"

/* 

DNS 映射表
实现三组映射关系
client_id -> server_id
server_id -> client_id
server_id -> sockaddr

client id exist? srand() another id : itself

server id -> ip + client id

delete 根据键删除对应表项
*/

struct client_info {
	struct sockaddr_in addr;
	uint16_t client_id;
};

typedef struct client_info client_info_t;

typedef struct {
    struct rbtree* server_to_client_map; // key为发往远程服务器的 DNS ID, value为客户端的 DNS ID 和 IP地址

	pthread_rwlock_t mutex; //保证对DNS ID映射表的修改是线程安全的
} dns_id_map;

/* 初始化 */
dns_id_map* create_dns_id_map();

/* 查询某个客户端的DNS请求ID是否已经存在 */
int is_dns_id_exist(uint16_t client_id, dns_id_map* map);

/* 插入一条客户端的DNS请求ID，本函数需要判定客户端id是否冲突，如果不冲突则服务器ID与客户端ID相同，如果冲突则类似解决哈希冲突的办法寻找其他对应的服务器id */
/* 返回值为冲突解决后的DNS ID */
uint16_t insert_dns_id(uint16_t client_id, struct sockaddr_in address, dns_id_map* map);

/* 根据DNS服务器端的DNS请求ID得到客户端的ID */
int get_client_info(uint16_t server_id, uint16_t* client_id, struct sockaddr_in* addr,dns_id_map* map);

/* DNS请求完成后，回收客户端id，从映射表中删除对应表项 */
int delete_id(uint16_t server_id, dns_id_map* map);

/* 销毁DNS ID映射表 */
void dns_id_map_destroy(dns_id_map* map);

#endif