#include <WinSock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include"dns_id_map.h"
#include"rbtree.h"

extern int debug_level;
static pthread_mutex_t mutex;

static int dns_id_compare(void* key_a, void* key_b)
{
	return (*(uint16_t*)key_a - *(uint16_t*)key_b);
}

dns_id_map* create_dns_id_map()
{
	dns_id_map* map = (dns_id_map*)malloc(sizeof(dns_id_map));

	map->server_to_client_map = rbtree_init(&dns_id_compare);
	if (map->server_to_client_map == NULL)
	{
		perror("dns_id_map_init error");
		exit(1);
	}

	pthread_rwlock_init(&map->mutex, NULL);
	return map;
}

int is_dns_id_exist(uint16_t client_id, dns_id_map* map)
{
	pthread_rwlock_rdlock(&map->mutex);
	void* ret = rbtree_lookup(map->server_to_client_map, &client_id);
	pthread_rwlock_unlock(&map->mutex);
	return (ret == NULL) ? 0 : 1;
}

uint16_t insert_dns_id(uint16_t client_id,struct sockaddr_in address,dns_id_map* map)
{
	/* Î±Ëæ»úÌ½²â·¨ */
	srand((unsigned)time(NULL));
	uint16_t id = client_id;
	if (is_dns_id_exist(id, map))
		{
		if (debug_level >= 1) {
			printf("[server]dns collision occur!\n");
		}
		do {
			id = (uint16_t)rand();
		} while (is_dns_id_exist(id, map));
	}
	uint16_t* key_id = (uint16_t*)malloc(sizeof(uint16_t));
	*key_id = id;

	client_info_t* client_info = (client_info_t*)malloc(sizeof(client_info_t));
	client_info->client_id = client_id;
	client_info->addr = address;

	pthread_rwlock_wrlock(&map->mutex);
	rbtree_insert(map->server_to_client_map, key_id, client_info);
	pthread_rwlock_unlock(&map->mutex);

	return id;
}
int get_client_info(uint16_t server_id, uint16_t* client_id, struct sockaddr_in* addr, dns_id_map* map)
{
	pthread_rwlock_rdlock(&map->mutex);
	client_info_t* client_info = rbtree_lookup(map->server_to_client_map, &server_id);
	pthread_rwlock_unlock(&map->mutex);
	if (client_info == NULL) return -1;
	*addr = client_info->addr;
	*client_id = client_info->client_id;
	return 0;
}

int delete_id(uint16_t server_id, dns_id_map* map)
{
	pthread_rwlock_wrlock(&map->mutex);
	int ret = rbtree_remove(map->server_to_client_map, &server_id);
	pthread_rwlock_unlock(&map->mutex);
	if (debug_level >= 1 && ret == 0) {
		printf("[dns id map]delete id %04x successfully.\n", ntohs(server_id));
	}
	return ret;
}

void dns_id_map_destroy(dns_id_map* map)
{
	rbtree_destroy(map->server_to_client_map);
	pthread_rwlock_destroy(&map->mutex);
	if (map != NULL) free(map);
	map = NULL;
}