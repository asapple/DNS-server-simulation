#define _CRT_SECURE_NO_WARNINGS
#ifdef _WIN32
#include <winsock2.h>
#include <WS2tcpip.h>
#endif
#ifdef __linux__
#include <sys/socket.h>
#include <arpa/inet.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "rbtree.h"
#include "db.h"

extern char db_file[50];
extern int debug_level;

static FILE* db_file_handle;
static struct rbtree* db_tree;
static pthread_rwlock_t db_mutex;

int compare(void* key_a,void* key_b)
{
    return strcmp((char*)key_a, (char*)key_b);
}

static int load_dnsrelay(struct rbtree* tree)
{
    if (tree == NULL)
    {
        fprintf(stderr, "malloc tree failed\n\n");
        exit(1);
    }
    int ret = -1;	
    FILE* infile = fopen(db_file, "r");
	if (infile == NULL) {
		return ret;
	}
    while (!feof(infile))
    {
        char* ip = (char*)malloc(sizeof(char) * SIZE);
        char* domain = (char*)malloc(sizeof(char) * SIZE);
		if (fscanf_s(infile, "%s%s", ip, SIZE, domain, SIZE) != EOF) {
			ret = rbtree_insert(tree, domain, ip);
		} else {
			if (ip != NULL) free(ip);
			ip = NULL;
			if (domain != NULL ) free(domain);
			domain = NULL;
			break;
		}
    }
	if (infile != NULL) {
		fclose(infile);
	}
	return ret;
}

int db_lookup(char* domain)
{
    pthread_rwlock_tryrdlock(&db_mutex);
    void *data = rbtree_lookup(db_tree, domain);
    pthread_rwlock_unlock(&db_mutex);
    int res = -1;
    if (data != NULL) {
        char* data_s = (char*)data;
        inet_pton(AF_INET, data_s, &res);
    }
    return res;
}

int db_insert(char* domain,int dnlen,char* ip,int iplen)
{
	char* key = (char*)malloc(dnlen * (sizeof(char) + 1));
	char* value = (char*)malloc(iplen*(sizeof(char) + 1));
	strcpy(key, domain);
	strcpy(value, ip);
	pthread_rwlock_wrlock(&db_mutex);
	rbtree_insert(db_tree, key, value);
	pthread_rwlock_unlock(&db_mutex);
	return 1;
}

void db_init()
{
    db_tree = rbtree_init(&compare);
	pthread_rwlock_init(&db_mutex, NULL);
    if (debug_level >= 1) {
        printf("[db]load db...\n");
    }
	int ret = load_dnsrelay(db_tree);
	if (ret < 0) {
		printf("[db]load db error\n");
	}
	if (ret == 0) {
		printf("[db]db load successfully.\n");
	}
}

void db_destroy()
{
	db_tree_destroy(db_tree);
	pthread_rwlock_destroy(&db_mutex);
	printf("[db]db has been destroyed successfully\n\n");

	return;
}

void destroy_with_store(struct rbtree_node* node)
{
	if (node == NULL) return;
	if (node->key != NULL && node->data != NULL) {
		fprintf(db_file_handle, "%s %s\n", (char*)(node->data), (char*)(node->key));
		fflush(db_file_handle);
		if (node->data) free(node->data);
		if (node->key) free(node->key);
		free(node);
		node = NULL;
	}
	else if (node->key != NULL) {
		free(node->key);
		node->key = NULL;
	}
	else if (node->data != NULL) {
		free(node->data);
		node->data = NULL;
	}
}

void db_tree_destroy(struct rbtree* tree)
{
	if (tree == NULL) return;
	//db_file_handle = fopen(db_file, "w");
	rbtree_destroy(tree);
	//fclose(db_file_handle);
}