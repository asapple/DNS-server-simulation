#ifndef CACHE
#define CACHE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CACHE_CAPACITY 3
#define HASH_TABLE_SIZE 1000

typedef struct {
    char* data;
    int len;
}entry_data;

typedef struct _cache_entry {
    entry_data domain_data, ip_data;
    struct _cache_entry* list_next, * list_pre;
    struct _cache_entry* hash_next, * hash_pre;
}cache_entry;

typedef struct {
    cache_entry** hash_array;  //哈希数组

    cache_entry* list_begin;   //指向链表头节点
    cache_entry* list_end;     //指向链表尾节点

    int now_capacity;         //现在的容量
}root_cache;

extern root_cache* root_of_cache;

void cache_insert(char* domain, int domain_len, char* ip, int ip_len);

char* cache_lookup(char* domain);

void new_cache(void);

void print_cache_lookup(void);

#endif