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
    cache_entry** hash_array;  //��ϣ����

    cache_entry* list_begin;   //ָ������ͷ�ڵ�
    cache_entry* list_end;     //ָ������β�ڵ�

    int now_capacity;         //���ڵ�����
}root_cache;

extern root_cache* root_of_cache;

void cache_insert(char* domain, int domain_len, char* ip, int ip_len);

char* cache_lookup(char* domain);

void new_cache(void);

void print_cache_lookup(void);

#endif