#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cache.h"

extern int debug_level;

//解决LNK1169 + LNK2005链接器问题
static root_cache* root_of_cache = NULL;

static int get_hash_key(entry_data key) {
    int hash = 0;
    for (int i = 0; i < key.len && i < 10; ++i) hash = (hash + key.data[i]) % HASH_TABLE_SIZE;
    /*
    while (root_of_cache->hash_array[hash]->domain_data.len == 0 ||
        root_of_cache->hash_array[hash]->domain_data.len != key.len ||
        !strncmp(root_of_cache->hash_array[hash]->domain_data.data, key.data, key.len)) ++hash;
    */
    return hash;
}

static void remove_entry_from_hash(cache_entry* entry) {
    if (NULL == entry) {
        return;
    }
    if (entry->hash_pre != NULL) {
        entry->hash_pre->hash_next = entry->hash_next;
    }
    else {
        int idx = get_hash_key(entry->domain_data);
        root_of_cache->hash_array[idx] = entry->hash_next;
        if (NULL != entry->hash_next) {
            entry->hash_next->hash_pre = root_of_cache->hash_array[idx];
        }
    }
}

static cache_entry* new_cache_entry(entry_data key, entry_data value) {
    cache_entry* entry = (cache_entry*)calloc(1, sizeof(cache_entry));
	entry->domain_data.data = (char*)malloc(sizeof(char)*key.len);
	entry->domain_data.len = key.len;
	strcpy_s(entry->domain_data.data, key.len, key.data);

	entry->ip_data.data = (char*)malloc(sizeof(char)*value.len);
	entry->ip_data.len = value.len;
	strcpy_s(entry->ip_data.data, value.len, value.data);

    entry->list_next = entry->list_pre = NULL;
    entry->hash_next = entry->hash_pre = NULL;

    return entry;
}

static void remove_entry_from_root(cache_entry* entry) {
    if (NULL == root_of_cache || NULL == entry) {
        return;
    }
    remove_entry_from_hash(entry);
    if (NULL == entry->list_pre && NULL == entry->list_next) {
		free(entry->domain_data.data);
		entry->domain_data.data = NULL;
		free(entry->ip_data.data);
		entry->ip_data.data = NULL;
        free(entry);
        entry = NULL;

        root_of_cache->list_begin = root_of_cache->list_end = NULL;
    }
    else if (NULL == entry->list_pre) {
        root_of_cache->list_begin = entry->list_next;
        root_of_cache->list_begin->list_pre = NULL;

		free(entry->domain_data.data);
		entry->domain_data.data = NULL;
		free(entry->ip_data.data);
		entry->ip_data.data = NULL;
		free(entry);
		entry = NULL;
    }
    else if (NULL == entry->list_next) {
        root_of_cache->list_end = entry->list_pre;
        root_of_cache->list_end->list_next = NULL;

		free(entry->domain_data.data);
		entry->domain_data.data = NULL;
		free(entry->ip_data.data);
		entry->ip_data.data = NULL;
		free(entry);
		entry = NULL;
    }
    else {
        entry->list_pre->list_next = entry->list_next;
        entry->list_next->list_pre = entry->list_pre;

		free(entry->domain_data.data);
		entry->domain_data.data = NULL;
		free(entry->ip_data.data);
		entry->ip_data.data = NULL;
		free(entry);
		entry = NULL;
    }
    root_of_cache->now_capacity -= 1;

    return;
}

static void remove_end_entry_from_root(void) {
    if (NULL != root_of_cache) {
        remove_entry_from_root(root_of_cache->list_end);
    }
}

static void add_entry_to_hash(cache_entry* entry) {
    if (NULL == root_of_cache || NULL == entry) {
        return;
    }
    cache_entry* hash_begin = root_of_cache->hash_array[get_hash_key(entry->domain_data)];
    if (NULL == hash_begin) {
        root_of_cache->hash_array[get_hash_key(entry->domain_data)] = entry;
        entry->hash_pre = root_of_cache->hash_array[get_hash_key(entry->domain_data)];
    }
    else {
        entry->hash_next = hash_begin;
        hash_begin->hash_pre = entry;

        root_of_cache->hash_array[get_hash_key(entry->domain_data)] = entry;
    }
}

static void add_entry_in_root_begin(cache_entry* entry) {
    if (NULL == root_of_cache || NULL == entry) {
        return;
    }
    cache_entry* root_of_cacheBegin = root_of_cache->list_begin;

    if (NULL == root_of_cacheBegin) {
        root_of_cache->list_begin = root_of_cache->list_end = entry;
    }
    else {
        root_of_cacheBegin->list_pre = entry;
        entry->list_next = root_of_cacheBegin;
        root_of_cache->list_begin = entry;
    }
    root_of_cache->now_capacity += 1;
    add_entry_to_hash(entry);
}
/*
 * 通过哈希寻找key
 */
static cache_entry* find_key(entry_data key) {
    cache_entry* listHead = root_of_cache->hash_array[get_hash_key(key)];

    if (NULL == listHead) {
        return NULL;
    }
    cache_entry* ptr = listHead;
    while (NULL != ptr) {
        if (ptr == NULL) return NULL;
        if (key.len == ptr->domain_data.len &&
            !strncmp(ptr->domain_data.data, key.data, ptr->domain_data.len))
            return ptr;

        //防止Debug模式中被删除的内存块数据置0xdddddddd形成自环
        if (ptr == ptr->hash_next || ptr->hash_next == 0xdddddddd) return NULL;
        ptr = ptr->hash_next;
    }
    return NULL;
}

/*
 *将(key: value)压入root_of_cache。
 * 1.若root_of_cache容量已经满了，就将最后一个节点删除
 * 2.若root_of_cache中已经存在key，则将这个(key : value)删除
 * 3.将(key: value)压入到队首
 */
void cache_insert(char* domain, int domain_len, char* ip, int ip_len) {
    entry_data key = (entry_data){ domain, domain_len };
    entry_data value = (entry_data){ ip, ip_len };

    if (NULL == root_of_cache) {
        return;
    }
    cache_entry* entry = find_key(key);
    if (NULL != entry) {
        /*********************************/
        if (debug_level == 2) {
            printf("domain[%s] has been updated to ip[%s]!\n", domain, ip);
        }
        /*********************************/
        remove_entry_from_root(entry);
    }
    entry = new_cache_entry(key, value);

    if (root_of_cache->now_capacity + 1 > CACHE_CAPACITY) {
        remove_end_entry_from_root();
    }
    add_entry_in_root_begin(entry);
}

/*
 *查找key多代表的节点
 *1.若没有key则返回NULL
 *2.找到后将(key: value)放到队首
 */
char* cache_lookup(char* domain) {
    entry_data key = (entry_data){ domain, strlen(domain) + 1 };
    if (NULL == root_of_cache) {
        return -1;
    }
    cache_entry* entry = find_key(key);
    if (NULL == entry) {
        /*********************************/
        if (debug_level == 2) {
            printf("domain[%s] cannot be found!\n", domain);
        }
        /*********************************/
        return -1;
    }
    cache_entry* ptr = new_cache_entry(entry->domain_data, entry->ip_data);
    remove_entry_from_root(entry);
    add_entry_in_root_begin(ptr);
    return ptr->ip_data.data;
}

void root_of_cache_cacheDestory(void) {
	if (root_of_cache == NULL) return;
    cache_entry* ptr = root_of_cache->list_begin;
    while (NULL != ptr){
        cache_entry* ptr2 = ptr->list_next;
        free(ptr);

        ptr = ptr2;
    }
    if (root_of_cache->hash_array) {
        free(root_of_cache->hash_array);
    }
    return;
}

void new_cache(void) {
    root_of_cache = (root_cache*)malloc(sizeof(root_cache));
    if (NULL == root_of_cache) {
        fprintf(stderr, "%s %d : malloc failed.\n", __func__, __LINE__);
    }
    root_of_cache->now_capacity = 0;
    root_of_cache->list_begin = root_of_cache->list_end = NULL;

    root_of_cache->hash_array = (cache_entry**)malloc(sizeof(cache_entry*) * (HASH_TABLE_SIZE + 1));
    memset(root_of_cache->hash_array, 0, sizeof(cache_entry*) * (HASH_TABLE_SIZE + 1));

    if (NULL == root_of_cache->hash_array) {
        fprintf(stderr, "%s %d : malloc failed.\n", __func__, __LINE__);
        exit(-1);
    }
}

void print_cache_lookup(char* domain) {
    /*********************************/
    if (debug_level >= 1) {
        printf("%s can be found as %s\n", domain, cache_lookup(domain));
    }
    /*********************************/
}