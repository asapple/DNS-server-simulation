#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#define SIZE 128
typedef unsigned long long ULL;

int compare(void* key_a,void* key_b);
void db_init();
static int load_dnsrelay(struct rbtree* tree);
int db_lookup(char* domain);
int db_insert(char* domain, int dnlen, char* ip, int iplen);
void db_destroy();
void db_tree_destroy(struct rbtree* tree);
void destroy_with_store(struct rbtree_node* node);

#endif