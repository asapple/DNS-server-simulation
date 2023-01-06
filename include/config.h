#ifndef DNS_CONFIG_H
#define DNS_CONFIG_H

#define OPT_SHORT "?d::l:a:"
#define getopt_long getopt_int

void init_config(int argc, char* argv[]);

#endif