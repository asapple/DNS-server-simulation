#ifdef __linux__
#include <unistd.h>
#include <getopt.h>
#endif
#ifndef __linux__
#include "getopt.h"
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include "config.h"

static struct option long_options[] = {
	{.name = "help",.has_arg = no_argument,.flag = NULL,.val = '?'},
	{.name = "debug",.has_arg = optional_argument,.flag = NULL,.val = 'd'},
	{.name = "log",.has_arg = required_argument,.flag = NULL,.val = 'l'},
	{.name = "address",.has_arg = required_argument,.flag = NULL,.val = 'a'},
	{.name = "",.has_arg = no_argument,.flag = NULL,.val = '\0'}
};

/* 默认选项 */
char remote_dns[512] = "101.199.128.54";
char db_file[50] = ".\\dnsrelay.txt";
int debug_level = 0;

void init_config(int argc, char* argv[])
{
	char now_str[50] = { '\0' };
	struct tm t;
	time_t now;
	time(&now);
	localtime_s(&t, &now);
	asctime_s(now_str, sizeof(now_str), &t);
	printf("DNSRELAY, Build: %s\n", now_str);
	int opt;
	while ((opt = getopt_long(argc, argv, OPT_SHORT, &long_options, NULL)) != -1) {
		switch (opt) {
		case '?':
			goto usage;

		case 'd':
			if (optarg != NULL) {
				debug_level = atoi(optarg);
			} else goto usage;
			if (debug_level < 0 || debug_level>2) goto usage;
			break;
        
        case 'l':
            memset(db_file, 0, sizeof(db_file));
            strcpy_s(db_file, 50, optarg);
            break;

        case 'a':
            memset(remote_dns, 0, sizeof(db_file));
            strcpy_s(remote_dns,512,optarg);
            break;

		default:
			printf("ERROR: Unsupported option\n");
			goto usage;
		}
	}

	printf("Remote dns: %s\n", remote_dns);
	printf("Data file: %s\n", db_file);
	printf("Debug level: %d\n", debug_level);
	printf("if you want to terminate the program, just type ESC.\n\n");

    return;
    usage:
		printf("\nUsage:\n  %s <options>\n", argv[0]);
		printf(
			"\nOptions : \n"
			"    -?, --help : print this\n"
			"    -d, --debug=<0-2>: debug level set, default 0\n"
			"    -l, --log=<filename> : using assigned file as db file\n"
			"    -a, --address=<remote dns ip address> : set remote dns server ip address\n"
			"\n"
			"i.e.\n"
			"    %s -d2 -a 8.8.8.8 -l ./dnsrelay.txt\n"
			"    %s --debug=2 --address=8.8.8.8 --log=./dnsrelay.txt\n"
			"\n",
			argv[0], argv[0]);
		exit(0);
}