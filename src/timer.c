#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include "thread_pool.h"
#include "timer.h"

timer_t* create_timer(unsigned long timeout, unsigned long repeat, void(*callback)(void*), void* arg, void(*cleanup)(void*))
{
	timer_t* timer = (timer_t*)malloc(sizeof(timer_t));
	timer->timeout = timeout;
	timer->time = 0;
	timer->repeat = repeat;
	timer->callback = callback;
	timer->arg = arg;
	timer->cleanup = cleanup;
	timer->shutdown = 0;

	return timer;
}
/* 开启一个定时器，每个定时器单独设置一个线程 */
void start_timer(void* info)
{
	timer_t* timer = (timer_t*)info;
	SOCKET s = socket(PF_INET, SOCK_STREAM, 0);
	fd_set dummy;
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 10000;
	while (timer->shutdown == 0 && timer->repeat > 0) {
		FD_ZERO(&dummy);
		FD_SET(s, &dummy);
		select(0, 0, 0, &dummy, &tv); 
		/* sleep(10ms) */
		if (timer->shutdown == 1) break;
		++timer->time;
		if (timer->time == timer->timeout) {
			timer->callback(timer->arg);
			--timer->repeat;
			timer->time = 0;
		}
	}
	closesocket(s);
	timer->cleanup(timer->arg);
	if (timer != NULL) free(timer);
	timer = NULL;
}
/* 删除一个定时器 */
void stop_timer(timer_t* timer)
{
	if (timer != NULL) timer->shutdown = 1;
}