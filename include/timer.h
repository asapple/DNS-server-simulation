#ifndef TIMER_H
#define TIMER_H
#include <stdint.h>
#include <pthread.h>
#include "thread_pool.h"

/* 实现多线程软件计时器，便于在多线程状态下进行定时控制 */

struct timer {
	unsigned long timeout; /* 超时时间 */
	unsigned long time; /* 计时器当前运行时间 */
	unsigned long repeat; /* 计时器的寿命，即最大重传次数 */
	void(*callback)(void*); /* 超时回调函数 */
	void* arg; /* 超时回调函数参数 */
	void(*cleanup)(void*); /* 计时结束后，用于回收传入参数内存资源的函数 */

	int shutdown;
};
typedef struct timer timer_t;

/* 创建一个定时器 */
timer_t* create_timer(unsigned long timeout, unsigned long repeat, void(*callback)(void*), void* arg, void(*cleanup)(void*));
/* 开启一个定时器 */
void start_timer(void* arg);
/* 删除一个定时器 */
void stop_timer(timer_t* timer);

#endif