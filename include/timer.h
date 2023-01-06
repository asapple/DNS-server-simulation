#ifndef TIMER_H
#define TIMER_H
#include <stdint.h>
#include <pthread.h>
#include "thread_pool.h"

/* ʵ�ֶ��߳������ʱ���������ڶ��߳�״̬�½��ж�ʱ���� */

struct timer {
	unsigned long timeout; /* ��ʱʱ�� */
	unsigned long time; /* ��ʱ����ǰ����ʱ�� */
	unsigned long repeat; /* ��ʱ����������������ش����� */
	void(*callback)(void*); /* ��ʱ�ص����� */
	void* arg; /* ��ʱ�ص��������� */
	void(*cleanup)(void*); /* ��ʱ���������ڻ��մ�������ڴ���Դ�ĺ��� */

	int shutdown;
};
typedef struct timer timer_t;

/* ����һ����ʱ�� */
timer_t* create_timer(unsigned long timeout, unsigned long repeat, void(*callback)(void*), void* arg, void(*cleanup)(void*));
/* ����һ����ʱ�� */
void start_timer(void* arg);
/* ɾ��һ����ʱ�� */
void stop_timer(timer_t* timer);

#endif