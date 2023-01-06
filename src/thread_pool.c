#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "thread_pool.h"
#ifdef _WIN32
#include <windows.h>
#endif

extern int debug_level;

static const int THREAD_STEP_NUM = 2;

thread_pool* create_thread_pool(int min, int max, int queue_size)
{
    thread_pool* pool = (thread_pool*) malloc(sizeof(thread_pool));
    do {
        if (pool == NULL) {
            perror("[thread pool]malloc pool error");
            break;
        }
        
        pool->thread_ids = (pthread_t*)malloc(sizeof(pthread_t)*max);
        if (pool->thread_ids == NULL) {
            perror("[thread pool]malloc thread id error");
            break;
        }
#ifndef __linux__
		/* 用于表示当前每个线程的状态，每个比特表示一个状态，其中至少需要[max]（向上取整）个字节来表示 */
		pool->thread_state = (char*)malloc(((max + sizeof(char) - 1) / sizeof(char)));
		if (pool->thread_state == NULL) {
			perror("[thread pool]malloc thread state error");
			break;
		}
#endif
        memset(pool->thread_ids, 0, sizeof(pthread_t)*max);
#ifndef __linux__
		memset(pool->thread_state, 0, (((max + sizeof(char) - 1) / sizeof(char))));
#endif
        pool->min_num = min;
        pool->max_num = max;
        pool->busy_num = 0;
        pool->live_num = min;
        pool->exit_num = 0;

        if (pthread_mutex_init(&pool->mutex_pool, NULL) != 0 || 
            pthread_mutex_init(&pool->mutex_busy, NULL) != 0 || 
            pthread_cond_init(&pool->not_empty, NULL) != 0   || 
            pthread_cond_init(&pool->not_full, NULL) != 0)
        {
            perror("[thread pool]init mutex error");
            break;
        }
        
        pool->task_q = (task*)malloc(sizeof(task)*queue_size);
        pool->queue_front = 0;
        pool->queue_rear = 0;
        pool->queue_size = 0;
        pool->queue_capicity = queue_size;

        pool->shutdown = 0;

        pthread_create(&pool->manager_id, NULL, manager, pool);
        for (int i=0; i<pool->min_num; ++i) {
            pthread_create(&pool->thread_ids[i], NULL, worker, pool);
			*(pool->thread_state + i / 8) |= 1 << (i % 8);
        }
        return pool;
    } while (0);
    if (pool && pool->thread_ids) free(pool->thread_ids);
	if (pool && pool->thread_state) free(pool->thread_state);
    if (pool && pool->task_q) free(pool->task_q);
    if (pool) free(pool);
    exit(1);
}

int thread_pool_destroy(thread_pool* pool)
{
    if (pool == NULL) {
        return -1;
    } else if (pool->shutdown) {
		return 0;
	}

    pool->shutdown = 1;

	pthread_join(pool->manager_id, NULL);

	for (int i = 0; i < pool->live_num; ++i) {
		pthread_cond_signal(&pool->not_empty);
	}

	pthread_mutex_lock(&pool->mutex_pool);
	while (pool->live_num != 0) {
		struct timespec tv;
		tv.tv_sec = 0;
		tv.tv_nsec = 10000000;
		pthread_cond_timedwait(&pool->not_empty, &pool->mutex_pool, &tv);
		pthread_cond_broadcast(&pool->not_empty);
		pthread_cond_broadcast(&pool->not_full);
	}
	pthread_mutex_unlock(&pool->mutex_pool);

    if (pool->task_q) {
        if (pool->task_q != NULL) free(pool->task_q);
		pool->task_q = NULL;
    }
    if (pool->thread_ids) {
        if (pool->task_q != NULL) free(pool->thread_ids);
		pool->thread_ids = NULL;
    }

    pthread_mutex_destroy(&pool->mutex_pool);
    pthread_mutex_destroy(&pool->mutex_busy);

    pthread_cond_destroy(&pool->not_empty);
    pthread_cond_destroy(&pool->not_full);

    if (pool != NULL) free(pool);
	pool = NULL;
    return 0;
}

void thread_pool_add(thread_pool* pool, void(*function)(void*), void* args)
{
	if (pool == NULL) return;
    pthread_mutex_lock(&pool->mutex_pool);

    while (pool->queue_size == pool->queue_capicity && !pool->shutdown) {
        pthread_cond_wait(&pool->not_full, &pool->mutex_pool);
    }

    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->mutex_pool);
        return;
    }

    pool->task_q[pool->queue_rear].function = function;
    pool->task_q[pool->queue_rear].args = args;
    pool->queue_rear = (pool->queue_rear + 1) % pool->queue_capicity;
    pool->queue_size++;

    pthread_cond_signal(&pool->not_empty);
    
	pthread_mutex_unlock(&pool->mutex_pool);
}

int thread_pool_busy_num(thread_pool* pool)
{
    pthread_mutex_lock(&pool->mutex_busy);
    int num = pool->busy_num;
    pthread_mutex_unlock(&pool->mutex_busy);
    return num;
}

int thread_pool_alive_num(thread_pool* pool)
{
    pthread_mutex_lock(&pool->mutex_pool);
    int num = pool->live_num;
    pthread_mutex_lock(&pool->mutex_pool);
    return num;
}

void* worker(void* arg)
{
	pthread_detach(pthread_self());
    thread_pool* pool = (thread_pool*)arg;
    while (1) {
        pthread_mutex_lock(&pool->mutex_pool);

        while (pool->queue_size == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->not_empty, &pool->mutex_pool);

            if (pool->exit_num > 0) {
                pool->exit_num--;
                if (pool->live_num > pool->min_num) {
                    pool->live_num--;
                    pthread_mutex_unlock(&pool->mutex_pool);
                    thread_exit(pool);
                }
            }
        }
        if (pool->shutdown == 1) {
			pool->live_num--;
			if (pool->live_num == 0) {
				pthread_cond_signal(&pool->not_empty);
			}
            pthread_mutex_unlock(&pool->mutex_pool);
			pthread_exit(NULL);
        }

        task new_task;
        new_task.function = pool->task_q[pool->queue_front].function;
        new_task.args = pool->task_q[pool->queue_front].args;

        pool->queue_front = (pool->queue_front + 1) % (pool->queue_capicity);
        pool->queue_size--;
        
        pthread_cond_signal(&pool->not_full);
        pthread_mutex_unlock(&pool->mutex_pool);

        pthread_mutex_lock(&pool->mutex_busy);
        pool->busy_num++;
        pthread_mutex_unlock(&pool->mutex_busy);

        new_task.function(new_task.args);
        if (new_task.args != NULL) free(new_task.args);
        new_task.args = NULL;

		pthread_mutex_lock(&pool->mutex_busy);
		pool->busy_num--;
		pthread_mutex_unlock(&pool->mutex_busy);
    }
	return NULL;
}

void* manager(void* arg)
{
    thread_pool* pool = (thread_pool*)arg;
    while (!pool->shutdown) {
        Sleep(3000);
        pthread_mutex_lock(&pool->mutex_pool);
        int queue_size = pool->queue_size;
        int live_num = pool->live_num;
        pthread_mutex_unlock(&pool->mutex_pool);
        
        pthread_mutex_lock(&pool->mutex_busy);
        int busy = pool->busy_num;
        pthread_mutex_unlock(&pool->mutex_busy);

        if (queue_size > live_num && live_num < pool->max_num) {
            pthread_mutex_lock(&pool->mutex_pool);
            int cnt = 0;
            for (int i=0;i<pool->max_num && cnt < THREAD_STEP_NUM && pool->live_num < pool->max_num; ++i)
            {
                #ifdef __linux__
                if (pool->thread_ids[i] == 0) {
                    pthread_create(&pool->thread_ids[i], NULL, worker, pool);
                    cnt++;
                    live_num++;
                }
                #endif
                #ifndef __linux__
				/* 对应字节中第i个比特位 */
				if (((*(pool->thread_state + i / 8) >> (i % 8)) & 1) == 0) {
					pthread_create(&pool->thread_ids[i], NULL, worker, pool);
					cnt++;
					pool->live_num++;
				}
                #endif
            }
            pthread_mutex_unlock(&pool->mutex_pool);
        }

        if (busy * 2 < live_num && live_num > pool->min_num) {
            pthread_mutex_lock(&pool->mutex_pool);
            pool->exit_num = THREAD_STEP_NUM;
            pthread_mutex_unlock(&pool->mutex_pool);
            for (int i = 0; i < THREAD_STEP_NUM; ++i) {
                pthread_cond_signal(&pool->not_empty);
            }
        }
    }
    return NULL;
}
void thread_exit(thread_pool* pool)
{
    pthread_t tid = pthread_self();
	for (int i = 0; i < pool->max_num; ++i) {
		if (pthread_equal(pool->thread_ids[i], tid)) {
			/* 对应第i个比特位置零 */
			*(pool->thread_state + i / 8) &= 0 << (i % 8);
			break;
		}
	}
    pthread_exit(NULL);
}