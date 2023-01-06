#ifndef THREAD_POOL_H
#define THREAD_POOL_H
#include <pthread.h>

typedef struct task {
    void (*function)(void*);
    void* args; 
} task;

typedef struct thread_pool {
    task* task_q;        //任务队列
    int queue_capicity; //任务最大容量
    int queue_front;    //队首任务
    int queue_rear;     //队尾任务
    int queue_size;     //队列当前大小

    pthread_t manager_id;   //管理者线程
    pthread_t* thread_ids;  //工作线程
#ifndef __linux__
	char* thread_state; //表示线程状态
#endif

    int min_num;  //最少工作线程数
    int max_num;  //最多工作线程数
    int busy_num; //忙线程数
    int live_num; //存活线程数
    int exit_num; //待销毁线程数

    pthread_mutex_t mutex_pool; //锁整个线程池
    pthread_mutex_t mutex_busy; //锁busy_num
    pthread_cond_t not_full;    //任务队列未满
    pthread_cond_t not_empty;   //任务队列未空

    int shutdown;
} thread_pool;

thread_pool* create_thread_pool(int min, int max, int queue_size); //创建线程池
int thread_pool_destroy(thread_pool* pool);     //销毁线程池

void thread_pool_add(thread_pool* pool, void(*function)(void*), void* args);  //向线程池中添加任务

int thread_pool_busy_num(thread_pool* pool);  //线程池中工作线程数量
int thread_pool_alive_num(thread_pool* pool); //线程池中存活的线程数量

void* worker(void* arg);  //工作任务函数
void* manager(void* arg);  //管理者任务函数
void thread_exit(thread_pool* pool);  //单个线程退出

#endif