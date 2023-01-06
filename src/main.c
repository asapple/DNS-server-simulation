#include "thread_pool.h"
#include "config.h"
#include "dns_server.h"
#include "db.h"
#include "dns_parse.h"
#ifdef _WIN32
#pragma comment(lib,"Ws2_32.lib")	
#endif

#define CRTDBG_MAP_ALLOC    
#include <stdlib.h>    
#include <crtdbg.h> 
#ifdef _DEBUG
#ifndef DBG_MALLOC
#define DBG_MALLOC malloc ( _NORMAL_BLOCK , __FILE__ , __LINE__ )
#define malloc DBG_MALLOC
#endif 
#endif  // _DEBUG

int main(int argc, char* argv[])
{
	/* ���Ӷ��߳�ģ����� */
#ifdef PTW32_STATIC_LIB
	pthread_win32_process_attach_np();
	pthread_win32_thread_attach_np();
#endif
	_CrtSetBreakAlloc(85);
	/* ������ʼ���� */
	init_config(argc, argv);
	/* ���������� */
	dns_server_start();
	_CrtDumpMemoryLeaks();
	/* ���Ӷ��߳�ģ����� */
#ifdef PTW32_STATIC_LIB
	pthread_win32_thread_detach_np();
	pthread_win32_process_detach_np();
#endif
	return 0;
}