#include <stdio.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <asm/ptrace.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <android/log.h>

#define LOG_TAG "inject"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
int main()
{
	void (*func)();
	while(1)
	{

		sleep(2);
		func();
	}
}
