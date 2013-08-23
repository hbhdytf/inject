/*
 * libmynet.c
 *
 *  Created on: 2013-1-17
 *      Author: d
 */

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <android/log.h>

#define LOG_TAG "inject"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)

int my_connect(int socket, const struct sockaddr *address, socklen_t address_len) {
    return -1;
}
int hook()
{
	LOGD("Hello HOOK HAHAHAH!\n");
	printf("Hello hooking!\n");
	return 0;
}
