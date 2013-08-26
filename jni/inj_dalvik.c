/*
 * 这个文件编译生成注入入口和符号表替换逻辑。
 * 1、在该函数中加载libhook.so通过其中的do_hook函数返回原来的open和close地址以及要替换的新的open和close函数地址
 * 2、然后静态打开libnativehelper动态库，读取其结构遍历节表，找到全局符号表（GOT表），该表存储了外部依赖符号的地址
 * 3、遍历GOT表找到原先的open函数和close函数地址，分别替换为新的open函数和新的close函数即可
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <asm/ptrace.h>
#include <asm/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <jni.h>
#include <elf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include "utils.h"
#include <signal.h>
#include <sys/types.h>
#ifdef ANDROID
//#include <linker.h>
#endif
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <jni.h>

/*
 * 此处定义要被替换符号表的so列表
 */
char *sos[] = { "libnativehelper.so", };

/*
 *此处打开动态链接库，通过do_hook函数得到新旧地址
 */
int hook_entry() {
	unsigned long old_open_addr;
	unsigned long new_open_addr;
	unsigned long old_close_addr;
	unsigned long new_close_addr;

	LOGD("hello ARM! pid:%d\n", getpid());
	void *handle;
	/**
	 * 调用do_hook 函数
	 */
	int (*fcn)(unsigned long *param, unsigned long *param1,
			unsigned long *param2, unsigned long *param3);
	int target_pid = getpid();

	handle = dlopen("/dev/libhook.so", RTLD_NOW);
	LOGD("The Handle of libhook: %x\n", handle);

	if (handle == NULL) {
		LOGD("Failed to load libhook.so: %s\n", dlerror());
		return 1;
	}

	/* 动态打开do_hook函数*/
	LOGD("find do_hook pre %x\n", fcn);
	fcn = dlsym(handle, "do_hook");
	if (fcn != NULL)
		LOGD("find do_hook %x\n", fcn);
	else {
		LOGD("failed to find do_hook\n");
		return 0;
	}
	fcn(&old_open_addr, &new_open_addr, &old_close_addr, &new_close_addr);
	//取old_open_addr地址
	LOGD("[+] Get old address global  %x\n", old_open_addr);
	//取new_open_addr地址
	LOGD("[+] Get new address global  %x\n", new_open_addr);
	LOGD("[+] Get old address global  %x\n", old_close_addr);
	LOGD("[+] Get new address global  %x\n", new_close_addr);
	return 0;
}

int main(int argc, char *argv[]) {
	int pid = 0;

	void *handle = NULL;
	long proc = 0;

	/*此处定义要注入的进程*/
	char *process = "com.speedsoftware.rootexplorer";
	//char *process="in.wptraffcianalyzer.filereadwritedemo";

	pid = find_pid_of(process);
	ptrace_attach(pid);
	ptrace_find_dlinfo(pid);

	handle = ptrace_dlopen(pid, "/dev/libhook.so", 2);
	printf("ptrace_dlopen handle %p\n", handle);
	hook_entry();

	/*查找替换open函数的符号节*/
	proc = (long) ptrace_dlsym(pid, handle, "new_open");
	printf("new_open = %lx\n", proc);
	LOGD("new_open = %lx\n", proc);
	replace_all_rels(pid, "open", proc, sos);

	/*查找替换close函数的符号节*/
	proc = (long) ptrace_dlsym(pid, handle, "new_close");
	printf("new_close = %lx\n", proc);
	LOGD("new_close = %lx\n", proc);
	replace_all_rels(pid, "close", proc, sos);

	ptrace_detach(pid);
}

