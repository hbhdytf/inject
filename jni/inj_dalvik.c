/*
 * inj_dalvik.c
 *
 *  Created on: 2013-1-18
 *      Author: d
 */

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
#include <dirent.h>




char *sos[] = {
        "linker"
        "libdvm.so",
        "libnativehelper.so",
        "libandroid_runtime.so",
        "libmath.so",
        "libc.so",
        NULL
};
int find_pid_of( const char *process_name )
{
	int id;
	pid_t pid = -1;
	DIR* dir;
	FILE *fp;
	char filename[32];
	char cmdline[256];

	struct dirent * entry;

	if ( process_name == NULL )
		return -1;

	dir = opendir( "/proc" );
	if ( dir == NULL )
		return -1;

	while( (entry = readdir( dir )) != NULL )
	{
		id = atoi( entry->d_name );
		if ( id != 0 )
		{
			sprintf( filename, "/proc/%d/cmdline", id );
			fp = fopen( filename, "r" );
			if ( fp )
			{
				fgets( cmdline, sizeof(cmdline), fp );
				fclose( fp );

				if ( strcmp( process_name, cmdline ) == 0 )
				{
					/* process found */
					pid = id;
					break;
				}
			}
		}
	}

	closedir( dir );

	return pid;
}


void call_shit(struct elf_info *einfo) {
    unsigned long addr2 = 0;
    unsigned long rel_addr = find_sym_in_rel(einfo, "math_shit");
    regs_t regs;
    ptrace_read(einfo->pid, rel_addr, &addr2, sizeof(long));
    printf("math_shit rel addr\t %lx\n", rel_addr);
    printf("addr2 is \t %lx\n", addr2);
    ptrace_readreg(einfo->pid, &regs);
    ptrace_dump_regs(&regs,"before call to call_shit\n");
#ifdef THUMB
    regs.ARM_lr = 1;
#else
    regs.ARM_lr = 0;
#endif
    regs.ARM_r0 = 5;
    regs.ARM_r1 = 6;
    regs.ARM_r2 = 7;
    regs.ARM_r3 = 8;
    {
        int a5 = 9;
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        a5 = 10;
        ptrace_push(einfo->pid, &regs, &a5, 4);
    }
    regs.ARM_pc = addr2;
    ptrace_writereg(einfo->pid, &regs);
    ptrace_cont(einfo->pid);
    printf("done %d\n",  ptrace_wait_for_signal(einfo->pid,SIGSEGV));
    ptrace_readreg(einfo->pid, &regs);
    ptrace_dump_regs(&regs,"before return call_shit\n");
}




int main(int argc, char *argv[]) {
    int pid;
    struct link_map *map;
    struct elf_info einfo;

    extern dl_fl_t ldl;

    void *handle = NULL;
    long proc = 0;
    long hooker_fopen = 0;
    char *process="com.speedsoftware.rootexplorer";
    pid = find_pid_of(process);
    ptrace_attach(pid);
    ptrace_find_dlinfo(pid);



    handle = ptrace_dlopen(pid, "/dev/libmynet.so",2);
    printf("ptrace_dlopen handle %p\n",handle);
    proc = (long)ptrace_dlsym(pid, handle, "my_connect");
    printf("my_connect = %lx\n",proc);
    int (*hook)();
    int (*hook1)();

    hook1=ptrace_dlsym(pid,handle,"hook");
    proc = (long)ptrace_dlsym(pid, handle, "hook");

    printf("hook1 = %lx\n",proc);
    printf("hook1 = %lx\n,size:%d\n",hook1,sizeof(hook1));

    handle=dlopen("/dev/libmynet.so", RTLD_NOW);
    hook = dlsym(handle, "hook");
    printf("hook = %lx\n,size:%d\n",hook,sizeof(hook));
    (*hook)();

    ptrace_detach(pid);
}










