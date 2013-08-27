/*
 * 该文件主要为ptrace的函数逻辑，将ptrace.h下函数进行了封装
 */
#include <stdio.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#ifdef ANDROID
#include <linux/user.h>
#else
#include <sys/user.h>
#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <utils.h>

#include <stdarg.h>
#include "linker.h"

static regs_t oldregs;

dl_fl_t ldl;

/*
 * 显示寄存器信息
 */
void ptrace_dump_regs(regs_t *regs, char *msg) {
    int i = 0;
    printf("------regs %s-----\n", msg);
    for (i = 0; i < 18; i++) {
        printf("r[%02d]=%lx\n", i, regs->uregs[i]);
    }
}

/*
 * 根据pid附加停止进程
 */
void ptrace_attach(int pid) {
    regs_t regs;
    int status = 0;
    /*
     * 形式：ptrace(PTRACE_ATTACH,pid)
     * 描述：跟踪指定pid 进程。pid表示被跟踪进程。被跟踪进程将成为当前进程的子进程，并进入中止状态。
     */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL ) < 0) {
        perror("ptrace_attach");
        exit(-1);
    }
    /*判断子进程停止是否由SIGSTOP引起*/
    status = ptrace_wait_for_signal(pid, SIGSTOP);
    printf("ptrace_wait_for_signal: %d %d\n", __LINE__, status);
    //waitpid(pid, NULL, WUNTRACED);

    ptrace_readreg(pid, &regs);
    memcpy(&oldregs, &regs, sizeof(regs));

    ptrace_dump_regs(&oldregs, "old regs");
#ifdef ANDROID
#ifdef THUMB
    regs.ARM_pc = 0x11;
    regs.ARM_cpsr |=0x30;
#else
    regs.ARM_pc= 0;
#endif
#else
    regs.rip = 0;
#endif
    ptrace_writereg(pid, &regs);

    ptrace_cont(pid);

    printf("waiting.. sigal...\n");

    /*
     * 异常捕获,SIGSEGV是当一个进程执行了一个无效的内存引用,或发生段错误时发送给它的信号
     * 否则执行后会发生signal 11 被注入进程失去响应而崩溃
     */
    status = ptrace_wait_for_signal(pid, SIGSEGV);
    printf("ptrace_wait_for_signal2: %d %d\n", __LINE__, status);

}

/*
 * 形式：ptrace(PTRACE_CONT, pid, 0, signal)
 * 描述：继续执行。pid表示被跟踪的子进程，signal为0则忽略引起调试进程中止的信号，若不为0则继续处理信号signal。
 */
void ptrace_cont(int pid) {
    //int stat;

    if (ptrace(PTRACE_CONT, pid, NULL, NULL ) < 0) {
        perror("ptrace_cont");
        exit(-1);
    }

    //while (!WIFSTOPPED(stat))
    //    waitpid(pid, &stat, WNOHANG);
}

void ptrace_detach(int pid) {
    ptrace_writereg(pid, &oldregs);

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL ) < 0) {
        perror("ptrace_detach");
        exit(-1);
    }
}

/*
 * 形式：ptrace(PTRACE_POKETEXT, pid, addr, data)
      ptrace(PTRACE_POKEDATA, pid, addr, data)
 * 描述：往内存地址中写入一个字节。pid表示被跟踪的子进程，内存地址由addr给出，data为所要写入的数据。
 */
void ptrace_write(int pid, unsigned long addr, void *vptr, int len) {
    int count;
    long word;
    void *src = (long*) vptr;
    count = 0;

    while (count < len) {
        memcpy(&word, src + count, sizeof(word));
        word = ptrace(PTRACE_POKETEXT, pid, (void*) (addr + count), (void*) word);
        count += 4;

        if (errno != 0)
            printf("ptrace_write failed\t %ld\n", addr + count);
    }
}

/*
 *从pid的addr开始读取len个字节
 */
void ptrace_read(int pid, unsigned long addr, void *vptr, int len) {
    int i, count;
    long word;
    unsigned long *ptr = (unsigned long *) vptr;

    i = count = 0;

    /*
     * 形式：ptrace(PTRACE_PEEKTEXT, pid, addr, data)
     * 	   ptrace(PTRACE_PEEKDATA, pid, addr, data)
     * 描述：从内存地址中读取一个字节，pid表示被跟踪的子进程，内存地址由addr给出，data为用户变量地址用于返回读到的数据。
     * 在Linux（i386）中用户代码段与用户数据段重合所以读取代码段和数据段数据处理是一样的。
     */
    while (count < len) {
        word = ptrace(PTRACE_PEEKTEXT, pid, (void*) (addr + count), NULL );
        count += 4;
        ptr[i++] = word;
    }
}

char * ptrace_readstr(int pid, unsigned long addr) {
    char *str = (char *) malloc(64);
    int i, count;
    long word;
    char *pa;

    i = count = 0;
    pa = (char *) &word;

    while (i <= 60) {
        word = ptrace(PTRACE_PEEKTEXT, pid, (void*) (addr + count), NULL );
        count += 4;

        if (pa[0] == '\0') {
            str[i] = '\0';
            break;
        } else
            str[i++] = pa[0];

        if (pa[1] == '\0') {
            str[i] = '\0';
            break;
        } else
            str[i++] = pa[1];

        if (pa[2] == '\0') {
            str[i] = '\0';
            break;
        } else
            str[i++] = pa[2];

        if (pa[3] == '\0') {
            str[i] = '\0';
            break;
        } else
            str[i++] = pa[3];
    }
    return str;
}

/*
 * 读取寄存器的值并打印
 */
void ptrace_readreg(int pid, regs_t *regs) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs))
        printf("*** ptrace_readreg error ***\n");

}

void ptrace_writereg(int pid, regs_t *regs) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs))
        printf("*** ptrace_writereg error ***\n");
}

/*
 * 参数压栈
 */
unsigned long ptrace_push(int pid, regs_t *regs, void *paddr, int size) {
#ifdef ANDROID
    unsigned long arm_sp;
    arm_sp = regs->ARM_sp;
    arm_sp -= size;
    arm_sp = arm_sp - arm_sp % 4;
    regs->ARM_sp= arm_sp;

    //开辟空间写入参数
    ptrace_write(pid, arm_sp, paddr, size);
    return arm_sp;
#else
    unsigned long esp;
    regs_t regs;
    ptrace_readreg(pid, &regs);
    esp = regs.esp;
    esp -= size;
    esp = esp - esp % 4;
    regs.esp = esp;
    ptrace_writereg(pid, &regs);
    ptrace_write(pid, esp, paddr, size);
    return esp;
#endif
}

long ptrace_stack_alloc(pid_t pid, regs_t *regs, int size) {
    unsigned long arm_sp;
    arm_sp = regs->ARM_sp;
    arm_sp -= size;
    arm_sp = arm_sp - arm_sp % 4;
    regs->ARM_sp= arm_sp;
    return arm_sp;
}

/*
 * 使子进程加载自定义库
 */
void *ptrace_dlopen(pid_t pid, const char *filename, int flag) {
#ifdef ANDROID
    regs_t regs;
    //int stat;
    ptrace_readreg(pid, &regs);

    ptrace_dump_regs(&regs, "before call to ptrace_dlopen\n");

#ifdef THUMB
    regs.ARM_lr = 1;
#else
    regs.ARM_lr= 0;
#endif

    //设置dlopen参数，r0是/dev/libhook.so的栈基址
    regs.ARM_r0= (long)ptrace_push(pid,&regs, (void*)filename,strlen(filename)+1);
    regs.ARM_r1= flag;
    regs.ARM_pc= ldl.l_dlopen;
    ptrace_writereg(pid, &regs);

    ptrace_dump_regs(&regs, "before continue ptrace_dlopen\n");
    ptrace_cont(pid);

    //捕捉异常，中断子进程
    printf("done %d\n", ptrace_wait_for_signal(pid, SIGSEGV));
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before return ptrace_dlopen\n");
    return (void*) regs.ARM_r0;
#endif
}

/*
 * 在库中查找符号，handle 指向的值为加载地址
 */
void *ptrace_dlsym(pid_t pid, void *handle, const char *symbol) {

#ifdef ANDROID
    regs_t regs;
    //int stat;读取子进程的寄存器值
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before call to ptrace_dlsym\n");

#ifdef THUMB

    regs.ARM_lr = 1;
#else
    regs.ARM_lr= 0;
#endif

    regs.ARM_r0= (long)handle;
    regs.ARM_r1= (long)ptrace_push(pid,&regs, (void*)symbol,strlen(symbol)+1);

    regs.ARM_pc= ldl.l_dlsym;
    ptrace_writereg(pid, &regs);
    ptrace_dump_regs(&regs, "before continue ptrace_dlsym\n");
    ptrace_cont(pid);
    printf("done %d\n", ptrace_wait_for_signal(pid, SIGSEGV));
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before return ptrace_dlsym\n");

    //dlsym的返回值在r0中，即查到的符号的地址
    return (void*) regs.ARM_r0;
#endif
}

int ptrace_mymath_add(pid_t pid, long mymath_add_addr, int a, int b) {
#ifdef ANDROID
    regs_t regs;
    //int stat;
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before call to ptrace_mymath_add\n");

#ifdef THUMB
    regs.ARM_lr = 1;
#else
    regs.ARM_lr= 0;
#endif

    regs.ARM_r0= a;
    regs.ARM_r1= b;

    regs.ARM_pc= mymath_add_addr;
    ptrace_writereg(pid, &regs);
    ptrace_cont(pid);
    printf("done %d\n", ptrace_wait_for_signal(pid, SIGSEGV));
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before return ptrace_mymath_add\n");

    return regs.ARM_r0;
#endif
}

int ptrace_call(int pid, long proc, int argc, ptrace_arg *argv) {
    int i = 0;
#define ARGS_MAX 64
    regs_t regs;
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before ptrace_call\n");

    /*prepare stacks*/
    for (i = 0; i < argc; i++) {
        ptrace_arg *arg = &argv[i];
        if (arg->type == PAT_STR) {
            arg->_stackid = ptrace_push(pid, &regs, arg->s, strlen(arg->s) + 1);
        } else if (arg->type == PAT_MEM) {
            //printf("push data %p to stack[%d] :%d \n", arg->mem.addr, stackcnt, *((int*)arg->mem.addr));
            arg->_stackid = ptrace_push(pid, &regs, arg->mem.addr, arg->mem.size);
        }
    }
    for (i = 0; (i < 4) && (i < argc); i++) {
        ptrace_arg *arg = &argv[i];
        if (arg->type == PAT_INT) {
            regs.uregs[i] = arg->i;
        } else if (arg->type == PAT_STR) {
            regs.uregs[i] = arg->_stackid;
        } else if (arg->type == PAT_MEM) {
            regs.uregs[i] = arg->_stackid;
        } else {
            printf("unkonwn arg type\n");
        }
    }

    for (i = argc - 1; i >= 4; i--) {
        ptrace_arg *arg = &argv[i];
        if (arg->type == PAT_INT) {
            ptrace_push(pid, &regs, &arg->i, sizeof(int));
        } else if (arg->type == PAT_STR) {
            ptrace_push(pid, &regs, &arg->_stackid, sizeof(unsigned long));
        } else if (arg->type == PAT_MEM) {
            ptrace_push(pid, &regs, &arg->_stackid, sizeof(unsigned long));
        } else {
            printf("unkonwn arg type\n");
        }
    }
#ifdef THUMB
    regs.ARM_lr = 1;
#else
    regs.ARM_lr= 0;
#endif
    regs.ARM_pc= proc;
    ptrace_writereg(pid, &regs);
    ptrace_cont(pid);
    printf("done %d\n", ptrace_wait_for_signal(pid, SIGSEGV));
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before return ptrace_call\n");

    //sync memory
    for (i = 0; i < argc; i++) {
        ptrace_arg *arg = &argv[i];
        if (arg->type == PAT_STR) {
        } else if (arg->type == PAT_MEM) {
            ptrace_read(pid, arg->_stackid, arg->mem.addr, arg->mem.size);
        }
    }

    return regs.ARM_r0;
}

/*
 * waitpid()的封装，用于等待子进程返回，并返回结束状态
 */
int ptrace_wait_for_signal(int pid, int signal) {
    int status;
    pid_t res;
    /*
     * waitpid()会暂时停止目前进程的执行,直到有信号来到或子进程结束。返回子进程结束状态值。
     * 子进程的结束状态值会由参数 status 返回
     * WIFSTOPPED(status) 若为当前暂停子进程返回的状态，则为真；
     * 对于这种情况可执行WSTOPSIG(status)，取使子进程暂停的信号编号。
     */
    res = waitpid(pid, &status, 0);
    if (res != pid || !WIFSTOPPED (status))
        return 0;
    return WSTOPSIG (status) == signal;
}

/*
 * 获取/system/bin/linker的开始基址和结束地址
 */
static Elf32_Addr get_linker_base(int pid, Elf32_Addr *base_start, Elf32_Addr *base_end) {
    unsigned long base = 0;
    char mapname[FILENAME_MAX];
    memset(mapname, 0, FILENAME_MAX);

    /*查看进程的虚拟地址空间是如何使用的*/
    snprintf(mapname, FILENAME_MAX, "/proc/%d/maps", pid);
    FILE *file = fopen(mapname, "r");
    *base_start = *base_end = 0;
    if (file) {
        //400a4000-400b9000 r-xp 00000000 103:00 139       /system/bin/linker
        while (1) {
            unsigned int atleast = 32;//到偏移量正好32
            int xpos = 20;
            char startbuf[9];
            char endbuf[9];
            char line[FILENAME_MAX];
            memset(line, 0, FILENAME_MAX);

            /*fgets 正好读取一行*/
            char *linestr = fgets(line, FILENAME_MAX, file);
            if (!linestr) {
                break;
            }
            printf("........%s <--\n", line);
            if (strlen(line) > atleast && strstr(line, "/system/bin/linker")) {
                memset(startbuf, 0, sizeof(startbuf));
                memset(endbuf, 0, sizeof(endbuf));

                memcpy(startbuf, line, 8);
                memcpy(endbuf, &line[8 + 1], 8);
                if (*base_start == 0) {
                    *base_start = strtoul(startbuf, NULL, 16);//字符串转为无符号数
                    *base_end = strtoul(endbuf, NULL, 16);
                    base = *base_start;
                } else {
                    *base_end = strtoul(endbuf, NULL, 16);
                }
            }
        }
        fclose(file);

    }
    return base;

}

/*
 *在libdl.so中查找dlopen、dlclose、dlsym的函数
 */
dl_fl_t *ptrace_find_dlinfo(int pid) {
    Elf32_Sym sym;
    Elf32_Addr addr;
    struct soinfo lsi;
#define LIBDLSO "libdl.so"
    Elf32_Addr base_start = 0;
    Elf32_Addr base_end = 0;

    /*linker 主要用于实现共享库的加载与链接。它支持应用程序对库函数的隐式和显式调用。*/
    Elf32_Addr base = get_linker_base(pid, &base_start, &base_end);

    if (base == 0) {
        printf("no linker found\n");
        return NULL ;
    } else {
        printf("search libdl.so from %08u to %08u\n", base_start, base_end);
    }

    for (addr = base_start; addr < base_end; addr += 4) {
        char soname[strlen(LIBDLSO)];
        Elf32_Addr off = 0;

        //查找/system/bin/linker中加载的libdl.so,加载位置固定,定义了dlopen,dlcose,dlsym,dlerror
        ptrace_read(pid, addr, soname, strlen(LIBDLSO));
        if (strncmp(LIBDLSO, soname, strlen(LIBDLSO))) {
            continue;
        }

        //找到libdl.so的加载位置，并读取libdl.so的动态库信息
        printf("soinfo found at %08u\n", addr);
        ptrace_read(pid, addr, &lsi, sizeof(lsi));
        printf("symtab: %p\n", lsi.symtab);

        //符号表，保存了一个程序在定位和重定位时需要的定义和引用的信息。
        /*
         * 在符号表”.symtab“中，其也是像段表的结构一样，是一个数组，每个数组元素是一个固定的结构来保存符号的相关信息，
         * 比如符号名（不是字符串，而是该符号名在字符串表的下标）、符号对应的值（可能是段中的偏移，也可能是符号的虚拟地址）、符号大小（数据类型的大小）等等。
         * 符号表中记录的一般是全局符号，比如全局变量、全局函数等等。
         *
         * 每个object要想使它对其他的ELF文件可用，就要用到符号表(symbol table)中
         * symbol entry.事实上，一个symbol entry 是个symbol结构，它描述了这个
         * symbol的名字和该symbol的value.symbol name被编码作为dynamic string
         * table的索引(index). The value of a symbol是在ELF OBJECT文件内该
         * symbol的地址。该地址通常需要被重新定位（加上该object装载到内存的基地址(base load address)）.
         */
        off = (Elf32_Addr)lsi.symtab;

        /*
         * 理解此段程序的难度在于lsi.symtab其实指的就是libdl.so加载到内存中的 .dynsym
         * 在查看模拟器导出的libdl.so发现只有动态符号表
         * symtab 和 .dynsym 里存放符号信息(这些符号包括文件名，函数名，变量名等等)，前者一般是静态符号，后者则是动态链接相关符号；
         *
         * sh_flag 成员用来表示节区的相关标志。取不同的值有不同的意义，比如可以表示该节区是不是存放可执行代码，该节区是否包含有在进程执行时可写的数据等。
         * 其中有一个 A 标志，是 Allocable 之意，表示在程序运行时，进程需要使用它们，所以它们会被加载到内存中去，比如 .data 一般就是 allocable 的。 反之，则是 non-Allocable，这类型的节区只是被链接器、调试器或者其他类似工具所使用，不会参与程序运行时的内存中去，如 .symtab 和 .strtab 以及各种 .debug 相关节区就属于这种类型。在可执行文件执行时，allocable 部分会被加载到内存中，而 non-Allocable 部分则仍留在文件内。
         *
         */
        ptrace_read(pid, off, &sym, sizeof(sym));
        //just skip
        off += sizeof(sym);

        /*
         * 关于顺序的问题，显示打印.dynsym节，在android2.3.3发现顺序其实是这样的
         * Symbol table '.dynsym' contains 28 entries:
   	   	   Num:    Value  Size Type    Bind   Vis      Ndx Name
     	 	 0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND
     	 	 1: 00001a0d     4 FUNC    GLOBAL DEFAULT    7 dlopen
     	 	 2: 00001a11     4 FUNC    GLOBAL DEFAULT    7 dlerror
     	 	 3: 00001a15     4 FUNC    GLOBAL DEFAULT    7 dlsym
     	 	 4: 00001a19     4 FUNC    GLOBAL DEFAULT    7 dladdr
     	 	 5: 00001a1d     4 FUNC    GLOBAL DEFAULT    7 dlclose
     	 * 由于dlclose没有用到，所以该程序相对位置还是对的。
     	 */

        ptrace_read(pid, off, &sym, sizeof(sym));
        printf("name2:%d\n",sym.st_name);
        printf("value2:%d\n",sym.st_value);
        ldl.l_dlopen = sym.st_value;
        off += sizeof(sym);

        ptrace_read(pid, off, &sym, sizeof(sym));
        printf("name3:%d\n",sym.st_name);
        printf("value3:%d\n",sym.st_value);
        ldl.l_dlclose = sym.st_value;
        off += sizeof(sym);

        ptrace_read(pid, off, &sym, sizeof(sym));
        printf("name4:%d\n",sym.st_name);
        printf("value4:%d\n",sym.st_value);
        ldl.l_dlsym = sym.st_value;
        off += sizeof(sym);

        printf("dlopen addr %p\n", (void*) ldl.l_dlopen);
        printf("dlclose addr %p\n", (void*) ldl.l_dlclose);
        printf("dlsym addr %p\n", (void*) ldl.l_dlsym);
        return &ldl;

    }
    printf("%s not found!\n", LIBDLSO);
    return NULL ;
}

/*
 * 根据进程名称查找进程的pid
 */
int find_pid_of( const char *process_name )
{
	int id;
	pid_t pid = -1;
	DIR* dir;
	FILE *fp;
	char filename[32];
	char cmdline[256];

	/*为了获取某文件夹目录内容，所使用的结构体。*/
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
			/*/proc/pid/cmdline存放启动进程时执行的命令，一般为进程名称*/
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

