/*
 * 该文件有三个主要功能
 * 1、获取old_open和old_close的函数地址以及自己定义的new_open和new_close的函数地址并返回
 * 2、新的open和close函数的主要流程，在open的时候，捕获路径，进行匹配，若需要解密，则进行解密到临时文件，然后将临时文件的描述符返回；
 * 	 在close的时候，进行判断是否为解密文件，若是，则进行加密操作，并删除临时文件。
 * 3、加解密模块的抽象
 */
#include <unistd.h>
#include <sys/types.h>
#include <android/log.h>
#include <linux/binder.h>
#include <stdio.h>
#include <stdlib.h>
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
#include <android/log.h>
#include <sys/system_properties.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/stat.h>
#define PROPERTY_VALUE_MAX 256
/*
 * JNI的日志输出
 */
#define LOG_TAG "inject"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)

/*	缓冲区大小*/
#define BUFFER_SIZE 1024

/*	枚举可选的加密算法	*/
enum crypt {
	Aes_256_ofb, //256位AES算法上述的算法是0.9.7版本,64位输出反馈（OutputFeedback）加密方式
	Aes_192_ofb, //OFB方式的192位AES算法
	Aes_128_ofb, //OFB方式的128位AES算法
	Des_ede3_ofb, //OFB方式的3DES算法，算法的三个密钥都不相同
	Des_ede_ofb, //OFB方式的3DES算法，算法的第一个密钥和最后一个密钥相同，事实上就只需要两个密钥
	Rc2_ofb, //OFB方式的RC2算法，该算法的密钥长度是可变的，可以通过设置有效密钥长度或有效密钥位来设置参数来改变。缺省的是128位。
	Bf_ofb, //OFB方式的Blowfish算法，该算法的密钥长度是可变的
	Enc_null //该算法不作任何事情，也就是没有进行加密处理
};

/*
 * 函数声明
 */
int encrypt_init(EVP_CIPHER_CTX *ctx);
int encrypt_abstract(const char *plaintext_path, EVP_CIPHER_CTX *ctx,
		const char *ciphertext_path);
int decrypt_init(EVP_CIPHER_CTX *ctx);
int decrypt_abstract(const char *plaintext_path, EVP_CIPHER_CTX *ctx,
		const char *ciphertext_path);
char *get_key(int key_length);
enum crypt get_crypt_config(char *config_name);
int check_path(const char* path);
char* create_tmpfile(const char* path);
char* recover_tmpfile(const char* path);

/*
 * 存放hook之前的open 和 close 函数地址，在加解密操作结束后调用用来返回到正常的调用中。
 */
extern int __open(const char*, int, int);
int (*old_open)(const char* path, int mode, ...) = open;
int (*old_close)(int fd)=close;

int call_count = 0;
// 欲接替open的新函数地址，其中内部调用了老的open
int new_open(const char* path, int mode, ...) {

	//for test
	LOGD("[+]-----------new open test txt file-----------");
	LOGD("[+] The New open path %s", path);
	call_count++;
	LOGD("[+] The New open count %d", call_count);
	LOGD("[+] The OLD open real path %x", old_open);
	LOGD("[+] The NEW open real path %x", new_open);

	// 检测path是否为检测列表中的地址
	//const char* to_path = "/mnt/sdcard/owncloud/admin@192.168.111.11/test.txt";
	int check = check_path(path);
	LOGD("[+] check %d", check);
	//temp文件名更新
	//	const char* de_path = "/mnt/sdcard/owncloud/admin@192.168.111.11/testcopy1.txt";

	if (check > 0) {
		LOGD("[+] open the file");
		//temp文件名更新

		const char* de_path = create_tmpfile(path);
		LOGD("[+] Create tmp open file fd %s", de_path);
		EVP_CIPHER_CTX ctx;

		/* 解密 */
		decrypt_init(&ctx);
		decrypt_abstract(de_path, &ctx, path);

		//将解密的文件返回
		int res = (*old_open)(de_path, mode); //
		LOGD("[+] The New open file fd %d", res);
		//打印的结果是from_fd 不是to_fd????

		/* 判断该fd关联的文件，确认是新的解密文件 */
		char s[256], name[256];
		snprintf(s, 255, "/proc/%d/fd/%d", getpid(), res);
		memset(name, 0, sizeof(name)); // readlink在name后面不会加'\0'，加上清buf
		readlink(s, name, 255);
		LOGD("[+] The Name of fd %s", name);
		LOGD("[+] The S of fd %s", s);

		return res;
	}

	//不是需要解密的文件，直接通过old_open返回
	int res = (*old_open)(path, mode); //?????
	LOGD("[+] The old openfile fd %d", res);
	return res;

}

int new_close(int fd) {
	LOGD("[+]-----------new close test txt file-----------");
	LOGD("[+] The OLD close real path %x", old_close);
	LOGD("[+] The NEW close real path %x", new_close);
	//通过fd关联的文件，判断是否是解密后的文件。
	char s[256], name[256];
	snprintf(s, 255, "/proc/%d/fd/%d", getpid(), fd);
	memset(name, 0, sizeof(name)); // readlink在name后面不会加'\0'，加上清buf
	readlink(s, name, 255);
	LOGD("[+] The Name of fd %s", name);
	LOGD("[+] The S of fd %s", s);

	//2.
	const char* from_path = name;
	const char* to_path = recover_tmpfile(name);
	LOGD("[+] The path of rec %s\n", to_path);
	int check = 0;
	LOGD("[+] The check1 %d\n", check);
	if (to_path == NULL) {
		check = 0;
		LOGD("[+] The check2 %d\n", check);
	} else {
		check = check_path(to_path);
		LOGD("[+] The check3 %d\n", check);
	}
	if (check) {
		LOGD("[+] open pre test copy file");

		/* 加密*/
		EVP_CIPHER_CTX ctx;
		encrypt_init(&ctx);
		encrypt_abstract(from_path, &ctx, to_path);

		/* 关闭加密文件 */
		int res = (*old_close)(fd);
		LOGD("[+] The new close file return %d.", res);
		return res;
	}
	//4.invoke old function
	int res = (*old_close)(fd);
	LOGD("[+] The old close file return %d.", res);

	/*	删除临时文件 */
//	int removefd=remove(new_path);
//	LOGD("[+] The temp file has been removed %d.",removefd);
	return res;
}

int do_hook(unsigned long * old_open_addr, unsigned long * new_open_addr,
		unsigned long * old_close_addr, unsigned long * new_close_addr) {

	LOGD("[+] do_hook function is invoked ");
	old_open = open;
	old_close = close;
	LOGD("[+] open addr: %p. New addr %p\n", open, new_open);

	//get open function address
	char value[PROPERTY_VALUE_MAX] = { '\0' };
	snprintf(value, PROPERTY_VALUE_MAX, "%u", old_open);
	*old_open_addr = old_open;
	LOGD("[+] just for test print old_open address %p\n", *old_open_addr);
//	snprintf(value, PROPERTY_VALUE_MAX, "%u", new_open);
	*new_open_addr = new_open;
	LOGD("[+] just for test print new_open address %p\n", *new_open_addr);

	//get close function address
	*old_close_addr = old_close;
	LOGD("[+] just for test print old_close address %p\n", *old_close_addr);
	*new_close_addr = new_close;
	LOGD("[+] just for test print new_close address %p\n", *new_close_addr);

	return 0;
}

/*
 * 密钥获取接口
 */
char *get_key(int key_length) {
	char *key = "1234567890A";
	return key;
}

/*
 * 读取配置，获得选取的加解密模式
 */
enum crypt get_crypt_config(char *config_name) {
	return Aes_192_ofb;
}

/*
 * 初始化加密上下文
 * 初始化成功返回	1，初始化失败返回	-1
 */
int encrypt_init(EVP_CIPHER_CTX *ctx) {
	int ret, key_len, i;
	const EVP_CIPHER *cipher;
	unsigned char iv[8];

	/*	向量初始化，此步骤为清零代替	*/
	for (i = 0; i < 8; i++) {
		memset(&iv[i], i, 1);
	}
	const char *key = get_key(key_len);

	/*
	 *加密初始化函数，本函数调用具体算法的 init 回调函数，将外送密钥 key 转换为内部密钥形式，
	 *加密初始化函数，本函数调用具体算法的 将初始化向量iv 拷贝到ctx 结构中。
	 */
	EVP_CIPHER_CTX_init(ctx);

	/*	读取加解密配置,返回一个EVP_CIPHER 	*/
//	cipher = EVP_enc_null();
	enum crypt ciphername;
	ciphername = get_crypt_config("xml");
	switch (ciphername) {
	case Aes_256_ofb:
		cipher = EVP_aes_256_ofb();
		break;
	case Aes_192_ofb:
		cipher = EVP_aes_192_ofb();
		break;
	case Aes_128_ofb:
		cipher = EVP_aes_128_ofb();
		break;
	case Des_ede_ofb:
		cipher = EVP_des_ede_ofb();
		break;
	case Des_ede3_ofb:
		cipher = EVP_des_ede3_ofb();
		break;
	case Rc2_ofb:
		cipher = EVP_rc2_ofb();
		break;
	case Bf_ofb:
		cipher = EVP_bf_ofb();
		break;
	case Enc_null:
	default:
		cipher = EVP_enc_null();
		break;

	}
	ret = EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
	if (ret != 1) {
		LOGD("EncryptInit err!\n");
		return -1;
	}
	return 1;
}
/*
 * 抽象加密函数
 * 加密成功则返回密文长度
 * 加密失败则返回-1
 */
int encrypt_abstract(const char *plaintext_path, EVP_CIPHER_CTX *ctx,
		const char *ciphertext_path) {
	int bytes_read, bytes_write, i;
	int from_fd, to_fd;
	unsigned char in[BUFFER_SIZE], out[BUFFER_SIZE];
	for (i = 0; i < BUFFER_SIZE; i++) {
		in[i] = '\0';
	}
	int inl = BUFFER_SIZE;
	int outl = 0;
	int len = 0;

	/*	打开明文路径文件和创建要存放的密文路径的文件	*/
	from_fd = (*old_open)(plaintext_path, O_RDONLY, 0);
	to_fd = (*old_open)(ciphertext_path, O_WRONLY | O_CREAT | O_TRUNC);
	if (from_fd < 0) {
		LOGD("Unable to open file %s", plaintext_path);
		return -1;
	} else if (to_fd < 0) {
		LOGD("Unable to open file %s", ciphertext_path);
		return -1;
	}

	/*
	 * 采用openssl的EVP模式进行加解密
	 * EVP_EncryptUpdate 加密函数，用于多次计算，它调用了具体算法的do_cipher回调函数。
	 * EVP_EncryptFinal 获取加密结果，函数可能涉及填充，它调用了具体算法的do_cipher回调函数。
	 */
	int final = 0;
	while (bytes_read = read(from_fd, in, BUFFER_SIZE)) {
//		LOGD("bytes_read:%d\n", bytes_read);
		if ((bytes_read == -1) && (errno != EINTR)) {
			printf("Error\n");
			break;
		} else if (bytes_read == BUFFER_SIZE) {
//			LOGD("read bytes :\n%s\n", in);
			EVP_EncryptUpdate(ctx, out, &outl, in, inl);
			len += outl;
		} else if ((bytes_read < BUFFER_SIZE) && len == 0) {
//			LOGD("short read:\n%s\n", in);
			EVP_EncryptUpdate(ctx, out, &outl, in, inl);
			len += outl;
			EVP_EncryptFinal_ex(ctx, out + len, &outl);
			len += outl;
		} else if ((bytes_read == 1) && len != 0) {
			final = 1;
//			LOGD("256 read:\n%s\n", in);
			EVP_EncryptFinal_ex(ctx, out, &outl);
			len += outl;
		} else {
//			LOGD("final read:\n%s\n", in);
			EVP_EncryptUpdate(ctx, out, &outl, in, inl);
			len += outl;
			EVP_EncryptFinal_ex(ctx, out, &outl);
			len += outl;
		}
		if (final != 1)
			bytes_write = write(to_fd, out, BUFFER_SIZE);

		/*防止缓冲区未清零，对读取的干扰*/
		memset(out, '\0', sizeof(char) * BUFFER_SIZE);
		memset(in, '\0', sizeof(char) * BUFFER_SIZE);
	}

	(*old_close)(from_fd);
	(*old_close)(to_fd);

	/*
	 * 清除对称算法上下文数据，它调用用户提供的销毁函数销清除存中的内部密钥以及其他数据。
	 */
	EVP_CIPHER_CTX_cleanup(ctx);
	LOGD("加密结果长度：%d\n", len);
	return len;
}

/*
 * 初始化解密上下文
 */
int decrypt_init(EVP_CIPHER_CTX *ctx) {
	int ret, key_len, i;
	const EVP_CIPHER *cipher;
	unsigned char iv[8];
	for (i = 0; i < 8; i++) {
		memset(&iv[i], i, 1);
	}
	const char *key = get_key(key_len);
	EVP_CIPHER_CTX_init(ctx);
	enum crypt ciphername;
	ciphername = get_crypt_config("xml");
	switch (ciphername) {
	case Aes_256_ofb:
		cipher = EVP_aes_256_ofb();
		break;
	case Aes_192_ofb:
		cipher = EVP_aes_192_ofb();
		break;
	case Aes_128_ofb:
		cipher = EVP_aes_128_ofb();
		break;
	case Des_ede_ofb:
		cipher = EVP_des_ede_ofb();
		break;
	case Des_ede3_ofb:
		cipher = EVP_des_ede3_ofb();
		break;
	case Rc2_ofb:
		cipher = EVP_rc2_ofb();
		break;
	case Bf_ofb:
		cipher = EVP_bf_ofb();
		break;
	case Enc_null:
	default:
		cipher = EVP_enc_null();
		break;

	}
	ret = EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
	if (ret != 1) {
		LOGD("EVP_DecryptInit_ex err1!\n");
		return -1;
	}
}

/*
 * 抽象解密函数
 * 解密成功则返回密文长度
 * 解密失败则返回-1
 */
int decrypt_abstract(const char *plaintext_path, EVP_CIPHER_CTX *ctx,
		const char *ciphertext_path) {
	int bytes_read, bytes_write, i;
	int to_fd, de_fd;
	unsigned char in[BUFFER_SIZE], de[BUFFER_SIZE];
	for (i = 0; i < BUFFER_SIZE; i++) {
		in[i] = '\0';
	}
	int inl = BUFFER_SIZE;
	int outl = 0;
	int len = 0;

	/*	打开明文路径文件和创建要存放的密文路径的文件	*/
	to_fd = (*old_open)(ciphertext_path, O_RDONLY, 0);
	de_fd = (*old_open)(plaintext_path, O_WRONLY | O_CREAT | O_TRUNC);
	if (de_fd < 0) {
		LOGD("Unable to open file %s", plaintext_path);
		return -1;
	} else if (to_fd < 0) {
		LOGD("Unable to open file %s", ciphertext_path);
		return -1;
	}
	memset(in, 0, sizeof(char) * BUFFER_SIZE);
	while (bytes_read = read(to_fd, in, BUFFER_SIZE)) {
//		LOGD("bytes_read:%d\n", bytes_read);
		if ((bytes_read == -1) && (errno != EINTR)) {
//			LOGD("Error\n");
			break;
		} else if (bytes_read == BUFFER_SIZE) {
//			LOGD("read bytes : %s\n", in);
			EVP_DecryptUpdate(ctx, de, &outl, in, inl);
			len += outl;
		} else if ((bytes_read < BUFFER_SIZE) && len == 0) {
//			LOGD("short read:\n%s\n", in);
			EVP_DecryptUpdate(ctx, de, &outl, in, inl);
			len += outl;
			EVP_DecryptFinal_ex(ctx, de + len, &outl);
			len += outl;
		} else {
			EVP_DecryptFinal_ex(ctx, de, &outl);
			len += outl;
		}
//		LOGD("the decrypt:\n%s\n", de);
		bytes_write = write(de_fd, de, BUFFER_SIZE);
		memset(de, '\0', sizeof(char) * BUFFER_SIZE);
		memset(in, '\0', sizeof(char) * BUFFER_SIZE);
	}

	(*old_close)(de_fd);
	(*old_close)(to_fd);
	LOGD("解密结果长度：%d\n", len);
	EVP_CIPHER_CTX_cleanup(ctx);

	return len;
}

/*
 * 在配置文件中查找是否该路径为加密信息
 */
int check_path(const char* path) {
	if (path == NULL)
		return -1;
	const char* to_path = "/mnt/sdcard/owncloud/admin@192.168.111.11/test.txt";
	if (strcmp(to_path, path) == 0)
		return 1;
	else
		return -1;
}

/*
 * 生成临时文件路径
 * 输入形如：/mnt/sdcard/owncloud/admin@192.168.111.11/test.txt
 * 输出临时文件路径：/mnt/sdcard/owncloud/.tmp/.mnt_sdcard_owncloud_admin@192.168.111.11_test.txt
 */
char* create_tmpfile(const char* path) {
	int len = strlen(path);
	char *input = (char *) malloc(len + 1);
	char prepath[] = "/mnt/sdcard/owncloud/.tmp/.";
	char *output = (char *) malloc(len + strlen(prepath) + 1);

	char tmppath[] = "/mnt/sdcard/owncloud/.tmp";

	/* 生成临时目录 */
	mkdir(tmppath, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

	/* 初始化 */
	memset(input, '\0', sizeof(char) * (len + 1));
	memset(output, '\0', sizeof(char) * (len + strlen(prepath) + 1));

	strcpy(input, path);
	strcat(output, prepath);

	char *p = strtok(input, "/");
	strcat(output, p);
	while ((p = strtok(NULL, "/"))) {
		printf("%s\n", p);
		strcat(output, "_");
		strcat(output, p);

	}
//	open(output, O_WRONLY | O_CREAT | O_TRUNC);
	free(input);
	return output;
}

/*
 * 由临时文件路径恢复为真实文件路径
 * 输出形如：/mnt/sdcard/owncloud/admin@192.168.111.11/test.txt
 * 输入临时文件路径：/mnt/sdcard/owncloud/.tmp/.mnt_sdcard_owncloud_admin@192.168.111.11_test.txt
 */
char* recover_tmpfile(const char* path) {
	int len = strlen(path);
	char *input = (char *) malloc(len + 1);
	char prepath[] = "/";
	char *output = (char *) malloc(len + strlen(prepath) + 1);

	/* 初始化 */
	memset(input, '\0', sizeof(char) * (len + 1));
	memset(output, '\0', sizeof(char) * (len + strlen(prepath) + 1));

	strcpy(input, path);
	strcat(output, prepath);

	char *check = strstr(input, "/mnt/sdcard/owncloud/.tmp/");
	if (check == NULL)
		return NULL;

	char *p = strtok(input, "_");
	strcat(output, "mnt");
	printf("%s\n", p);
	while ((p = strtok(NULL, "_"))) {
		strcat(output, "/");
		strcat(output, p);
	}

	free(input);
	return output;
}
