#ifndef _FW_UTIL_H_
#define _FW_UTIL_H_

#ifdef __cplusplus
	extern "C" {
#endif


char *installPath;

int make_socket_non_blocking (int fd);
int fw_setThreadName(const char *fmt,...);
int fw_setThreadPriority(int prio);
int fw_get_install_path(void);
int single_process (const char *pidfile);

#ifdef __cplusplus
}
#endif

#endif /*_FW_UTIL_H_*/
