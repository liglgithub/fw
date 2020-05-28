#include <stdio.h>
#include <stdarg.h>
#include <sys/prctl.h>
#include <sys/time.h>	  //setpriority
#include <sys/resource.h> //setpriority
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define read_lock(fd, offset, whence, len) \
                 lock_reg(fd, F_SETLK, F_RDLCK, offset, whence, len)
#define readw_lock(fd, offset, whence, len) \
                 lock_reg(fd, F_SETLKW, F_RDLCK, offset, whence, len)
#define write_lock(fd, offset, whence, len) \
                 lock_reg(fd, F_SETLK, F_WRLCK, offset, whence, len)
#define writew_lock(fd, offset, whence, len) \
                 lock_reg(fd, F_SETLKW, F_WRLCK, offset, whence, len)
#define un_lock(fd, offset, whence, len) \
                 lock_reg(fd, F_SETLK, F_UNLCK, offset, whence, len)

char *installPath;

int make_socket_non_blocking (int fd)
{
	int flags, s;

	flags = fcntl (fd, F_GETFL, 0);
	if (flags == -1)
	{
		perror ("fcntl");
		return -1;
	}

	flags |= O_NONBLOCK;
	s = fcntl (fd, F_SETFL, flags);
	if (s == -1)
	{
		perror ("fcntl");
		return -1;
	}

	return 0;
}

int fw_setThreadName(const char *fmt,...)
{
	va_list ap;
	#define MAX_NAME_LEN 16
	char name[MAX_NAME_LEN]={0};
	#undef MAX_NAME_LEN
	
	va_start(ap, fmt);
	vsnprintf(name, sizeof(name), fmt, ap);
	va_end(ap);
	
	return prctl(PR_SET_NAME, name);
}

int fw_setThreadPriority(int prio)
{
	if(prio < -20 || prio > 19)
		return -1;
	return setpriority(PRIO_PROCESS, 0, prio);
}


int fw_get_install_path(void)
{
	char *p;
	char *pnext;
	char prog_path[1024] = {'\0'};
	char proc_self_exe[16] = {'\0'};
	char proc_name[48] = {'\0'};

	if(installPath)
		return 0;
	snprintf(proc_self_exe, sizeof(proc_self_exe) , "/proc/self/exe");
	if(readlink(proc_self_exe, prog_path, sizeof(prog_path)) < 0)
		return -1;

	p = strrchr(prog_path, '/');
	if(!p)
		return -1;
	snprintf(proc_name, sizeof(proc_name),"/bin%s",p);
	p = prog_path;
	while((pnext = strstr(p, proc_name)))
	{
		p = ++pnext;
	}
	if(p == prog_path)
		return -1;
	*p = '\0';
	p = strdup(prog_path);
	if(__sync_val_compare_and_swap(&installPath, NULL,p))
	{
		free(p);
	}
	return 0; 	
}

int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
    struct flock    lock;

    lock.l_type = type;             /* F_RDLCK, F_WRLCK, F_UNLCK */
    lock.l_start = offset;          /* byte offset, relative to l_whence */
    lock.l_whence = whence;         /* SEEK_SET, SEEK_CUR, SEEK_END */
    lock.l_len = len;               /* #bytes (0 means to EOF) */

    return( fcntl(fd, cmd, &lock) );
}

int single_process (const char *pidfile)
{
	int     fd;
	int     pid;
	char    buf[10];

	if ( (fd = open(pidfile, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0)
	{
		printf(" open error for pid file : %s error:%s\n", pidfile, strerror(errno));
		exit(-1);
	}
	/* try and set a write lock on the entire file */
	if (write_lock(fd, 0, SEEK_SET, 0) < 0)
	{
		if (errno == EACCES || errno == EAGAIN)
		{
			/* gracefully exit, daemon is already running */
			close(fd);
			printf("daemon is already running\n");
			return -1;
		}
		else
		{
			printf("pidfile %s write_lock error:%s\n ",pidfile, strerror(errno));
			exit(-1);
		}
	}

	/* truncate to zero length, now that we have the lock */
	if (ftruncate(fd, 0) < 0)
	{
		printf(" ftruncate error for pidfile %s :%s\n ", pidfile, strerror(errno));
		exit(-1);
	}

	/* and write our process ID */
	snprintf(buf, sizeof buf, "%d\n", pid=getpid());
	if (write(fd, (void *)buf, strlen(buf)) != (ssize_t)strlen(buf))
	{
		printf(" write error for pidfile %s :%s\n ", pidfile, strerror(errno));
		exit(-1);
	}
	return fd;
}

