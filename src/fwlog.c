#define _GNU_SOURCE
#include <unistd.h>
#include <unistd.h> 	//fcntl
#include <fcntl.h>
#include <stdio.h>  	//perror
#include <pthread.h>
#include <sys/epoll.h>
#include <stdlib.h>   	//exit
#include "internal.h"
#include "fwdb.h"
#include "fwutil.h"
#include "fwlogger.h"

#define EPOLL_TIMEOUT 	1000
#define EPOLL_MAXEVENTS 1
#define TRANSACTION_NUM 200

static pthread_t thread_thid[4];
fwpkg pkgarr[4][TRANSACTION_NUM];
int pipe_wlog[4];
int pipe_rlog[4];



static int pipe_init(void)
{
	int i,m;
	int pipefd[2];
	for(i=0,m=0;i<4;++i,++m)
	{
		if(!pipe(pipefd) && 
			!make_socket_non_blocking (pipefd[0]) && 
			!make_socket_non_blocking (pipefd[1]))
		{
			
			pipe_rlog[m] = pipefd[0];
			pipe_wlog[m] = pipefd[1];
		}
		else
		{
			goto Error;
		}
	}
	return 0;
Error:
	for(m=0;m<i;++m)
	{
		close(pipe_rlog[m]);
		close(pipe_wlog[m]);
	}
	return -1;
}

static int pipe_exit(void)
{
	int i;
	for(i=0;i<4;++i)
	{
		close(pipe_rlog[i]);
		close(pipe_wlog[i]);
	}
	return 0;
}

static void *fwlog_thread(void *arg)
{
	int efd;
	sqlite3 *db;
	unsigned int count=0;
	int index = (intptr_t)arg;
	struct epoll_event event;
	struct epoll_event events[EPOLL_MAXEVENTS];
	fw_setThreadName("fwlog%d",index);
	if(!(db=fwdb_open()))
	{
		FWLOG_ERROR("fwlog db open error");
		exit(-1);
	}
	if((efd = epoll_create (1))< 0)
	{
		FWLOG_ERROR("epoll_create error");
		exit(-1);
	}
	
	event.data.fd = pipe_rlog[index];
	event.events = EPOLLIN | EPOLLET;
	if(epoll_ctl (efd, EPOLL_CTL_ADD, pipe_rlog[index], &event)<0)
	{
		FWLOG_ERROR("epoll_ctl error");
		exit(-1);
	}

	while(!force_exit)
	{
		int n,i;
		n = epoll_wait (efd, events, EPOLL_MAXEVENTS, EPOLL_TIMEOUT);
		if(!n)
		{
			if(count > 0)
			{
				fw_log_insert_into_db(&db,&pkgarr[index][0],count);
				count = 0;
			}
			continue;
		}
		for(i=0;i<n;++i)
		{
			ssize_t len;
			if ((events[i].events & EPOLLERR) ||
				(events[i].events & EPOLLHUP) ||
				(!(events[i].events & EPOLLIN)))
			{
				FWLOG_ERROR("epoll error");
				close (events[i].data.fd);
				exit(-2);
			}
			while((len = read (events[i].data.fd, &pkgarr[index][count], sizeof(fwpkg)))>0)	
			{
				if(++count == TRANSACTION_NUM )
				{
					fw_log_insert_into_db(&db,&pkgarr[index][0],count);
					count = 0;
				}
			}
		}
	}
	epoll_ctl(efd, EPOLL_CTL_DEL, pipe_rlog[index], NULL);
	close(efd);
	fwdb_close(db);
	return NULL;
}

ssize_t fwlog_write(int index,void *data, size_t count)
{
	int i;
	ssize_t len = -1;
	for(i=0; i<4 && len<0; ++i)
	{
		len=write(pipe_wlog[(index+i)%4], data, count);
	}
	return len;
}

int fwlog_init(void)
{
	int i;
	if(pipe_init())
		return -1;
	for(i=0;i<4;++i)
	{
		if(pthread_create(thread_thid + i, NULL, fwlog_thread, (void *)(intptr_t)i))
			return -1;
	}
	return 0;
}

int fwlog_exit(void)
{
	int i;
	for(i=0;i<4;++i)
	{
		if(pthread_join(thread_thid[i], NULL))
			return -1;
	}
	pipe_exit();
	return 0;
}
