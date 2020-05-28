#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/types.h>  //kill
#include <signal.h>	//kill

#include "internal.h"
#include "fwutil.h"
#include "fwlogger.h"
#include "fwtlv.h"
#include "fwrule.h"
#include "fwinit.h"

#define NAME ".fw.ipc"
#define EPOLL_MAXEVENTS 	1
#define EPOLL_TIMEOUT 		1000
#define READ_WRITE_TIMEOUT 	3

static pthread_t fwserv_thid;

static void fw_log_level_set(void *arg)
{
	FWLOG_DEBUG("set log level %u",*(uint16_t *)arg);
	fwlogger_set_level(*(uint16_t *)arg);
}

static void fw_log_reload_rule_from_xml()
{
	 load_fw_rule_from_xml();
}

static int set_rw_timeout(int sockfd, int timeout)
{
	struct timeval    tval;
	tval.tv_sec = timeout;
	tval.tv_usec = 0;
	return setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,&tval,sizeof(tval)) ||
		setsockopt(sockfd,SOL_SOCKET,SO_SNDTIMEO,&tval,sizeof(tval));
}

static int parse_cmd(int connfd)
{
	ssize_t len=0;
	size_t rlen=2*sizeof(uint16_t);
	int flags = MSG_PEEK|MSG_WAITALL;
	char buf[4096]={'\0'};

	if(set_rw_timeout(connfd, READ_WRITE_TIMEOUT)<0)
	{
		FWLOG_ERROR("set read write timeout error");
		return -1;
	}

	do
	{
		len=recv(connfd, buf, rlen, flags);
		FWLOG_DEBUG("len:%ld errno:%d Tag:%d Length:%d",len,errno,MSGTAG(buf),MSGLEN(buf));
		if(len < 0 || (size_t)len <  rlen)
		{
			FWLOG_ERROR("recv error");
			return -1;
		}
		if(flags & MSG_PEEK)
		{
			rlen += MSGLEN(buf);
			flags &= ~MSG_PEEK;
		}
		else
		{
			flags = 0;
		}
	}while(flags);

	switch(MSGTAG(buf))
	{
		case FW_LOG_LEVEL_SET:
			fw_log_level_set(MSGVAL(buf));
			break;
		case FW_RELOAD_RULE_FROM_XML:
			fw_log_reload_rule_from_xml();
			break;
		case FW_RELOAD_RULE_FROM_DB:
			FWLOG_DEBUG("reload rule from DB");
			fw_reload();
			break;
		case FW_EXIT:
			kill(getpid(),SIGQUIT);
			break;
		default:
			FWLOG_ERROR("unknown tag");
			break;
	}
	return 0;	
}

static int do_cmd(int sockfd)
{
	int connfd;
	while(!force_exit)
	{
		if((connfd = accept(sockfd, NULL, NULL)) < 0)
		{
			if(EAGAIN == errno ||  EWOULDBLOCK == errno)
				return 0;
			char buf[256]={'\0'};
			strerror_r(errno, buf, sizeof(buf));
			FWLOG_ERROR("accept error:%s",buf);
			return -1;
		}
		parse_cmd(connfd);
		close(connfd);
	}
	return 0;
}

int create_server(void)
{
    int sock;
    struct sockaddr_un server;


    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
	char buf[256]={'\0'};
	strerror_r(errno, buf, sizeof(buf));
	FWLOG_ERROR("opening stream socket:%s",buf);
        exit(1);
    }

    server.sun_family = AF_UNIX;
    snprintf(server.sun_path, sizeof(server.sun_path),"%setc/%s",installPath,NAME);
    unlink(server.sun_path);
    if (bind(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un))) {
	char buf[256]={'\0'};
	strerror_r(errno, buf, sizeof(buf));
	FWLOG_ERROR("binding stream socket:%s",buf);
        exit(1);
    }
    FWLOG_DEBUG("Socket has name %s", server.sun_path);
    listen(sock, 5);
    return sock;
}

static void *serv_thread(void *arg)
{
	int efd;
	int server_sock;
	struct epoll_event event;
        struct epoll_event events[EPOLL_MAXEVENTS];
	{(void)arg;}
	fw_setThreadName("fwserv");

	server_sock = create_server();
	if(make_socket_non_blocking (server_sock)<0)
	{
		FWLOG_ERROR("set socket non blocking error");
                exit(-1);
	}
	if((efd = epoll_create (1))< 0)
        {
		FWLOG_ERROR("epoll_create error");
                exit(-1);
        }
        event.data.fd = server_sock;
        event.events = EPOLLIN | EPOLLET;
        if(epoll_ctl (efd, EPOLL_CTL_ADD, server_sock, &event)<0)
        {
		FWLOG_ERROR("epoll_ctl error");
                exit(-1);
        }

	while(!force_exit)
	{
		int n,i;
		if(!(n = epoll_wait (efd, events, EPOLL_MAXEVENTS, EPOLL_TIMEOUT)))
		{
			continue;
		}
		for(i=0;i<n;++i)
		{
			if ((events[i].events & EPOLLERR) ||
					(events[i].events & EPOLLHUP) ||
					(!(events[i].events & EPOLLIN)))
			{
				FWLOG_ERROR("epoll_wait error");
				close (events[i].data.fd);
				exit(-2);
			}
			do_cmd(events[i].data.fd);
		}
	}
	epoll_ctl(efd, EPOLL_CTL_DEL, server_sock, NULL);
        close(efd);
    	close(server_sock);
	{
		char buf[4096]={'\0'};
		snprintf(buf, sizeof(buf),"%setc/%s",installPath,NAME);
		unlink(buf);
	}
	return 0;
}

int fwserv_init(void)
{
	if(pthread_create(&fwserv_thid, NULL, serv_thread, NULL))
		return -1;
	return 0;
}

int fwserv_exit(void)
{
	if(pthread_join(fwserv_thid, NULL))
		return -1;
	return 0;
}
