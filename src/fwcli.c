/*
 * =====================================================================================
 *
 *       Filename:  fwcli.c
 *
 *    Description:  fwcli main
 *
 *        Version:  1.0
 *        Created:  05/20/2020 12:04:08 PM
 *       Revision:  none
 *       Compiler:  gcc
 *        License:  GNU GENERAL PUBLIC LICENSE Version 2
 *
 *         Author:  liguoliang
 *          Email:  397543611@qq.com
 *
 * =====================================================================================
 */
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include "fwtlv.h"
#include "fwutil.h"

#define NAME "etc/.fw.ipc"

static void usage(int argc ,char **argv)
{
	{(void)argc;}
	printf("%s option:\n"
			"\t [-l<1~6>] \t log level\n"
			"\t [-x] \t\t reload rule from xml file\n"
			"\t [-r] \t\t reload rule from database\n"
			"\t [-e] \t\t firewall exit\n"
			"\t [-h] \t\t print this help information\n",argv[0]);
}


static int conn_serv(void)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr,"error socket\n");
		goto done;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path),"%s%s",installPath,NAME);

	if(connect(fd, (struct sockaddr*)&addr, sizeof(addr))<0)
	{
		close(fd);
		fd = -1;
		fprintf(stderr,"error connect:%s\n",NAME);
	}
done:
	return fd; 
}


static int write_serv(int fd, uint8_t *buf)
{
	return write(fd, buf, sizeof(fwtlv)+MSGLEN(buf));
}

int do_command(int argc, char **argv)
{
	int fd;
        int opt = 0;
	uint16_t *pu16;
	uint8_t buf[1024]={0};
	MSGTAG(buf) = FW_MAX_TAG;

	opterr = 0;
        while ((opt = getopt(argc, argv, "l:xreh")) != -1)
        {
                switch (opt)
                {
                        case 'l':
				MSGTAG(buf) = FW_LOG_LEVEL_SET;
				pu16=(uint16_t *)MSGVAL(buf);
				*pu16=atoi(optarg);
				//(*(uint16_t *)MSGVAL(buf)) = atoi(optarg);
				MSGLEN(buf) = sizeof(uint16_t);
                                break;
                        case 'x':
				MSGTAG(buf) = FW_RELOAD_RULE_FROM_XML;
                                break;
                        case 'r':
				MSGTAG(buf) = FW_RELOAD_RULE_FROM_DB;
                                break;
                        case 'e':
				MSGTAG(buf) = FW_EXIT;
                                break;
                        case 'h':
                                usage(argc, argv);
                                exit(0);
                        default:
                                usage(argc, argv);
                                exit(-1);
                }
        }
	if(FW_MAX_TAG == MSGTAG(buf))
	{
		fprintf(stderr,"no command specified\n");
		usage(argc, argv);
		exit(1);
	}
	fd = conn_serv();
	write_serv(fd,buf);
	close(fd);
        return 0;
}

int main(int argc, char *argv[]) 
{
	if(fw_get_install_path()< 0)
	{
		fprintf(stderr,"get install path error\n");
		exit(1);
	}
	return do_command(argc, argv);
}
