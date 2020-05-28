/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  firewall main
 *
 *        Version:  1.0
 *        Created:  04/18/2020 02:34:48 PM
 *       Revision:  none
 *       Compiler:  gcc
 *        License:  GNU GENERAL PUBLIC LICENSE Version 2 
 *
 *         Author:  liguoliang
 *          Email:  397543611@qq.com
 *
 * =====================================================================================
 */
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include "fwdb.h"
#include "fwcb.h"
#include "fwutil.h"
#include "fwserv.h"
#include "fwrule.h"
#include "fwlog.h"
#include "fwlogger.h"
#include "fwinit.h"

int force_exit;
static sigset_t block_sigset;


static void usage(int argc ,char **argv)
{
	{(void)argc;}
	printf("%s option:\n"
			"\t [-d] \t\t daemon \n"
			"\t [-l <1~6>] \t log level\n"
			"\t [-h] \t\t print this help information\n"
			,argv[0]);
}

static void sig_handler(int signum)
{
	switch(signum)
	{
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
			force_exit = 1;
			break;
		case SIGHUP:
			fw_reload();
			break;
		default:
			break;
	}
}

static int signal_init(void)
{
	sigemptyset(&block_sigset);
	sigaddset(&block_sigset, SIGINT);
	sigaddset(&block_sigset, SIGQUIT);
	sigaddset(&block_sigset, SIGTERM);
	sigaddset(&block_sigset, SIGHUP);
	if (pthread_sigmask(SIG_BLOCK, &block_sigset, NULL) != 0)
	{
		return -1;
	}
	return 0;
}

int parse_args(int argc, char **argv)
{
	int opt = 0;
	while ((opt = getopt(argc, argv, "dl:h")) != -1)
	{
		switch (opt)
		{
			case 'd':
				daemon(0,0);
				break;
			case 'l':
				if(fwlogger_set_level(atoi(optarg))<0) {
					usage(argc, argv); return -1;
				}
				break;
			case 'h':
				usage(argc, argv);
				exit(0);
			default:
				usage(argc, argv);
				return -1;
		}
	}
	return 0;
}

static int ensure_single_process(void)
{
	return single_process (FW_PID_FILE);
}

static void fw_init(void)
{
	if(fwdb_init() ||
			fwinit_init() ||
			fwlogger_init() ||
			fwlog_init() ||
			fwcb_init() ||
			fwserv_init() )
	{
		FWLOG_ERROR("fw init error");
		exit(1);
	}
	FWLOG_INFO("fw start");
	fw_setThreadName("fwmain");
}

static void fw_exit(void)
{
	FWLOG_INFO("fw exit");
	fwserv_exit();
	fwcb_exit();
	fwlog_exit();
	fwlogger_exit();
	fwinit_exit();
	fwdb_exit();
}

int main(int argc, char **argv)
{
	siginfo_t  info;
	{(void)argc;}
	if(parse_args(argc,argv) < 0 || 
		signal_init() < 0 || 
		fw_get_install_path() < 0 ||
		ensure_single_process()<0)
	{
		return -1;
	}

	fw_init();

	while(!force_exit)
	{
		if(sigwaitinfo(&block_sigset, &info) > 0)
		{
			sig_handler(info.si_signo);
		}
	}

	fw_exit();
	exit(0);
}
