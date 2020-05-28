#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "fwdb.h"
#include "fwutil.h"
#include "internal.h"
#include "fwlogger.h"

const char *fw4cmd;
const char *fw6cmd;
static int fw_clear(void)
{
	unsigned int i;
	char buf[2048]={0};
	const char *fwcmdarr[2]={fw4cmd, fw6cmd};
	const char *cmd;
	if(!fw4cmd)
		return -1;
	for(i=0;i<sizeof(fwcmdarr)/sizeof(char *);++i)
	{
		cmd = fwcmdarr[i];
		if(!cmd) continue;
		snprintf(buf, sizeof(buf),"%s -t %s -D %s -j %s > /dev/null 2>&1;"  //Delete rule that target is fw input chain 
				"%s -t %s -D %s -j %s > /dev/null 2>&1;"  //Delete rule that target is fw output chain
				"%s -t %s -F %s > /dev/null 2>&1;"        //Delete all rules in fw input chain
				"%s -t %s -X %s > /dev/null 2>&1;"        //Delete fw create input chain
				"%s -t %s -F %s > /dev/null 2>&1;"        //Delete all rules in fw output chain
				"%s -t %s -X %s > /dev/null 2>&1;"        //Delete fw create output chain
				,cmd,FW_TABLE,FW_TABLE_SELF_INPUT_CHAIN,FW_USER_DEFINED_INPUT_CHAIN 
				,cmd,FW_TABLE,FW_TABLE_SELF_OUTPUT_CHAIN,FW_USER_DEFINED_OUTPUT_CHAIN
				,cmd,FW_TABLE,FW_USER_DEFINED_INPUT_CHAIN 
				,cmd,FW_TABLE,FW_USER_DEFINED_INPUT_CHAIN 
				,cmd,FW_TABLE,FW_USER_DEFINED_OUTPUT_CHAIN 
				,cmd,FW_TABLE,FW_USER_DEFINED_OUTPUT_CHAIN);
		system(buf);
	}
	return 0;
}

/*
 *  iptables 
 *
 *
 */
static int fw_reset(void)
{
	unsigned int i;
	char buf[2048]={0};
	const char *fwcmdarr[2]={fw4cmd, fw6cmd};
	const char *cmd;
	if(!fw4cmd)
		return -1;
	fw_clear();

	for(i=0;i<sizeof(fwcmdarr)/sizeof(char *);++i)
	{
		cmd = fwcmdarr[i];
		if(!cmd) continue;
		snprintf(buf, sizeof(buf),"%s -t %s -N %s;"        //create fw input chain
				"%s -t %s -I %s -j %s;"  //add rule that target is fw input chain
				"%s -t %s -N %s;"        //create fw output chain
				"%s -t %s -I %s -j %s;"  //add rule that target is fw output chain
				,cmd,FW_TABLE,FW_USER_DEFINED_INPUT_CHAIN
				,cmd,FW_TABLE,FW_TABLE_SELF_INPUT_CHAIN,FW_USER_DEFINED_INPUT_CHAIN
				,cmd,FW_TABLE,FW_USER_DEFINED_OUTPUT_CHAIN
				,cmd,FW_TABLE,FW_TABLE_SELF_OUTPUT_CHAIN,FW_USER_DEFINED_OUTPUT_CHAIN);
		system(buf);
	}
	return 0;
}

void fw_reload(void)
{
	if(!fw_reset())
	fw_load_rule_from_db();
}

int fwinit_init(void)
{
	if(0==access(IPTABLESPATH1,F_OK))
	{
		fw4cmd = IPTABLESPATH1;
	}
	else if(0==access(IPTABLESPATH2,F_OK))
	{
		fw4cmd = IPTABLESPATH2;
	}
	else
	{
		FWLOG_ERROR("error not found iptables");
		return -1;
	}
	if(0==access(IP6TABLESPATH1,F_OK))
	{
		fw6cmd = IP6TABLESPATH1;
	}
	else if(0==access(IP6TABLESPATH2,F_OK))
	{
		fw6cmd = IP6TABLESPATH2;
	}
	fw_reload();
	return 0;
}

int fwinit_exit(void)
{
	return fw_clear();
}
