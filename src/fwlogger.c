#include <stdio.h>
#include <stdlib.h>
#include "fwutil.h"
#include "fwlogger.h"
static FILE *g_log_file;

static void file_output_callback(const zf_log_message *msg, void *arg)
{
	(void)arg;
	*msg->p = '\n';
	fwrite(msg->buf, msg->p - msg->buf + 1, 1, g_log_file);
	fflush(g_log_file);
}

static int file_output_close(void)
{
	return fclose(g_log_file);
}

static int file_output_open(const char *const log_path)
{
	g_log_file = fopen(log_path, "a");
	if (!g_log_file)
	{
		FWLOG_WARN("Failed to open log file %s", log_path);
		return -1;
	}
	//atexit(file_output_close);
	zf_log_set_output_v(ZF_LOG_PUT_STD, 0, file_output_callback);
	if(!_zf_log_global_output_lvl)
		zf_log_set_output_level(ZF_LOG_INFO);
	return 0;
}

int fwlogger_set_level(int level)
{
	if(level < ZF_LOG_VERBOSE || level >ZF_LOG_FATAL)
		return -1;

	zf_log_set_output_level(level);
	return 0;
}


int fwlogger_init(void)
{
	char loggerfile[4096]={'\0'};
	snprintf(loggerfile,sizeof(loggerfile), "%s%s", installPath, "log/fwlog");
	return file_output_open(loggerfile);
}

int fwlogger_exit(void)
{
	return file_output_close();
}
