#ifndef _FW_LOGGER_H_
#define _FW_LOGGER_H_

#define ZF_LOG_LEVEL ZF_LOG_DEBUG
#define ZF_LOG_TAG "fw"
#include "zf_log.h"

#define FWLOG_DEBUG(...) 	ZF_LOGD(__VA_ARGS__)
#define FWLOG_INFO(...) 	ZF_LOGI(__VA_ARGS__)
#define FWLOG_WARN(...) 	ZF_LOGW(__VA_ARGS__)
#define FWLOG_ERROR(...) 	ZF_LOGE(__VA_ARGS__)
#define FWLOG_FATAL(...)	ZF_LOGF(__VA_ARGS__)

int fwlogger_set_level(int level);
int fwlogger_init(void);
int fwlogger_exit(void);

#endif /*_FW_LOGGER_H_*/
