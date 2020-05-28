#ifndef _FW_LOG_H_
#define _FW_LOG_H_
int fwlog_init(void);
ssize_t fwlog_write(int index,void *data, size_t count);
int fwlog_exit(void);
#endif /*_FW_LOG_H_*/
