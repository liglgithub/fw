#ifndef _FW_INIT_H_
#define _FW_INIT_H_

#define FW_PID_FILE 			"/var/run/fw.pid"
const char *fwcmd;
const char *fw6cmd;
int fwinit_init(void);
void fw_reload(void);
int fwinit_exit(void);

#endif /*FW_INIT_H_*/
