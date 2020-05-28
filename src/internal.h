#ifndef _INTERNAL_H_
#define _INTERNAL_H_

#define STR1(R)				#R
#define STR(MARCO)			STR1(MARCO)	

#define IN_LOG_ACCEPT_QUEUE_NUM		100
#define IN_LOG_DROP_QUEUE_NUM		101
#define OUT_LOG_ACCEPT_QUEUE_NUM	200
#define OUT_LOG_DROP_QUEUE_NUM		201

//firewall table and chain
#define FW_TABLE			"raw"
#define FW_TABLE_SELF_INPUT_CHAIN	"PREROUTING"
#define FW_TABLE_SELF_OUTPUT_CHAIN	"OUTPUT"
#define FW_CMD_INPUT_CHAIN		"INPUT"
#define FW_CMD_OUTPUT_CHAIN		FW_TABLE_SELF_OUTPUT_CHAIN
#define FW_USER_DEFINED_INPUT_CHAIN	"PRE_INPUT"
#define FW_USER_DEFINED_OUTPUT_CHAIN	"PRE_OUTPUT"
#define IPTABLESPATH1			"/sbin/iptables"
#define IPTABLESPATH2			"/usr/sbin/iptables"
#define IP6TABLESPATH1			"/sbin/ip6tables"
#define IP6TABLESPATH2			"/usr/sbin/ip6tables"

#define IN_LOG_ACCEPT_TARGET		"NFQUEUE --queue-num "STR(IN_LOG_ACCEPT_QUEUE_NUM)" --queue-bypass"	
#define IN_LOG_DROP_TARGET		"NFQUEUE --queue-num "STR(IN_LOG_DROP_QUEUE_NUM)" --queue-bypass"
#define OUT_LOG_ACCEPT_TARGET		"NFQUEUE --queue-num "STR(OUT_LOG_ACCEPT_QUEUE_NUM)" --queue-bypass"
#define OUT_LOG_DROP_TARGET		"NFQUEUE --queue-num "STR(OUT_LOG_DROP_QUEUE_NUM)" --queue-bypass"


extern int force_exit;

#endif /*_INTERNAL_H_*/ 
