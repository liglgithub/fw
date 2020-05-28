#ifndef _FW_TLV_H_
#define _FW_TLV_H_
#include <stdint.h>

/* 
 * TLV
 *
 * T->Tag	uint16_t 
 * L->Length	uint16_t
 * v->Value	variable size
 *
 */

typedef struct fwtlv
{
	uint16_t tag;
	uint16_t len;
	uint8_t  val[0];
}__attribute__((__may_alias__)) fwtlv;

#define MSGTAG(buf)	(((fwtlv *)(buf))->tag)
#define MSGLEN(buf)	(((fwtlv *)(buf))->len)
#define MSGVAL(buf)	((void *)((fwtlv *)(buf))->val)

typedef enum
{
	FW_LOG_LEVEL_SET,
	FW_RELOAD_RULE_FROM_XML,
	FW_RELOAD_RULE_FROM_DB,
	FW_EXIT,
	FW_MAX_TAG
}FWTAG;


#endif /*_FW_TLV_H_*/
