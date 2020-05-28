#ifndef _PARSE_H_
#define _PARSE_H_
#include "fwpkg.h"

int parse_ipv4(fwpkg *pkg,unsigned char *nf_packet,int packet_len);
int parse_ipv6(fwpkg *pkg,unsigned char *nf_packet,int packet_len);

#endif /*_PARSE_H_*/
