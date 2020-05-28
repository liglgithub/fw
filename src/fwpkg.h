#ifndef _FW_PKG_H_
#define _FW_PKG_H_
#include <stdint.h>

typedef struct fwpkg
{
//network
#if __BYTE_ORDER == __LITTLE_ENDIAN
        uint8_t 	isinput:1;
        uint8_t 	isipv4:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
        uint8_t 	isipv4:1;
        uint8_t 	isinput:1;
#else
# error "Please fix <bits/endian.h>"
#endif
        uint8_t 	verdict;
        uint8_t	 	protocol3;	//no use
        uint8_t   	protocol4;	
        uint16_t  	sport;   	//type protocol4 = icmp
        uint16_t 	dport;	 	//type protocol4 = icmp
        uint32_t    	saddr[4];	//ipv4 use [0]
        uint32_t    	daddr[4];	//ipv4 use [0]
}fwpkg;

#endif  /*_FW_PKG_H_*/

