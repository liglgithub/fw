#include <stdio.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h> 	//inet_ntop

#include "fwpkg.h" 
#include "fwlogger.h" 

#define MAX_IPV4_STR_LEN 16
#define MAX_IPV6_STR_LEN 40

int parse_ipv4(fwpkg *pkg,unsigned char *nf_packet,int packet_len)
{
        struct iphdr *iph = ((struct iphdr *) nf_packet);
	if (ntohs(iph->frag_off) & IP_MF){
                printf("More Fragments \n");
		return -1;
	}
	if(packet_len < (iph->ihl<<2))
	{
		return -1;
	}

	//copy saddr daddr
	pkg->isipv4=1;
	pkg->saddr[0]=iph->saddr;
	pkg->daddr[0]=iph->daddr;
	//copy protocol
	pkg->protocol4 = iph->protocol;

        //fprintf(stdout,"Recibido con origen\n");


	if(iph->protocol == IPPROTO_TCP)
	{
		struct tcphdr *tcp = (struct tcphdr *)((unsigned char *)iph + (iph->ihl<<2));
		//copy sport dport
		pkg->sport = tcp->source;
		pkg->dport = tcp->dest;
	}
	else if(iph->protocol == IPPROTO_UDP)
	{
		struct udphdr *udp = (struct udphdr *)((unsigned char *)iph + (iph->ihl<<2));
		//copy sport dport
		pkg->sport = udp->source;
		pkg->dport = udp->dest;
	}
	else if(iph->protocol == IPPROTO_ICMP)
	{
		struct icmphdr *icmp = (struct icmphdr *)((unsigned char *)iph + (iph->ihl<<2));
		//copy type code 
		pkg->sport = icmp->type;
		pkg->dport = icmp->code;
	}

#ifdef DEBUG
	char *tmp1;
	char *tmp2;
	int  result1;
	int  result2;
        char saddr[MAX_IPV4_STR_LEN]={0};
	char daddr[MAX_IPV4_STR_LEN]={0};
	char *protocol=NULL;
        inet_ntop(AF_INET, &(iph->saddr), saddr, sizeof(saddr));
	inet_ntop(AF_INET, &(iph->daddr), daddr, sizeof(daddr));

	if(IPPROTO_ICMP == iph->protocol)
	{
		protocol = "ICMP";
		tmp1="type";
		tmp2="code";
		result1=pkg->sport;
		result2=pkg->dport;
	}
	else
	{
		if(IPPROTO_TCP == iph->protocol) protocol = "TCP";
		if(IPPROTO_UDP == iph->protocol) protocol = "UDP";
		tmp1="sport";
		tmp2="dport";
		result1=ntohs(pkg->sport);
		result2=ntohs(pkg->dport);
	}
	FWLOG_DEBUG("ipl:%d tot_len:%d frag_off:%d protocol:%s(%d) sourceip:%s destip:%s %s:%d %s:%d isdrop:%d\n",
			iph->ihl<<2,ntohs(iph->tot_len),ntohs(iph->frag_off)&IP_MF, protocol, iph->protocol, saddr,daddr,tmp1,result1, 
			tmp2,result2,pkg->verdict);
	FWLOG_DEBUG("saddr %u daddr %u\n",iph->saddr,iph->daddr);
#endif
	return 0;
}

int parse_ipv6(fwpkg *pkg,unsigned char *nf_packet,int packet_len)
{
	size_t len=packet_len;
	unsigned char *pos=nf_packet;
	struct ip6_hdr *ip6h=((struct ip6_hdr *) nf_packet);
	struct ip6_ext *ip6e;
	struct icmphdr *icmp;
	struct icmp6_hdr *icmp6;
	struct tcphdr *tcp;
	struct udphdr *udp;
	int next_header;
	int rc=0;

	if (len < sizeof(struct ip6_hdr)) {
		fprintf(stderr, "Error parsing IPv6 packet. Packet is too small (%zu of %lu bytes)",
			len, sizeof(struct ip6_hdr));
		return -2;
	}

	len -= sizeof(struct ip6_hdr);
	pos += sizeof(struct ip6_hdr);

	memcpy(pkg->saddr,&ip6h->ip6_src,sizeof(pkg->saddr));
	memcpy(pkg->daddr,&ip6h->ip6_dst,sizeof(pkg->daddr));
#ifdef DEBUG
        char saddr[MAX_IPV6_STR_LEN]={0};
	char daddr[MAX_IPV6_STR_LEN]={0};
	inet_ntop(AF_INET6, &(ip6h->ip6_src), saddr, sizeof(saddr));
	inet_ntop(AF_INET6, &(ip6h->ip6_dst), daddr, sizeof(daddr));
#endif

	next_header = ip6h->ip6_nxt;
	// Skip IPv6 extension headers
	while (next_header != -1) {
		switch (next_header) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_FRAGMENT:
		case IPPROTO_DSTOPTS:
			if (len < 8) {
				fprintf(stderr, "Error parsing IPv6 packet. Extension header is too small (%zd of %d bytes)",
					len, 8);
				return -2;
			}
			ip6e = (struct ip6_ext *)pos;
			if (len < (size_t)(ip6e->ip6e_len + 1) * 8) {
				fprintf(stderr, "Error parsing IPv6 packet. Extension header is too small (%zd of %d bytes)",
					 len, (ip6e->ip6e_len + 1) * 8);
				return -2;
			}
			pos += (ip6e->ip6e_len + 1) * 8;
			len -= (ip6e->ip6e_len + 1) * 8;
			next_header = ip6e->ip6e_nxt;
			break;
		case IPPROTO_TCP:
			if(len < sizeof(struct tcphdr ))
				return -2;
			tcp = (struct tcphdr *)(pos);
			//copy sport dport
			pkg->sport = tcp->source;
			pkg->dport = tcp->dest;
			pkg->protocol4 = next_header;
#ifdef DEBUG
			fprintf(stdout,"ipv6 tcp saddr%s daddr%s sport:%d dport:%d\n",saddr, daddr,ntohs(pkg->sport),ntohs(pkg->dport));
#endif
			return 0;
			break;
		case IPPROTO_UDP:
			if(len < sizeof(struct udphdr ))
			{
				fprintf(stderr, "Error parsing IPv6 packet. UDP header is too small (%zd of %lu bytes)",
						 len, sizeof(struct udphdr ));
				return -2;
			}
			udp = (struct udphdr *)(pos);
			//copy sport dport
			pkg->sport = udp->source;
			pkg->dport = udp->dest;
			pkg->protocol4 = next_header;
#ifdef DEBUG
			fprintf(stdout,"ipv6 udp saddr%s daddr%s sport:%d dport:%d\n",saddr, daddr,ntohs(pkg->sport),ntohs(pkg->dport));
#endif
			return 0;
			break;
		case IPPROTO_ICMP:
			if(len < sizeof(struct icmphdr))
				return -2;
			icmp = (struct icmphdr *)pos;
			pkg->sport = icmp->type;
			pkg->dport = icmp->code;
			pkg->protocol4 = next_header;
#ifdef DEBUG
			fprintf(stdout,"ipv6 icmp  saddr%s daddr%s type:%d code:%d\n",saddr, daddr,pkg->sport,pkg->dport);
#endif
			return 0;
			break;
		case IPPROTO_ICMPV6:
			if(len < sizeof(struct icmp6_hdr))
				return -2;
			icmp6 = (struct icmp6_hdr *)pos;
			pkg->sport = icmp6->icmp6_type;
			pkg->dport = icmp6->icmp6_code;
			pkg->protocol4 = next_header;
#ifdef DEBUG
			fprintf(stdout,"icmpv6 saddr%s daddr%s type:%d code:%d\n",saddr, daddr,pkg->sport,pkg->dport);
#endif
			return 0;
			break;
		default:
			next_header = -1;
			break;
		}
	}

	if (next_header == -1) {
		return -1;
	}
	return rc;
}
