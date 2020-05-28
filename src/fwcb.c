#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <linux/netfilter.h>		
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "internal.h"
#include "fwlog.h"
#include "fwlogger.h"
#include "fwpkg.h"
#include "fwparse.h"
#include "fwutil.h"

#define  EPOLL_TIMEOUT   1000

extern int force_exit;
static int threadindex; 
static pthread_t firewall_thid[4];

const struct  NFQ_POLICY
{
	int   number;
	short action;
	short isinput;
}nfqPolicy[4]={	{IN_LOG_ACCEPT_QUEUE_NUM,NF_ACCEPT,1},
		{IN_LOG_DROP_QUEUE_NUM,NF_DROP,1},
		{OUT_LOG_ACCEPT_QUEUE_NUM,NF_ACCEPT,0},
		{OUT_LOG_DROP_QUEUE_NUM,NF_DROP,0}};
#if 0
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d ", ret);
		//processPacketData (data, ret);
	}
	fputc('\n', stdout);

	return id;
}
#endif
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
//	u_int32_t id = print_pkt(nfa);
	{(void )nfmsg;}
	int index = (intptr_t)data;
	unsigned char *nf_packet;

        int ret;
	u_int32_t id;
	fwpkg pkg ={0};

        struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);	
	id = ntohl(ph->packet_id);
	//printf("entering callback\n");

        ret = nfq_get_payload(nfa, &nf_packet);
        if ((ret <= 0))
        {
                FWLOG_ERROR("Error, no hay paquete que recibir - wtf ");
                return -1;
        }
	//input or output
	pkg.isinput = nfqPolicy[index].isinput;
	pkg.verdict = (nfqPolicy[index].action==NF_DROP);
	if(nf_packet[0]>>4==4)
		ret=parse_ipv4(&pkg,nf_packet,ret);
	else
		ret=parse_ipv6(&pkg,nf_packet,ret);
	if(!ret)
		fwlog_write(index, &pkg, sizeof(pkg));
	return nfq_set_verdict(qh, id, nfqPolicy[index].action, 0, NULL);
}

static void *firewall_thread(void *arg)
{
	int fd;
	int rv;
	int efd;
	struct epoll_event event;
        struct epoll_event events[1];

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int index = (intptr_t)arg;
	char buf[4096] __attribute__ ((aligned));
	fw_setThreadName("fwcb%d",index);
	fw_setThreadPriority(-20);

	while(!__sync_bool_compare_and_swap(&threadindex, index, index))
	{
		usleep(250);
	}
	if((efd = epoll_create (1))< 0)
        {
                FWLOG_ERROR("epoll_create");
                exit(-1);
        }


	FWLOG_DEBUG("opening library handle\n");
	h = nfq_open();
	if (!h) {
		FWLOG_ERROR("error during nfq_open()");
		exit(1);
	}

#if 0  //Linux kernels from 3.8 onwards ignore it.
	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}
#endif

	FWLOG_DEBUG("binding this socket to queue '%d'\n",nfqPolicy[index].number);
	qh = nfq_create_queue(h,  nfqPolicy[index].number, &cb, arg);
	if (!qh) {
		FWLOG_ERROR("error during nfq_create_queue()\n");
		exit(1);
	}

	//set queue length before start dropping packages
	nfq_set_queue_maxlen(qh, 4096);
	
	if(nfq_set_queue_flags(qh,NFQA_CFG_F_FAIL_OPEN,NFQA_CFG_F_FAIL_OPEN)<0)
	{
		FWLOG_ERROR("error during nfq_set_queue_flags()");
		exit(1);
	}
	
	FWLOG_DEBUG("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		FWLOG_ERROR("can't set packet_copy mode");
		exit(1);
	}

	fd = nfq_fd(h);
	__sync_add_and_fetch (&threadindex, 1);

	int opt=1;
	if (setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int)) == -1) 
	{
		FWLOG_ERROR("can't set netlink enobufs");
	}

	if(make_socket_non_blocking (fd)<0)
	{
		FWLOG_ERROR("can't set non blocking");
		exit(1);
	}

        event.data.fd = fd;
        event.events = EPOLLIN | EPOLLET;
        if(epoll_ctl (efd, EPOLL_CTL_ADD, fd, &event)<0)
        {
                FWLOG_ERROR("epoll_ctl error");
                exit(-1);
        }

	while(!force_exit)
	{
                int n;
                n = epoll_wait (efd, events, 1, EPOLL_TIMEOUT);
                if(!n)
                {
                        continue;
                }
		if ((events[0].events & EPOLLERR) ||
			(events[0].events & EPOLLHUP) ||
			(!(events[0].events & EPOLLIN)))
		{
			FWLOG_ERROR("epoll error");
			close (events[0].data.fd);
			exit(-2);
		}

		while(!force_exit && (rv = recv(events[0].data.fd, buf, sizeof(buf), 0))>0)
			nfq_handle_packet(h, buf, rv);
	}

	FWLOG_DEBUG("unbinding from queue %d\n",nfqPolicy[index].number);
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	FWLOG_DEBUG("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	FWLOG_DEBUG("closing library handle\n");
	nfq_close(h);

	return 0;
}

int fwcb_init(void)
{
	int i;
	for(i=0;i<4;++i)
	{
		if(pthread_create(firewall_thid+i, NULL, firewall_thread,(void *)(intptr_t)i))
			return -1;
	}
	return 0;
}
int fwcb_exit(void)
{
	int i;
	for(i=0;i<4;++i)
	{
		if(pthread_join(firewall_thid[i], NULL))
			return -1;
	}
	return 0;
}
