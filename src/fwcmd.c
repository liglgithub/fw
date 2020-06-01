/*
 * =====================================================================================
 *
 *       Filename:  fwcmd.c
 *
 *    Description:  fwcmd main
 *
 *        Version:  1.0
 *        Created:  05/27/2020 07:39:18 PM
 *       Revision:  none
 *       Compiler:  gcc
 *        License:  GNU GENERAL PUBLIC LICENSE Version 2
 *
 *         Author:  liguoliang
 *          Email:  397543611@qq.com
 *
 * =====================================================================================
 */
#include <unistd.h>
#include <stdlib.h> 
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>  //isspace
#include "internal.h"
#include "fwdb.h"
#include "fwutil.h"

#define exit_error(var,...) 	(fprintf(stderr,__VA_ARGS__),exit(1))
#define DIRECTION(chain)	(chain?(!strcmp(chain,FW_USER_DEFINED_INPUT_CHAIN)?"1":"0"):"0 or 1")
#define VERDICT(TARGET)		(!strcmp(TARGET,"DROP")?1:0)
#define CHAINNAME(chain)	(chain?(chain):"")
#define ISLOG(log)		((log)?1:0)
#define ISIPV6TYPE(iptype)	(6==iptype)
#define IPTYPE(iptype)		(6==iptype?"1": "0")
const char *fw4cmd;
const char *fw6cmd;

void exit_printhelp(void)
{
printf("Commands:\n"
"Either long or short options are allowed.\n"
"chain is only support INPUT and OUTPUT\n"
"  --append  -A chain		Append to chain\n"
"  --delete  -D chain		Delete matching rule from chain\n"
"  --delete  -D chain rulenum\n"
"				Delete rule rulenum (1 = first) from chain\n"
"  --insert  -I chain [rulenum]\n"
"				Insert in chain as rulenum (default 1=first)\n"
"  --list    -L [chain]		List the rules in a chain or all chains\n"
"  --flush   -F [chain]		Delete all rules in  chain or all chains\n"
"				Change policy on chain to target\n"

"Options:\n"
"  --ipv6        -6             Force IPv6 address resolution\n"
"  --proto       -p proto	protocol: tcp,udp,icmp,icmpv6\n"
"  --source      -s address[/mask]\n"
"				source specification\n"
"  --destination -d address[/mask]\n"
"				destination specification\n"
"  --sport       -f source port \n"
"  --dport       -t destination port \n"
"  --jump        -j target 	target for rule (ACCEPT or DROP)\n"
"  --log         -l 	 	log when match rule\n");
	exit(0);
}

#define ICMP_PROTOCOL		0x0001U
#define ICMPV6_PROTOCOL		0x0002U
#define TCP_PROTOCOL		0x0004U
#define UDP_PROTOCOL		0x0008U
#define NUMBER_OF_PROTOCOL	4

#define CMD_NONE                0x0000U
#define CMD_INSERT              0x0001U
#define CMD_DELETE              0x0002U
#define CMD_DELETE_NUM          0x0004U
#define CMD_APPEND              0x0008U
#define CMD_LIST                0x0010U
#define CMD_FLUSH               0x0020U
#define NUMBER_OF_CMD   	6

static const char cmdflags[] = { 'I', 'D', 'D', 'A', 'L', 'F'};
#define OPTION_OFFSET 256

#define OPT_NONE        	0x00000U
#define OPT_IPV6    		0x00001U
#define OPT_PROTOCOL    	0x00002U
#define OPT_SOURCE      	0x00004U
#define OPT_DESTINATION 	0x00008U
#define OPT_SOURCE_PORT 	0x00010U
#define OPT_DESTINATION_PORT    0x00020U
#define OPT_JUMP        	0x00040U
#define OPT_LOG		   	0x00080U
#define NUMBER_OF_OPT   	8

static const char optflags[NUMBER_OF_OPT]
= { '6', 'p', 's', 'd', 'f','t', 'j', 'l'};

static const char *optstr[NUMBER_OF_OPT]
= { "", "p", "s", "d", "-sport", "-dport", "j", ""};

static const char *optvals[NUMBER_OF_OPT]
= { "", "p", "s", "d", "-sport", "-dport", "j", ""};

static struct option original_opts[] = {
        { "append", 1, 0, 'A' },
        { "delete", 1, 0,  'D' },
        { "insert", 1, 0,  'I' },
        { "list", 2, 0,  'L' },
        { "flush", 2, 0,  'F' },
        { "ipv6", 0, 0,  '6' },
        { "source", 1, 0, 's' },
        { "destination", 1, 0,  'd' },
        { "src", 1, 0,  's' }, /* synonym */
        { "dst", 1, 0,  'd' }, /* synonym */
        { "protocol", 1, 0,  'p' },
        { "sport", 1, 0,  'f' },
        { "dport", 1, 0,  't' },
        { "jump", 1, 0, 'j' },
        { "log", 0, 0, 'l' },
        { "help", 2, 0, 'h' },
        { 0 }
};

static struct option *opts = original_opts;

int
string_to_number(const char *s, int min, int max)
{
        long number;
        char *end;

        /* Handle hex, octal, etc. */
        errno = 0;
        number = strtol(s, &end, 0);
        if (*end == '\0' && end != s) {
                /* we parsed a number, let's see if we want this */
                if (errno != ERANGE && min <= number && number <= max)
                        return number;
        }
        return -1;
}

/* Can't be zero. */
static int
parse_rulenumber(const char *rule)
{
        int rulenum = string_to_number(rule, 1, INT_MAX);

        if (rulenum == -1)
                exit_error(PARAMETER_PROBLEM,
                           "Invalid rule number `%s'", rule);

        return rulenum;
}

static int
parse_protocol(const char *s,int *protype)
{
	if(!strcmp(s,"tcp"))
		*protype=TCP_PROTOCOL;
	else if(!strcmp(s,"udp"))
		*protype=UDP_PROTOCOL;
	else if(!strcmp(s,"icmp"))
		*protype=ICMP_PROTOCOL;
	else if(!strcmp(s,"icmpv6"))
		*protype=ICMPV6_PROTOCOL;
	else
                exit_error(PARAMETER_PROBLEM,
                           "Invalid protocol '%s'\n", s);
	return 0;
}

int parse_hostnetworkmask(const char *srcdst,const char *name,int *type)
{
	unsigned char buf[sizeof(struct in6_addr)];
	char *pmask=NULL;
	char *prang=NULL;
	int mask;
	if ((pmask = strrchr(name, '/')) != NULL) {
		*pmask++ = '\0';		
		mask=atoi(pmask);
	}
	if ((prang = strrchr(name, '-')) != NULL) {
		*prang++ = '\0';		
	}
        if (1 == inet_pton(AF_INET, name, buf)) 
	{
		if(*type == 0)
			*type=4;
		else if(*type !=4)
			exit_error(PARAMETER_PROBLEM,"IP Address type does not match\n");
		if(pmask)
		{
			*--pmask='/';
			if(mask >32 || mask <=0)
				return -1;
			return 0;
		}
		if(prang)
		{
			*(prang-1)='-';
			return parse_hostnetworkmask(srcdst,prang,type);
		}	
		return 0;
	}

	if(1 == inet_pton(AF_INET6, name, buf))
	{
		if(*type == 0)*type=6;
		else if(*type !=6) return -1;
		if(pmask)
		{
			*--pmask='/';
			if(mask >128 || mask <=0)
				return -1;
		}
		if(prang)
		{
			*(prang-1)='-';
			return parse_hostnetworkmask(srcdst,prang,type);
		}
		return 0;
	}
	if(pmask)*--pmask='/';
	if(prang)*--prang='-';
	exit_error(PARAMETER_PROBLEM,"%s:IP Address error\n",srcdst);
	return -1;
}

int parse_port(const char *srcdst,const char *port)
{
	int  num;
	char *saveptr;
	char *token;
	char *freestr=strdup(port);
	char *pcomma;
	for(pcomma=freestr;(token=strtok_r(pcomma, ",:", &saveptr));pcomma=NULL)
	{
		num=atoi(token);
		if(num <=0 || num >65535) exit_error(PARAMETER_PROBLEM, "%s:port %s error\n",srcdst, port);
	}
	free(freestr);
	return 0;
}

static int
parse_target(const char *targetname)
{
	if(!strcmp(targetname,"DROP"))
		return 1;
	else if(!strcmp(targetname,"ACCEPT"))
		return 0;
	else
                exit_error(PARAMETER_PROBLEM, "Invalid target '%s'\n", targetname);
	return 0;
}

static const char * 
parse_chain(const char *chainname,int *isinput)
{
	if(!strcmp(chainname,FW_CMD_INPUT_CHAIN))
		return *isinput=1,FW_USER_DEFINED_INPUT_CHAIN;
	else if(!strcmp(chainname,FW_CMD_OUTPUT_CHAIN))
		return *isinput=0,FW_USER_DEFINED_OUTPUT_CHAIN;
	else
                exit_error(PARAMETER_PROBLEM, "Invalid chain '%s'\n", chainname);
	return 0;
}

static void
set_optvals(const char *vals, unsigned int option)
{
        const char **ptr;
        for (ptr = optvals; option > 1; option >>= 1, ptr++);

        *ptr=vals;
}

static const char *
get_optvals(int option)
{
        const char **ptr;
        for (ptr = optvals; option > 1; option >>= 1, ptr++);

        return *ptr;
}

static void
set_optstr(const char *str, unsigned int option)
{
        const char **ptr;
        for (ptr = optstr; option > 1; option >>= 1, ptr++);

        *ptr=str;
}

static const char *
get_optstr(int option)
{
        const char **ptr;
        for (ptr = optstr; option > 1; option >>= 1, ptr++);

        return *ptr;
}

static char
opt2char(int option)
{
        const char *ptr;
        for (ptr = optflags; option > 1; option >>= 1, ptr++);

        return *ptr;
}

static void
set_option(unsigned int *options, unsigned int option)
{
        if (*options & option)
                exit_error(PARAMETER_PROBLEM, "multiple -%c flags not allowed",
                           opt2char(option));
        *options |= option;
}

static char
cmd2char(int option)
{
        const char *ptr;
        for (ptr = cmdflags; option > 1; option >>= 1, ptr++);

        return *ptr;
}

static void
add_command(unsigned int *cmd, const unsigned int newcmd, const int othercmds)
{
        if (*cmd & (~othercmds))
                exit_error(PARAMETER_PROBLEM, "Can't use -%c with -%c\n",
                           cmd2char(newcmd), cmd2char(*cmd & (~othercmds)));
        *cmd |= newcmd;
}

int do_command(int argc, char *argv[])
{

	int opt;
	int iptype=0;
	int protype=0;
	int isdrop=0;
	int isinput=0;
	int cmdlen=0;
	char cmd[1024]={0};
	sqlite3 *db=NULL;
	SQL_CODE c=SQL_SUCCESS;
	const char *chain = NULL;
	char *protocol = NULL;
        char *target = NULL;
	unsigned int rulenum = 0, options = 0, command = 0;
	const char *shostnetworkmask = NULL, *dhostnetworkmask = NULL, *sport = NULL, *dport = NULL;

	/* Suppress error messages: we may add new options if we
	   demand-load a protocol. */
	opterr = 0;

	while ((opt = getopt_long(argc, argv,
					"-A:D:I:L::F::6p:s:d:f:t:j:lh",
					opts, NULL)) != -1) 
	{
		switch (opt) 
		{
			/*
			 * Command selection
			 */
			case 'A':
				add_command(&command, CMD_APPEND, CMD_NONE);
				chain = parse_chain(optarg,&isinput);
				break;

			case 'D':
				add_command(&command, CMD_DELETE, CMD_NONE);
				chain = parse_chain(optarg,&isinput);
				if (optind < argc && argv[optind][0] != '-') {
					rulenum = parse_rulenumber(argv[optind++]);
					command = CMD_DELETE_NUM;
				}
				break;
			case 'I':
				add_command(&command, CMD_INSERT, CMD_NONE);
				chain = parse_chain(optarg,&isinput);
				if (optind < argc && argv[optind][0] != '-')
					rulenum = parse_rulenumber(argv[optind++]);
				else rulenum = 1;
				break;

			case 'L':
				add_command(&command, CMD_LIST, CMD_NONE);
				if (optarg) chain = parse_chain(optarg,&isinput);
				else if (optind < argc && argv[optind][0] != '-')
					chain = parse_chain(argv[optind++],&isinput);;
				break;

			case 'F':
				add_command(&command, CMD_FLUSH, CMD_NONE);
				if (optarg) chain = parse_chain(optarg,&isinput);
				else if (optind < argc && argv[optind][0] != '-')
					chain = parse_chain(argv[optind++],&isinput);;
				break;

				/*
				 *Option selection
				 */
			case '6':
				set_option(&options, OPT_IPV6);
				break;
			case 'p':
				set_option(&options, OPT_PROTOCOL);

				protocol = argv[optind-1];
				set_optvals(protocol, OPT_PROTOCOL);
				parse_protocol(protocol,&protype);

				break;

			case 's':
				set_option(&options, OPT_SOURCE);
				shostnetworkmask = argv[optind-1];
				parse_hostnetworkmask("src",shostnetworkmask, &iptype);
				if(strchr(shostnetworkmask,'-'))
					set_optstr("m iprange --src-range", OPT_SOURCE);
				set_optvals(shostnetworkmask, OPT_SOURCE);
				break;

			case 'd':
				set_option(&options, OPT_DESTINATION);
				dhostnetworkmask = argv[optind-1];
				parse_hostnetworkmask("dst",dhostnetworkmask, &iptype);
				if(strchr(dhostnetworkmask,'-'))
					set_optstr("m iprange --dst-range", OPT_DESTINATION);
				set_optvals(dhostnetworkmask, OPT_DESTINATION);
				break;

			case 'f':
				set_option(&options, OPT_SOURCE_PORT);
				sport = argv[optind-1];
				parse_port("src",sport);
				if(strchr(sport,','))
					set_optstr("m multiport --source-ports", OPT_SOURCE_PORT);
				set_optvals(sport, OPT_SOURCE_PORT);
				break;

			case 't':
				set_option(&options, OPT_DESTINATION_PORT);
				dport = argv[optind-1];
				parse_port("dst",dport);
				if(strchr(dport,','))
					set_optstr("m multiport --destination-ports", OPT_DESTINATION_PORT);
				set_optvals(dport, OPT_DESTINATION_PORT);
				break;
			case 'j':
				set_option(&options, OPT_JUMP);
				target = optarg;
				isdrop = parse_target(target);
				set_optvals(target, OPT_JUMP);
				break;
			case 'l':
				set_option(&options, OPT_LOG);
				break;
			case 'h':
			default:
				exit_printhelp();
				break;
		}
	}
	if (optind < argc)
                exit_error(PARAMETER_PROBLEM, "unknown arguments found on commandline");
	if (!command)
		exit_error(PARAMETER_PROBLEM, "no command specified\n");
	if ((sport || dport) && (!protocol || !strcmp(protocol,"icmp")))
		exit_error(PARAMETER_PROBLEM, "%s\n",(protocol?"icmp protocol no port":"no protocol specified"));
	if (!protocol && (command & (CMD_APPEND |CMD_INSERT)))
		exit_error(PARAMETER_PROBLEM, "protocol shoud assign\n");
	if (4==iptype && (options & OPT_IPV6 ))
		exit_error(PARAMETER_PROBLEM, "iptype do not match\n");
	if(!iptype )
	{
		if( (options & OPT_IPV6 )) iptype = 6;
		else iptype = 4;
	}
	if ( options & OPT_JUMP && options & OPT_LOG)
	{
		if(isinput) {if(isdrop) set_optvals(IN_LOG_DROP_TARGET, OPT_JUMP);
			else set_optvals(IN_LOG_ACCEPT_TARGET, OPT_JUMP);
		}
		else { if(isdrop) set_optvals(OUT_LOG_DROP_TARGET, OPT_JUMP);
			else set_optvals(OUT_LOG_ACCEPT_TARGET, OPT_JUMP);
		}
	}
	cmdlen=snprintf(cmd, sizeof(cmd),"%s -t %s -%c %s",(ISIPV6TYPE(iptype)?fw6cmd:fw4cmd),FW_TABLE, cmd2char(command), CHAINNAME(chain));
	if(rulenum >= 1)
		cmdlen+=snprintf(cmd+cmdlen, sizeof(cmd)-cmdlen," %d",rulenum);
	unsigned opts=OPT_PROTOCOL;
	unsigned opte=OPT_LOG;
	for(opts = OPT_PROTOCOL;opts<opte && (size_t)cmdlen<sizeof(cmd);opts<<=1)
	{
		if(opts & options)
		cmdlen += snprintf(cmd+cmdlen,sizeof(cmd)-cmdlen, " -%s %s",get_optstr(opts),get_optvals(opts));
	}
	if((size_t)cmdlen >= sizeof(cmd))
			exit_error(SQL_ERROR,"CMD is too long\n");
	if(!(db= fwdb_open()) || fw_begin_transaction(db)<0)
	{
		fwdb_close(db);
		return -1;
	}
	switch(command)
	{
		case CMD_APPEND:
		case CMD_INSERT:
			c=fw_rule_insert_into_db(db,protocol,isinput, VERDICT(target),sport, dport,
						shostnetworkmask, dhostnetworkmask,ISIPV6TYPE(iptype),ISLOG(options&OPT_LOG),rulenum);
			break;
		case CMD_DELETE_NUM:
			c=fw_rule_delete_by_num_from_db(db, isinput, rulenum,ISIPV6TYPE(iptype));
			break;
		case CMD_DELETE:
			c=fw_rule_delete_by_rule_from_db(db, protocol,isinput, VERDICT(target),sport,
						dport, shostnetworkmask, dhostnetworkmask,ISIPV6TYPE(iptype),ISLOG(options&OPT_LOG));
			break;
		case CMD_FLUSH:
			c=fw_rule_flush_from_db(db, DIRECTION(chain),IPTYPE(iptype));
			break;
		case CMD_LIST:
			c=fw_rule_list_from_db(db, DIRECTION(chain),IPTYPE(iptype));
			break;
	}
	if(fw_commite_transaction(db) < 0 && fw_rollback_transaction(db)<0)
	{
		fwdb_close(db);
		return -1;
	}
	fwdb_close(db);
	if(c<SQL_SUCCESS)
	{
		switch(c)
		{
			case SQL_NOT_FOUND:
				exit_error(SQL_ERROR,"Not Found\n");
			case SQL_DUPLICATE_ROW:
				exit_error(SQL_ERROR,"Found Duplicate Rule\n");
			default:
				exit_error(SQL_ERROR,"SQL Error:\n");
		}
	}
	if(CMD_LIST != command)
		system(cmd);
	return 0;
}

static int init_fwcmd(void)
{
	if(0==access(IPTABLESPATH1,F_OK)) 
		fw4cmd = IPTABLESPATH1;
        else if(0==access(IPTABLESPATH2,F_OK)) 
		fw4cmd = IPTABLESPATH2;
        else 
		return -1;
	if(0==access(IP6TABLESPATH1,F_OK)) 
		fw6cmd = IP6TABLESPATH1;
        else if(0==access(IP6TABLESPATH2,F_OK)) 
		fw6cmd = IP6TABLESPATH2;
	if(fw_get_install_path()< 0)
		return -1;
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	if(init_fwcmd()<0)
	{
                fprintf(stderr,"Not found iptables\n");
                exit(1);
	}

	ret = do_command(argc, argv);
	if (ret) fprintf(stderr, "%s error\n",argv[0]);
	exit(ret);
}
