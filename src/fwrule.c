/*
<?xml version="1.0" encoding="utf-8"?>
<Policy type="iprule">
	<!--IP规则-->
	<IpRule>
		<!--每条规则一个Rule节点，enable表示是否启用-->
		<Rule enable="1" log="1">
			<!--动作，0=阻止，1=直接放行-->
			<Action>1</Action>
			<!--方向，1=入站，2=出站-->
			<Direction>1</Direction>
			<!--源IP，仅支持单条-->
			<SourceIP>
				<Value>192.168.10.0/24</Value>
			</SourceIP>
			<!--目的IP，规则同源IP-->
			<DestIP>
				<Value>192.168.10.0/24</Value>
			</DestIP>
			<!--协议-->
			<Protocol>
				<!--协议号，6=tcp，17=udp-->
				<Number>17</Number>
				<!--源端口，仅对TCP/UDP协议有效，最多支持5组-->
				<SourcePort>
					<Port>
						<Begin>0</Begin>
						<End>65535</End>
					</Port>
				</SourcePort>
				<!--目的端口，规则源端口-->
				<DestPort>
					<Port>
						<Begin>0</Begin>
						<End>65535</End>
					</Port>
				</DestPort>
			</Protocol>
		</Rule>
	</IpRule>
</Policy>
*/
#include <string.h>
#include <unistd.h> //access
#include <arpa/inet.h> //inet_pton
#include <libxml/parser.h>
#include "fwdb.h"
#include "fwserv.h"
#include "fwutil.h"
#include "fwinit.h"
#include "fwlogger.h"
#define RULEXMLFILE  "etc/iprule.xml"

static int parse_iptype(const char *name,int *type)
{
        unsigned char buf[sizeof(struct in6_addr)];
        char *pmask=NULL;
        char *prang=NULL;
        int res = 0;
        if ((pmask = strrchr(name, '/')) != NULL) {
                *pmask++ = '\0';
        }
        if ((prang = strrchr(name, '-')) != NULL) {
                *prang++ = '\0';
        }
        if (1 == inet_pton(AF_INET6, name, buf))
	{
		if(!*type)
			*type=6;
		else if(*type!=6)
			res = -1;
		
	}
	else if (1 == inet_pton(AF_INET, name, buf))
	{
		if(!*type)
			*type=4;
		else if(*type!=4)
			res = -1;
	}
	else
	{
		res = -1;
	}
	if(pmask)*--pmask = '/';
	if(prang)*--prang = '-';
	return res;
}

static int parse_rule_from_xml(const char *xmlfile,sqlite3 *db)
{
	char *protocol="";
	int enable=0;
	int log=0;
	int iptype;
	int action=0;
	int direction=0;
	char saddr[48]={0},daddr[48]={0}; 
	char sport[60]={0},dport[60]={0}; 
	int res = 0;
	xmlDocPtr doc;
	xmlNodePtr root, child, iprule_node,rule_node;
	if(!(doc = xmlParseFile(xmlfile)))
	{
		FWLOG_ERROR("xml file open error:%s\n",xmlfile);
		xmlFreeDoc(doc);
		return -1;
	}
	if(!(root = xmlDocGetRootElement(doc)))
	{
		FWLOG_ERROR("xml file GetRootElement error:%s\n",xmlfile);
		xmlFreeDoc(doc);
		return -1;
	}
	for (child=root->children; child; child=child->next)
	{
		FWLOG_DEBUG("xml file :%s",(char *)child->name);
		if (xmlStrcasecmp(child->name, BAD_CAST"IpRule") != 0) 
			continue;
		iptype = 0;
		for (iprule_node = child->children; iprule_node; iprule_node = iprule_node->next)
		{
			if (xmlStrcasecmp(iprule_node->name, BAD_CAST"Rule") != 0) 
				continue;
			xmlChar* attr_value = xmlGetProp(iprule_node, BAD_CAST"enable");
			if(attr_value)
			{
				FWLOG_DEBUG("enable %d",atoi((char *)attr_value));
				enable = atoi((char *)attr_value);
				xmlFree(attr_value);
				if(!enable)
					continue;
			}
			attr_value = xmlGetProp(iprule_node, BAD_CAST"log");
			if(attr_value)
			{
				FWLOG_DEBUG("log %d",atoi((char *)attr_value));
				log = atoi((char *)attr_value);
				xmlFree(attr_value);
			}
			for (rule_node = iprule_node->children; rule_node; rule_node = rule_node->next)
			{
				if (xmlStrcasecmp(rule_node->name, BAD_CAST"Action") == 0)
				{
					xmlChar* value = xmlNodeGetContent(rule_node);
					if(value)
					{
						FWLOG_DEBUG("Action %d",atoi((char *)value));
						switch(atoi((char *)value))
						{
							case 0:action = 1;break;
							case 1:action = 0;break;
							default:action = 0;break;
						}
						xmlFree(value);
					}
				}
				else if (xmlStrcasecmp(rule_node->name, BAD_CAST"Direction") == 0)
				{
					xmlChar* value = xmlNodeGetContent(rule_node);
					if(value)
					{
						FWLOG_DEBUG("Direction %d",atoi((char *)value));
						switch(atoi((char *)value))
						{
							case 1:direction =1;break;
							case 2:direction =0;break;
							default:direction =0;break;
						}
						xmlFree(value);
					}
				}
				else if (xmlStrcasecmp(rule_node->name, BAD_CAST"SourceIP") == 0)
				{
					xmlNodePtr sip_node;
					for (sip_node = rule_node->children; sip_node; sip_node = sip_node->next)
					{
						if (xmlStrcasecmp(sip_node->name, BAD_CAST"Value") == 0) 
						{
							xmlChar* value = xmlNodeGetContent(sip_node);
							if(value)
							{
								FWLOG_DEBUG("saddr IP %s",value);
								if(!parse_iptype((const char *)value,&iptype))
								{
									if((4==iptype && memcmp(value,"0.0.0.0", strlen("0.0.0.0")))
										|| (6==iptype && memcmp(value,"0::0", strlen("0::0"))))
									snprintf(saddr, sizeof(saddr),"%s", (char*)value);
									xmlFree(value);
								}
								else
								{
									xmlFree(value);
									continue;
								}
							}
						}
					}
				}
				else if (xmlStrcasecmp(rule_node->name, BAD_CAST"DestIP") == 0)
				{
					xmlNodePtr dip_node;
					for (dip_node = rule_node->children; dip_node; dip_node = dip_node->next)
					{
						if (xmlStrcasecmp(dip_node->name, BAD_CAST"Value") == 0) 
						{
							xmlChar* value = xmlNodeGetContent(dip_node);
							if(value)
							{
#if 0
								FWLOG_DEBUG("daddr IP %s",value);
								if(memcmp(value,"0.0.0.0", strlen("0.0.0.0")))
									snprintf(daddr, sizeof(daddr),"%s", (char*)value);
								xmlFree(value);
#endif
								if(!parse_iptype((const char *)value,&iptype))
								{
									if((4==iptype && memcmp(value,"0.0.0.0", strlen("0.0.0.0")))
										|| (6==iptype && memcmp(value,"0::0", strlen("0::0"))))
									snprintf(saddr, sizeof(saddr),"%s", (char*)value);
									xmlFree(value);
								}
								else
								{
									xmlFree(value);
									continue;
								}
							}
						}
					}
				}
				else if (xmlStrcasecmp(rule_node->name, BAD_CAST"Protocol") == 0) 
				{
					xmlNodePtr protocol_node;
					for (protocol_node = rule_node->children; protocol_node; protocol_node = protocol_node->next) 
					{
						if (xmlStrcasecmp(protocol_node->name, BAD_CAST"Number") == 0) 
						{
							xmlChar* value = xmlNodeGetContent(protocol_node);
							if(value)
							{
								FWLOG_DEBUG("Number %d",atoi((char *)value));
								switch(atoi((char *)value))
								{
									case 6:protocol="tcp";break;
									case 17:protocol="udp";break;
								}
								xmlFree(value);
							}
						}
						else if (xmlStrcasecmp(protocol_node->name, BAD_CAST"SourcePort") == 0) 
						{
							xmlNodePtr port_node;
							for(port_node = protocol_node->children; port_node; port_node = port_node->next)
							{
								char *sbport,*seport;
								xmlNode *sub_node;
								if (xmlStrcasecmp(port_node->name, BAD_CAST"Port") != 0) 
									continue;
								for (sub_node = port_node->children;sub_node;sub_node = sub_node->next)
								{
									if(xmlStrcasecmp(sub_node->name, BAD_CAST"Begin") ==0)
									{
										xmlChar* value = xmlNodeGetContent(sub_node);
										if(value)
										{
											FWLOG_DEBUG("Begin %d",atoi((char *)value));
											sbport = strdup((char *)value);
											xmlFree(value);
										}
									}
									else if(xmlStrcasecmp(sub_node->name, BAD_CAST"End") ==0)
									{
										xmlChar* value = xmlNodeGetContent(sub_node);
										if(value)
										{
											FWLOG_DEBUG("End %d",atoi((char *)value));
											seport = strdup((char *)value);
											xmlFree(value);
										}
									}
								}
								FWLOG_DEBUG("sbport:%s,seport:%s",sbport,seport);
								if(sport[0])strcat(sport,",");
								strcat(sport, sbport);
								if(memcmp(sbport,seport,strlen(sbport)))
								{
									strcat(sport, ":");
									strcat(sport, seport);
								}
								free(sbport); sbport=NULL;
								free(seport); seport=NULL;
							}
						}
						else if (xmlStrcasecmp(protocol_node->name, BAD_CAST"DestPort") == 0) 
						{
							xmlNodePtr port_node;
							for (port_node = protocol_node->children; port_node; port_node = port_node->next)
							{
								char *dbport,*deport;
								xmlNode *sub_node;
								if (xmlStrcasecmp(port_node->name, BAD_CAST"Port") != 0) 
									continue;
								for(sub_node = port_node->children;sub_node;sub_node = sub_node->next)
								{
									if(xmlStrcasecmp(sub_node->name, BAD_CAST"Begin") ==0)
									{
										xmlChar* value = xmlNodeGetContent(sub_node);
										if(value)
										{
											FWLOG_DEBUG("Begin %d",atoi((char *)value));
											dbport = strdup((char *)value);
											xmlFree(value);
										}
									}
									else if(xmlStrcasecmp(sub_node->name, BAD_CAST"End") ==0)
									{
										xmlChar* value = xmlNodeGetContent(sub_node);
										if(value)
										{
											FWLOG_DEBUG("End %d",atoi((char *)value));
											deport = strdup((char *)value);
											xmlFree(value);
										}
									}
								}
								FWLOG_DEBUG("dbport:%s,deport:%s",dbport,deport);
								if(dport[0])strcat(dport,",");
								strcat(dport, dbport);
								if(memcmp(dbport,deport,strlen(dbport)))
								{
									strcat(dport, ":");
									strcat(dport, deport);
								}
								free(dbport); dbport=NULL;
								free(deport); deport=NULL;
							}
						}
					}
				}
			}
#ifdef DEBUG
			FWLOG_DEBUG("Action:%d Direction:%d enable:%d log:%d protocol:%s saddr:%s daddr:%s,sport:%s dport:%s",
					action,direction,enable,log,protocol,saddr,daddr,sport, dport);
#endif
			if(fw_rule_insert_into_db(db,protocol,direction, action,sport, dport, saddr, daddr,6==iptype,log,0)!=SQL_SUCCESS)
			{
				res = -1;
				goto END;
			}
			memset(sport, 0, sizeof(sport)); memset(dport, 0, sizeof(dport));
			memset(saddr, 0, sizeof(saddr)); memset(daddr, 0, sizeof(daddr));
		}
	}
END:
	xmlFreeDoc(doc);
	return res;
}

int load_fw_rule_from_xml(void)
{
	char rulexmlfile[1024]={0};
	snprintf(rulexmlfile,sizeof(rulexmlfile), "%s/%s", installPath, RULEXMLFILE);
	if(access(rulexmlfile,F_OK)<0)
	{
		return -1;
	}
	sqlite3 *db = fwdb_open();
	if(!db)
	{
		return -1;
	}
	if(fw_begin_transaction(db)<0 || fw_rule_table_rename(db,"backrule")<0)
	{
		fwdb_close(db);
		return -1;
	}
	parse_rule_from_xml(rulexmlfile,db);
	if(fw_rule_table_del(db,"backrule") < 0 || fw_commite_transaction(db) <0)
	{
		fw_rollback_transaction(db);
	}
	fwdb_close(db);
	db=NULL;
	fw_reload();
	return 0;
}

