#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> 	//usleep
#include <time.h> 	//time
#include <arpa/inet.h> //inet_ntop
#include "internal.h"
#include "fwdb.h"
#include "fwutil.h"
#include "fwlogger.h"

#define  FW_RULE_TABLE_PATH		"db/"
#define  FW_DB				"fw.db"
//firewall rule
#define  FW_RULE_TABLE 			"fwrule"
#define  ID_FEILD			"id"
#define  PROTOCOL_FEILD 		"protocol"
#define  DIRECTION_FEILD 		"direction"
#define  VERDICT_FEILD			"verdict" 
#define  SPORT_FEILD			"sport"
#define  DPORT_FEILD			"dport"
#define  SADDR_FEILD			"saddr"
#define  DADDR_FEILD			"daddr"
#define  ISIPV6_FEILD			"isipv6"
#define  ISLOG_FEILD			"islog"
#define  PRIORITY_FEILD			"priority"

#define CREATE_FW_RULE_TABLE_SQL      	"create table if not exists "\
                                                FW_RULE_TABLE"("\
                                                ID_FEILD" INTEGER PRIMARY KEY ASC, "\
                                                PROTOCOL_FEILD" TEXT, "\
                                                DIRECTION_FEILD" INTEGER DEFAULT 1, "\
                                                VERDICT_FEILD" INTEGER DEFAULT 1, "\
                                                SPORT_FEILD" TEXT, "\
                                                DPORT_FEILD" TEXT, "\
                                                SADDR_FEILD" TEXT, "\
                                                DADDR_FEILD" TEXT, "\
                                                ISIPV6_FEILD" INTEGER DEFAULT 0, "\
                                                ISLOG_FEILD" INTEGER DEFAULT 0, "\
                                                PRIORITY_FEILD" INTEGER DEFAULT 0)"

#define FW_RULE_INSERT_SQL            	"insert into "FW_RULE_TABLE "("\
                                                PROTOCOL_FEILD"," DIRECTION_FEILD", "VERDICT_FEILD", "SPORT_FEILD", "DPORT_FEILD\
						", "SADDR_FEILD", "DADDR_FEILD", "ISIPV6_FEILD", "ISLOG_FEILD", "PRIORITY_FEILD")"\
                                                "values('%s','%d','%d','%s','%s','%s','%s','%d','%d','%d')"

#define FW_RULE_SELECT_SQL            	"select "PROTOCOL_FEILD"," DIRECTION_FEILD", "VERDICT_FEILD", "SPORT_FEILD"," \
                                                DPORT_FEILD", "SADDR_FEILD", "DADDR_FEILD", "ISIPV6_FEILD", "ISLOG_FEILD \
                                                " from "FW_RULE_TABLE " order by "PRIORITY_FEILD" ASC"

#define FW_RULE_DELETE_BY_PRIORITY_SQL  "delete from "FW_RULE_TABLE " where "DIRECTION_FEILD" = '%d' and "PRIORITY_FEILD" = '%d' and "\
					ISIPV6_FEILD" = '%d'"

#define FW_RULE_DELETE_BY_RULE_SQL      "delete from "FW_RULE_TABLE " where "ID_FEILD" IN(SELECT "ID_FEILD" FROM "FW_RULE_TABLE" WHERE "\
					PROTOCOL_FEILD" = '%s' and "DIRECTION_FEILD" = '%d' and " VERDICT_FEILD" = '%d' and "SPORT_FEILD"\
					 = '%s' and "DPORT_FEILD" = '%s' and " SADDR_FEILD" = '%s' and "DADDR_FEILD" = '%s' and "\
					ISIPV6_FEILD" = '%d' and "ISLOG_FEILD" = '%d' ORDER BY "PRIORITY_FEILD" DESC limit 1)"

#define FW_RULE_DELETE_BY_DIRECTION_SQL "delete from "FW_RULE_TABLE " where "DIRECTION_FEILD" = %s and "ISIPV6_FEILD" = %s"

#define FW_RULE_LIST_SELECT_SQL         "select "PROTOCOL_FEILD"," DIRECTION_FEILD", "VERDICT_FEILD", "SPORT_FEILD"," \
                                                DPORT_FEILD", "SADDR_FEILD", "DADDR_FEILD","ISIPV6_FEILD","ISLOG_FEILD \
                                                " from "FW_RULE_TABLE " where "DIRECTION_FEILD" = %s and "ISIPV6_FEILD" = %s order by "\
						DIRECTION_FEILD","PRIORITY_FEILD" ASC"

//TODO
#define FW_RULE_SELECT_BY_RULE_SQL	"select "ID_FEILD" from "FW_RULE_TABLE " where "PROTOCOL_FEILD" = '%s' and " DIRECTION_FEILD \
					" = '%d' and "VERDICT_FEILD" = '%d' and "SPORT_FEILD" = '%s' and " DPORT_FEILD" = '%s' and " \
					SADDR_FEILD" = '%s' and "DADDR_FEILD" = '%s' and "ISIPV6_FEILD" = '%d' and "ISLOG_FEILD \
					" = '%d' limit 1"

#define FW_RULE_SELECT_MAX_PRIORITY_SQL	"select "PRIORITY_FEILD" from "FW_RULE_TABLE " where "DIRECTION_FEILD\
						" ='%d' and "ISIPV6_FEILD" = '%d' order by "PRIORITY_FEILD" DESC limit 1"
#define _FW_RULE_UPDATE_PRIORITY_SQL(o) "update "FW_RULE_TABLE" set "PRIORITY_FEILD" = "PRIORITY_FEILD" " #o" 1 where "\
					PRIORITY_FEILD" >= '%d' and "DIRECTION_FEILD" = '%d' and "ISIPV6_FEILD" = '%d'"

#define FW_RULE_UPDATE_PRIORITY_ADD_SQL _FW_RULE_UPDATE_PRIORITY_SQL(+)
#define FW_RULE_UPDATE_PRIORITY_SUB_SQL _FW_RULE_UPDATE_PRIORITY_SQL(-)

#define FW_RULE_DELETE_TABLE_SQL      	"DROP TABLE '%s'"
#define FW_RULE_RENME_TABLE_NAME_SQL  	"ALTER TABLE "FW_RULE_TABLE" RENAME TO '%s'"

//firewall log
#define  FW_LOG_TABLE			"fwlog"
#define  UID_FEILD			"UID"
#define  EPGUID_FEILD			"EpGuid"
#define  L3PROTOCOL_FEILD		"L3Protocol"
#define  L4PROTOCOL_FEILD		"L4Protocol"
#define  SRCMAC_FEILD			"SrcMac"
#define  SRCIP_FEILD			"SrcIp"
#define  SRCPORT_FEILD			"SrcPort"
#define  DSTMAC_FEILD			"DstMac"
#define  DSTIP_FEILD			"DstIp"
#define  DSTPORT_FEILD			"DstPort"
#define  TIME_FEILD			"Time"
#define  NUM_FEILD			"Num"
#define  DIRECT_FEILD			"Direct"
#define  REPORTSTATUS_FEILD		"ReportStatus"


#define CREATE_FW_LOG_TABLE_SQL		"create table if not exists "FW_LOG_TABLE"( "\
						UID_FEILD" TEXT, "\
						EPGUID_FEILD" TEXT, "\
						L3PROTOCOL_FEILD" INTEGER, "\
						L4PROTOCOL_FEILD" TEXT, "\
						SRCMAC_FEILD" TEXT, "\
						SRCIP_FEILD" TEXT, "\
						SRCPORT_FEILD" INTEGER, "\
						DSTMAC_FEILD" TEXT, "\
						DSTIP_FEILD" TEXT, "\
						DSTPORT_FEILD" INTEGER, "\
						TIME_FEILD" INTEGER, "\
						NUM_FEILD" INTEGER DEFAULT 1, "\
						DIRECT_FEILD" INTEGER, "\
						REPORTSTATUS_FEILD" INTEGER DEFAULT 0)"

#define FW_LOG_INSERT_SQL		"insert into "FW_LOG_TABLE"( "\
						UID_FEILD", "\
						EPGUID_FEILD", "\
						L3PROTOCOL_FEILD", "\
						L4PROTOCOL_FEILD", "\
						SRCMAC_FEILD", "\
						SRCIP_FEILD", "\
						SRCPORT_FEILD", "\
						DSTMAC_FEILD", "\
						DSTIP_FEILD", "\
						DSTPORT_FEILD", "\
						TIME_FEILD", "\
						NUM_FEILD", "\
						DIRECT_FEILD", "\
						REPORTSTATUS_FEILD")"\
                                                "values('%s','%s','%d','%s','%s','%s','%d','%s','%s','%d','%ld','%d','%d','%d')"


extern const char *fw4cmd;
extern const char *fw6cmd;

static int fw_rule_query_callback(void *arg, int argc, char **argv, char **colName)
{
	int i;
	int isin  = 0;
	int isdrop= 0;
	int isipv6= 0;
	int islog = 0;
	int ismsport=0;
	int isdisplay=(intptr_t)arg;
	const char *protocol;
	const char *sport;
	const char *dport;
	const char *saddr;
	const char *daddr;
	char buf[4096]={0};

	for(i=0; i<argc; i++)
	{
		if(!strcmp(colName[i],ISLOG_FEILD))
		{
			islog= atol(argv[i]);
#ifdef DEBUG
			printf("islog = %d\t", islog);
#endif
		}
		else if(!strcmp(colName[i],DIRECTION_FEILD))
		{
			isin = atoi(argv[i]);
#ifdef DEBUG
			printf("isin = %d\t", isin);
#endif
		}
		else if(!strcmp(colName[i],PROTOCOL_FEILD))
		{
			protocol = argv[i];
#ifdef DEBUG
			printf("protocol = %s\t", protocol);
#endif
		}
		else if(!strcmp(colName[i],VERDICT_FEILD))
		{
			isdrop = atoi(argv[i]);
#ifdef DEBUG
			printf("isdrop = %d\t", isdrop);
#endif
		}
		else if(!strcmp(colName[i],SPORT_FEILD))
		{
			sport = argv[i];
#ifdef DEBUG
			printf("sport = %s\t", sport);
#endif
		}
		else if(!strcmp(colName[i],DPORT_FEILD))
		{
			dport = argv[i];
#ifdef DEBUG
			printf("dport = %s\t",  dport ?  : "NULL");
#endif
		}
		else if(!strcmp(colName[i],SADDR_FEILD))
		{
			saddr = argv[i];
#ifdef DEBUG
			printf("saddr = %s\t",  saddr);
#endif
		}
		else if(!strcmp(colName[i],DADDR_FEILD))
		{
			daddr = argv[i];
#ifdef DEBUG
			printf("daddr = %s\t",  daddr);
#endif
		}
		else if(!strcmp(colName[i],ISIPV6_FEILD))
		{
			isipv6 = atoi(argv[i]);
#ifdef DEBUG
			printf("isipv6 = %d\t",  isipv6);
#endif
		}
	}
#ifdef DEBUG
	printf("\n");
#endif
	if(isdisplay)
		strcat(buf,isipv6?"fwcmd -6":"fwcmd");
	else
		strcat(buf,isipv6?fw6cmd:fw4cmd);
	if(!isdisplay)
	strcat(buf," -t "FW_TABLE);

	strcat(buf," -A ");
	if(isdisplay)
		strcat(buf,isin==1?FW_CMD_INPUT_CHAIN:FW_CMD_OUTPUT_CHAIN);
	else
		strcat(buf,isin==1?FW_USER_DEFINED_INPUT_CHAIN:FW_USER_DEFINED_OUTPUT_CHAIN);
	if(strcmp(protocol,""))
	{
		strcat(buf," -p ");
		strcat(buf,protocol);
	}
	if(strcmp(saddr,""))
	{
		if(strchr(saddr,'-') && !isdisplay)
			strcat(buf," -m iprange --src-range ");
		else
			strcat(buf," -s ");
		strcat(buf,saddr);
	}
	if(strcmp(sport,""))
	{
		if(strchr(sport,',') && !isdisplay)
			strcat(buf," -m multiport --source-ports "),ismsport=1;
		else
			strcat(buf," --sport ");
		strcat(buf,sport);
	}
	if(strcmp(daddr,""))
	{
		if(strchr(daddr,'-') && !isdisplay)
			strcat(buf," -m iprange --dst-range ");
		else
			strcat(buf," -d ");
		strcat(buf,daddr);
	}
	if(strcmp(dport,""))
	{
		if((strchr(dport,',') || ismsport) && !isdisplay)
			strcat(buf," -m multiport --destination-ports ");
		else
			strcat(buf," --dport ");
		strcat(buf,dport);
	}
	if(islog)
	{
		if(isdisplay)
		{
			if(isdrop)
				strcat(buf," -j DROP -l");
			else
				strcat(buf," -j ACCEPT -l");
		}
		else
		{
			strcat(buf," -j NFQUEUE --queue-num ");
			if(isdrop)
				strcat(buf,isin==1?STR(IN_LOG_DROP_QUEUE_NUM):STR(OUT_LOG_DROP_QUEUE_NUM));
			else
				strcat(buf,isin==1?STR(IN_LOG_ACCEPT_QUEUE_NUM):STR(OUT_LOG_ACCEPT_QUEUE_NUM));

			/* --queue-bypass is on other NFQUEUE option by Florian Westphal. 
			 * It change the behavior of a iptables rules when no userspace software is connected to the queue. 
			 * Instead of dropping packets, the packet are authorized if no software is listening to the queue.

			 * The extension is available since Linux kernel 2.6.39 and iptables v1.4.11.

			 * This feature is broken from kernel 3.10 to 3.12: when using a recent iptables, 
			 * passing the option --queue-bypass has no effect on these kernels
			 *
			 * sa https://home.regit.org/netfilter-en/using-nfqueue-and-libnetfilter_queue/
			 */
			strcat(buf," --queue-bypass");
		}
	}
	else
	{
		strcat(buf," -j ");
		strcat(buf,isdrop==1?"DROP":"ACCEPT");
	}
#ifdef DEBUG
	//FWLOG_DEBUG("cmd:%s",buf);
#endif
	if(isdisplay)
		printf("%s\n",buf);
	else
		system(buf);
	
	return 0;
}

int fw_rule_table_rename(sqlite3 *db,char *newname)
{
	int rc;
	char buf[64]={0};
	snprintf(buf, sizeof(buf), FW_RULE_RENME_TABLE_NAME_SQL,newname);
        do
        {
                if(SQLITE_BUSY == (rc = sqlite3_exec(db, buf, 0, 0, NULL)))
                {
                        usleep(10);
                }
        }while(SQLITE_BUSY == rc);
	if(SQLITE_OK != rc)
        {
		return -1;
        }
	return 0;
}

int fw_rule_table_del(sqlite3 *db,char *deltable)
{
	int rc;
	char buf[64]={0};
	snprintf(buf, sizeof(buf), FW_RULE_DELETE_TABLE_SQL,deltable);
        do
        {
                if(SQLITE_BUSY == (rc = sqlite3_exec(db, buf, 0, 0, NULL)))
                {
                        usleep(10);
                }
        }while(SQLITE_BUSY == rc);
	if(SQLITE_OK != rc)
        {
		return -1;
        }
	return 0;
}

static int fw_rule_select_max_priority(sqlite3 *db, int *priority,int direction, int isipv6)
{
	int rc;
	sqlite3_stmt *res;
	char buf[128]={0};
	snprintf(buf, sizeof(buf), FW_RULE_SELECT_MAX_PRIORITY_SQL,direction,isipv6);
	rc = sqlite3_prepare(db, buf, -1, &res, 0);
	if (rc != SQLITE_OK) 
	{
                FWLOG_ERROR("SQL error:<%d> sql:%s", rc,buf);
		return -1;
	}
	if(sqlite3_step(res) == SQLITE_ROW)
		*priority=sqlite3_column_int(res, 0);	
	else
		*priority = 0;	
	sqlite3_finalize(res);
	return 0;
}

SQL_CODE fw_rule_delete_by_num_from_db(sqlite3 *db, int direction, int priority, int isipv6)
{
	int rc;
	char buf[4096]={0};
	int last_priority;
	fw_rule_select_max_priority(db, &last_priority,direction,isipv6);
	if(priority<0 || (priority  > last_priority ))
		return SQL_NOT_FOUND;
	snprintf(buf, sizeof(buf),FW_RULE_DELETE_BY_PRIORITY_SQL ";" FW_RULE_UPDATE_PRIORITY_SUB_SQL,
					isipv6,direction,priority,priority,direction,isipv6);
	//FWLOG_INFO("buf:%s",buf);
        do
        {
                if(SQLITE_BUSY == (rc = sqlite3_exec(db, buf, 0, 0, NULL)))
                {
                        usleep(10);
                }
        }while(SQLITE_BUSY == rc);
	if(SQLITE_OK != rc)
        {
		return SQL_ERROR;
        }
	return SQL_SUCCESS;
}

SQL_CODE fw_rule_delete_by_rule_from_db(sqlite3 *db, const char *protocol,int direction, int verdict,const char *sport, 
					const char *dport, const char *saddr, const char *daddr,int isipv6, int islog)
{
	int rc;
	char buf[4096]={0};

	snprintf(buf, sizeof(buf),FW_RULE_DELETE_BY_RULE_SQL, protocol,direction,verdict,sport?sport:"",
					dport?dport:"",saddr?saddr:"",daddr?daddr:"",isipv6,islog);
        do
        {
                if(SQLITE_BUSY == (rc = sqlite3_exec(db, buf, 0, 0, NULL)))
                {
                        usleep(10);
                }
        }while(SQLITE_BUSY == rc);
	if(SQLITE_OK != rc)
        {
		return SQL_ERROR;
        }
	if(1 != sqlite3_total_changes(db))
		return SQL_NOT_FOUND;
	return SQL_SUCCESS;
}

int fw_rule_flush_from_db(sqlite3 *db, const char *direction, const char *iptype)
{
	int rc;
	char buf[4096]={0};
	snprintf(buf, sizeof(buf),FW_RULE_DELETE_BY_DIRECTION_SQL, direction,iptype);
        do
        {
                if(SQLITE_BUSY == (rc = sqlite3_exec(db, buf, 0, 0, NULL)))
                {
                        usleep(10);
                }
        }while(SQLITE_BUSY == rc);
	if(SQLITE_OK != rc)
        {
		return -1;
        }
	return 0;
}

int fw_rule_list_from_db(sqlite3 *db, const char *direction,const char *iptype)
{
	int rc;
	char buf[4096]={0};
	snprintf(buf, sizeof(buf), FW_RULE_LIST_SELECT_SQL, direction,iptype);
        do
        {
                if(SQLITE_BUSY == (rc = sqlite3_exec(db, buf, fw_rule_query_callback, (void *)(intptr_t)1, NULL)))
                {
                        usleep(10);
                }
        }while(SQLITE_BUSY == rc);
	if(SQLITE_OK != rc)
        {
		return -1;
        }
	return 0;
}

static int fw_rule_select_rule_by_rule( sqlite3 *db,const char *protocol,int direction, int verdict,const char *sport, 
					const char *dport, const char *saddr, const char *daddr,int isipv6, int islog)
{
	int rc;
	sqlite3_stmt *res;
	char buf[4096]={0};
	snprintf(buf, sizeof(buf), FW_RULE_SELECT_BY_RULE_SQL,protocol,direction,verdict,sport,dport,saddr,daddr,isipv6,islog);
	rc = sqlite3_prepare(db, buf, -1, &res, 0);
	if (rc != SQLITE_OK) 
	{
                FWLOG_ERROR("SQL error:<%d> sql:%s", rc,buf);
		return -1;
	}
	if(sqlite3_step(res) == SQLITE_ROW)
		rc = 1;
	else
		rc = 0;
	sqlite3_finalize(res);
	return rc;
}

SQL_CODE fw_rule_insert_into_db(sqlite3 *db,const char *protocol,int direction, int verdict,const char *sport, 
					const char *dport, const char *saddr, const char *daddr,int isipv6,int islog,int priority)
{
	int rc;
	char buf[4096]={0};
	int last_priority;
	if(SQLITE_OK != sqlite3_exec(db, CREATE_FW_RULE_TABLE_SQL, 0, 0, NULL))
        {
		FWLOG_ERROR("SQL error: %s", CREATE_FW_RULE_TABLE_SQL);
		return SQL_ERROR;
        }

	if(fw_rule_select_rule_by_rule(db, protocol, direction, verdict, sport?sport:"", dport?dport:"", saddr?saddr:"", daddr?daddr:"",isipv6, islog)>0)
		return SQL_DUPLICATE_ROW;
	fw_rule_select_max_priority(db, &last_priority,direction, isipv6);
	if(priority<0 || (priority  > (last_priority + 1)))
		return SQL_NOT_FOUND;
	if(priority ==0 || priority > last_priority)
	{
		++last_priority;
		snprintf(buf, sizeof(buf), FW_RULE_INSERT_SQL,protocol,direction,verdict,sport?sport:"",dport?dport:"",saddr?saddr:"",daddr?daddr:"",isipv6,islog,last_priority);
	}
	else
	{
		snprintf(buf, sizeof(buf), FW_RULE_UPDATE_PRIORITY_ADD_SQL";"FW_RULE_INSERT_SQL,priority,direction,isipv6,protocol,direction,verdict,sport?sport:"",dport?dport:"",saddr?saddr:"",daddr?daddr:"",isipv6,islog,priority);
	}
        do
        {
                if(SQLITE_BUSY == (rc = sqlite3_exec(db, buf, 0, 0, NULL)))
                {
                        usleep(10);
                }
        }while(SQLITE_BUSY == rc);
	if(SQLITE_OK != rc)
        {
		return SQL_ERROR;
        }
	return SQL_SUCCESS;
}

int fw_load_rule_from_db(void)
{
	int rc;
	sqlite3 *db;
        char buf[4096]={0};
        snprintf(buf, sizeof(buf),"%s%s%s",installPath,FW_RULE_TABLE_PATH,FW_DB);

	if(SQLITE_OK != sqlite3_open(buf, &db))
	{
		FWLOG_ERROR("open db error");
		return -1;	
	}

	if(SQLITE_OK != sqlite3_exec(db, CREATE_FW_RULE_TABLE_SQL, 0, 0, NULL))
        {
                FWLOG_ERROR("SQL error: %s", CREATE_FW_RULE_TABLE_SQL);
                sqlite3_close(db);
                db = NULL;
		return -1;
        }
        do
        {
                if(SQLITE_BUSY == (rc = sqlite3_exec(db, FW_RULE_SELECT_SQL, fw_rule_query_callback, NULL, NULL)))
                {
                        usleep(10);
                }
        }while(SQLITE_BUSY == rc);

	return 0;
}

int fw_begin_transaction(sqlite3 *db)
{
	if(!db) return -1;
	if(SQLITE_OK != sqlite3_exec(db, "BEGIN;", 0, 0, NULL))
	{
                FWLOG_ERROR("SQL BEGIN error");
		return -1;
	}
	return	0;
}

int fw_commite_transaction(sqlite3 *db)
{
	if(!db) return -1;
	if(SQLITE_OK != sqlite3_exec(db, "COMMIT", 0, 0, NULL))
	{
                FWLOG_ERROR("SQL COMMIT error");
		return -1;
	}
	return	0;
}

int fw_rollback_transaction(sqlite3 *db)
{
	if(!db) return -1;
	if(SQLITE_OK != sqlite3_exec(db, "ROLLBACK", 0, 0, NULL))
	{
                FWLOG_ERROR("SQL COMMIT error");
		return -1;
	}
	return	0;
}

int fw_log_insert_into_db(sqlite3 **db,fwpkg *pkg,unsigned int count)
{
	int rc;
	unsigned int i;
	char saddr[40]={0};
        char daddr[40]={0};
	char sql[4096]={0};
	char *protocol;

	if(!*db) *db = fwdb_open();
	if(!pkg || !*db ||!count )
		return -1;

	if(SQLITE_OK != sqlite3_exec(*db, "BEGIN;", 0, 0, NULL))
	{
		fwdb_close(*db);
		*db=NULL;
		return -1;
	}
	for(i=0;i<count;++i)
	{
		switch(pkg->protocol4)
		{
			case 1:  protocol="ICMP";   break;
			case 6:  protocol="TCP";    break;
			case 17: protocol="UDP";    break;
			case 58: protocol="ICMPV6"; break;
			default: protocol="unknown";break;
		}
		snprintf(sql, sizeof(sql), FW_LOG_INSERT_SQL,	"","",pkg->protocol3,protocol, "",
				inet_ntop(pkg->isipv4?AF_INET:AF_INET6, &(pkg->saddr), saddr, sizeof(saddr)),
				((pkg->protocol4 == 1 || pkg->protocol4==58)?pkg->sport:ntohs(pkg->sport)),"",
				inet_ntop(pkg->isipv4?AF_INET:AF_INET6, &(pkg->daddr), daddr, sizeof(daddr)), 
				((pkg->protocol4==1 || pkg->protocol4==58) ?pkg->dport:ntohs(pkg->dport)),
				time(NULL),1,pkg->isinput,0);
#ifdef DEBUG
		printf("%s",sql);
#endif
		do
		{
			if(SQLITE_BUSY == (rc = sqlite3_exec(*db, sql, 0, 0, NULL)))
			{
				usleep(10);
			}
		}while(SQLITE_BUSY == rc);
		if (rc != SQLITE_OK )
		{
			FWLOG_ERROR("SQL error: %s\n", sql);
			fwdb_close(*db);
			*db=NULL;
			return -1;
		}
		++pkg;
	}

	do
	{
		if(SQLITE_BUSY == (rc = sqlite3_exec(*db, "COMMIT", 0, 0, NULL)))
		{
			usleep(10);
		}
	}while(SQLITE_BUSY == rc);
	if (rc != SQLITE_OK )
	{
		FWLOG_ERROR("SQL error: COMMIT");
		sqlite3_exec(*db, "ROLLBACK", 0, 0, NULL);
		return -1;
	}
	return 0;
}

sqlite3 *fwdb_open(void)
{
	sqlite3 *db;
	char buf[4096]={0};
        snprintf(buf, sizeof(buf),"%s%s%s",installPath,FW_RULE_TABLE_PATH,FW_DB);
	if(SQLITE_OK != sqlite3_open(buf, &db))
	{
		FWLOG_ERROR("open db error\n");
		return NULL;	
	}
	return db;
}

void fwdb_close(sqlite3 *db)
{
	sqlite3_close(db);
}

int fwdb_init(void)
{
	sqlite3 *db;
        char buf[4096]={0};
        snprintf(buf, sizeof(buf),"%s%s%s",installPath,FW_RULE_TABLE_PATH,FW_DB);

	if(SQLITE_OK != sqlite3_open(buf, &db))
	{
                FWLOG_ERROR("open db error");
		return -1;	
	}
	if(SQLITE_OK != sqlite3_exec(db, CREATE_FW_RULE_TABLE_SQL, 0, 0, NULL))
        {
                FWLOG_ERROR("SQL error: %s",CREATE_FW_RULE_TABLE_SQL);
                sqlite3_close(db);
                db = NULL;
		return -1;
        }

	if(SQLITE_OK != sqlite3_exec(db, CREATE_FW_LOG_TABLE_SQL, 0, 0, NULL))
        {
                FWLOG_ERROR("SQL error: %s", CREATE_FW_LOG_TABLE_SQL);
                sqlite3_close(db);
                db = NULL;
		return -1;
        }
	sqlite3_close(db);
	return 0;
}

int fwdb_exit(void)
{
	return 0;
}
