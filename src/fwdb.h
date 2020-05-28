#ifndef _FW_DB_H_
#define _FW_DB_H_
#include <sqlite3.h>
#include "fwpkg.h"

typedef enum
{
	SQL_ERROR = -1,
	SQL_DUPLICATE_ROW = -2,
	SQL_NOT_FOUND = -3,
	SQL_SUCCESS = 0
}SQL_CODE;

SQL_CODE fw_rule_insert_into_db(sqlite3 *db,const char *protocol,int direction, int verdict, const char *sport,
					const char *dport, const char *saddr, const char *daddr,int isipv6,int islog,int priority);
SQL_CODE fw_rule_delete_by_num_from_db(sqlite3 *db, int direction, int priority,int isipv6);
SQL_CODE fw_rule_delete_by_rule_from_db(sqlite3 *db, const char *protocol,int direction, int verdict,const char *sport, 
					const char *dport, const char *saddr, const char *daddr,int isipv6, int islog);
extern int fw_rule_flush_from_db(sqlite3 *db, const char *direction, const char *iptype);
int fw_rule_list_from_db(sqlite3 *db, const char *direction, const char *iptype);
extern int fw_load_rule_from_db(void);
extern int fw_rule_table_rename(sqlite3 *db,char *newname);
extern int fw_rule_table_del(sqlite3 *db,char *deltable);
extern int fw_log_insert_into_db(sqlite3 **db,fwpkg *pkg,unsigned int count);

extern sqlite3 *fwdb_open(void);
extern void fwdb_close(sqlite3 *db);
extern int fw_begin_transaction(sqlite3 *db);
extern int fw_commite_transaction(sqlite3 *db);
extern int fw_rollback_transaction(sqlite3 *db);
extern int fwdb_init(void);
extern int fwdb_exit(void);

#endif /*_FW_DB_H_*/
