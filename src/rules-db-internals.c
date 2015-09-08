/*
 * libprivilege control, rules database
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Jan Olszak <j.olszak@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
* @file        rules-db-internals.c
* @author      Jan Olszak (j.olszak@samsung.com)
* @version     1.0
* @brief       Definition of internal functions of the rules-db API.
*/

#include <errno.h>      // For error logging
#include <stdarg.h>     // For handling multiple arguments
#include <stdlib.h>     // For free
#include <stdio.h>      // For file manipulation
#include "common.h"     // For smack_label_is_valid
#include <unistd.h>     // For sleep

#include "rules-db-internals.h"
#include "rules-db.h"

#define RDB_MAX_QUERY_ATTEMPTS    50
#define RDB_TIME_BETWEEN_ATTEMPTS 1 // sec

/**
 * Reset and unbind statement. Used in functions that use bindings.
 * @param  p_stmt SQLite3 statement
 * @return        PC_OPERATION_SUCCESS on success, error code otherwise
 */
static int reset_and_unbind_stmt(sqlite3_stmt *p_stmt)
{
	if(sqlite3_clear_bindings(p_stmt) != SQLITE_OK) {
		C_LOGE("RDB: Error unbinding statement: %s",
		       sqlite3_errmsg(sqlite3_db_handle(p_stmt)));
		return PC_ERR_DB_QUERY_STEP;
	}

	if(sqlite3_reset(p_stmt) != SQLITE_OK) {
		C_LOGE("RDB: Error reseting statement: %s",
		       sqlite3_errmsg(sqlite3_db_handle(p_stmt)));
		return PC_ERR_DB_QUERY_STEP;
	}
	return PC_OPERATION_SUCCESS;
}



/**
 * Helper function. Use on INSERT or DELETE or UPDATE, when not interested in returned value
 *
 * @ingroup RDB: internal functions
 *
 * @param  p_stmt SQLite3 statement
 * @return        PC_OPERATION_SUCCESS on success, error code otherwise
 */
static int step_and_convert_returned_value(sqlite3_stmt *p_stmt)
{
	if(sqlite3_step(p_stmt) == SQLITE_DONE) {
		return PC_OPERATION_SUCCESS;
	} else {
		C_LOGE("RDB: Error during stepping: %s",
		       sqlite3_errmsg(sqlite3_db_handle(p_stmt)));
		return PC_ERR_DB_QUERY_STEP;
	}
}

int add_modified_label_internal(sqlite3 *p_db, const char *const s_label_name)
{
	int ret = PC_OPERATION_SUCCESS;
	sqlite3_stmt *p_stmt = NULL;
	ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT OR IGNORE INTO modified_label(name) VALUES(%Q)",
			   s_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int add_modified_permission_internal(sqlite3 *p_db, sqlite3_int64 i_permission_id)
{
	RDB_LOG_ENTRY_PARAM("%lld", i_permission_id);

	int ret = PC_OPERATION_SUCCESS;
	sqlite3_stmt *p_stmt = NULL;
	ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT OR IGNORE INTO modified_label(name) \
			    SELECT app_permission_view.app_name        \
			    FROM   app_permission_view                 \
			    WHERE  app_permission_view.permission_id = %lld",
			   i_permission_id);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int add_modified_all_apps_with_any_permission(sqlite3 *p_db)
{
	RDB_LOG_ENTRY;

	if(sqlite3_exec(p_db,"INSERT OR IGNORE INTO modified_label(name) \
			      SELECT app_permission_view.app_name        \
			      FROM   app_permission_view                 \
			      WHERE  app_permission_view.is_enabled = 1",
			0, 0, 0) != SQLITE_OK) {
		C_LOGE("RDB: Error during marking labels as modified: %s", sqlite3_errmsg(p_db));
		return PC_ERR_DB_OPERATION;
	}
	return PC_OPERATION_SUCCESS;
}


int add_modified_additional_rules_internal(sqlite3 *p_db)
{
	if(sqlite3_exec(p_db,"INSERT OR IGNORE INTO modified_label(name)  \
			      SELECT label_name                           \
			      FROM   label_app_path_type_rule_view",
			0, 0, 0) != SQLITE_OK) {
		C_LOGE("RDB: Error during marking labels as modified: %s", sqlite3_errmsg(p_db));
		return PC_ERR_DB_OPERATION;
	}
	return PC_OPERATION_SUCCESS;
}


int add_modified_apps_path_internal(sqlite3 *p_db,
				    const char *const s_app_label_name)
{
	int ret = PC_OPERATION_SUCCESS;
	sqlite3_stmt *p_stmt = NULL;
	ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT OR IGNORE INTO modified_label(name) \
			    SELECT path_view.path_label_name           \
			    FROM   path_view                           \
			    WHERE  path_view.owner_app_label_name = %Q",
			   s_app_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}

int add_modified_paths_label_internal(sqlite3 *p_db, const char *const s_path)
{
	int ret = PC_OPERATION_SUCCESS;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT OR IGNORE INTO modified_label(name) \
			    SELECT path_view.path_label_name           \
			    FROM   path_view                           \
			    WHERE  path_view.path = %Q",
			   s_path);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));

	return ret;
}

int add_modified_blacklist_permissions_internal(sqlite3 *p_db, const char * const s_tizen_version)
{
	int ret = PC_OPERATION_SUCCESS;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt, "\
				INSERT OR IGNORE INTO modified_label(name) \
				SELECT app_permission_view.app_name        \
				FROM   app_permission_view                 \
				INNER JOIN permission USING(permission_id) \
				WHERE  permission.on_blacklist = 1 AND tizen_version=%Q;",
				s_tizen_version);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));

	return ret;
}

/**
 * Function called when the target database is busy.
 * We attempt to access the database every
 * RDB_TIME_BETWEEN_ATTEMPTS seconds
 *
 * @param  not_used  not used
 * @param  i_attempt number of the attempt
 * @return           0 when stops waiting
 *                   1 when waiting
 */
static int database_busy_handler(void *not_used UNUSED,
				 int i_attempt)
{
	if(i_attempt > RDB_MAX_QUERY_ATTEMPTS) {
		// I ain't gonna wait for you forever!
		C_LOGE("RDB: Database busy for too long.");
		return 0;
	}
	C_LOGW("RDB: Database busy, waiting");
	sleep(RDB_TIME_BETWEEN_ATTEMPTS);
	return 1;
}


int open_rdb_connection(sqlite3 **p_db, bool b_create_temporary_tables)
{
	RDB_LOG_ENTRY;

	char *p_err_msg;

	// Open connection:
	int ret = sqlite3_open_v2(RDB_PATH,
				  p_db,
				  RDB_READWRITE_FLAG,
				  NULL);
	if(*p_db == NULL) {
		C_LOGE("RDB: Error opening the database: Unable to allocate memory.");
		return PC_ERR_DB_CONNECTION;
	}
	if(ret != SQLITE_OK) {
		C_LOGE("RDB: Error opening the database: %s", sqlite3_errmsg(*p_db));
		return PC_ERR_DB_CONNECTION;
	}

	//Register busy handler:
	if(sqlite3_busy_handler(*p_db, database_busy_handler, NULL) != SQLITE_OK) {
		C_LOGE("RDB: Error opening the database: %s", sqlite3_errmsg(*p_db));
		return PC_ERR_DB_CONNECTION;
	}

	// Load extensions:
	if(sqlite3_enable_load_extension(*p_db, 1) != SQLITE_OK) {
		C_LOGE("RDB: Error enabling extensions: %s", sqlite3_errmsg(*p_db));
		return PC_ERR_DB_CONNECTION;
	}

	if(sqlite3_load_extension(*p_db,
				  "/usr/lib/librules-db-sql-udf.so", 0,
				  &p_err_msg) != SQLITE_OK) {

		C_LOGE("RDB: Error during loading librules-db-sql-udf.so: %s",
		       p_err_msg);
		sqlite3_free(p_err_msg);
		return PC_ERR_DB_CONNECTION;
	}
	sqlite3_free(p_err_msg);


	if (b_create_temporary_tables) {
		// Create the temporary tables:
		if(sqlite3_exec(*p_db,
				"PRAGMA foreign_keys = ON;                                 \
											   \
				PRAGMA temp_store = MEMORY;                                \
											   \
				CREATE TEMPORARY TABLE modified_label(                     \
					name VARCHAR NOT NULL PRIMARY KEY);                \
											   \
				CREATE TEMPORARY TABLE all_smack_binary_rules_modified(    \
					subject TEXT NOT NULL,                             \
					object  TEXT NOT NULL,                             \
					access  INTEGER NOT NULL,                          \
					is_volatile INTEGER NOT NULL);                     \
											   \
				CREATE TEMPORARY TABLE current_smack_rule_modified(        \
					subject VARCHAR NOT NULL,                          \
					object  VARCHAR NOT NULL,                          \
					access  INTEGER NOT NULL);                         \
											   \
				CREATE TEMPORARY TABLE history_smack_rule_modified(        \
					subject VARCHAR NOT NULL,                          \
					object  VARCHAR NOT NULL,                          \
					access  INTEGER NOT NULL);                         \
											   \
				CREATE TEMPORARY VIEW modified_smack_rules AS              \
				SELECT  subject, object,                                   \
					access_to_str(access_add) AS access_add,           \
					access_to_str(access_del) AS access_del            \
				FROM    (                                                  \
					SELECT     subject, object,                        \
						   s1.access & ~s2.access AS access_add,   \
						   s2.access & ~s1.access AS access_del    \
					FROM       current_smack_rule_modified AS s1       \
					INNER JOIN history_smack_rule_modified AS s2       \
						   USING (subject, object)                 \
					WHERE      s1.access != s2.access                  \
					UNION                                              \
					SELECT     subject, object,                        \
						   s1.access AS access_add,                \
						   0 AS access_del                         \
					FROM       current_smack_rule_modified s1          \
					LEFT JOIN  history_smack_rule_modified s2          \
						   USING (subject, object)                 \
					WHERE      s2.subject IS NULL AND                  \
						   s2.object  IS NULL                      \
					UNION                                              \
					SELECT     subject, object,                        \
						   0 AS access_add,                        \
						   s1.access AS access_del                 \
					FROM       history_smack_rule_modified s1          \
					LEFT JOIN  current_smack_rule_modified s2          \
						   USING (subject, object)                 \
					WHERE      s2.subject IS NULL AND                  \
						   s2.object  IS NULL                      \
					)                                                  \
				ORDER BY subject, object ASC;",
				0, 0, 0) != SQLITE_OK) {
			C_LOGE("RDB: Error during preparing script: %s", sqlite3_errmsg(*p_db));
			return PC_ERR_DB_CONNECTION;
		}
	} else {
		// Just enable foreign keys:
		if(sqlite3_exec(*p_db, "PRAGMA foreign_keys = ON", 0, 0, 0) != SQLITE_OK) {
			C_LOGE("RDB: Error during preparing script: %s", sqlite3_errmsg(*p_db));
			return PC_ERR_DB_CONNECTION;
		}
	}

	return PC_OPERATION_SUCCESS;
}


int prepare_stmt(sqlite3 *p_db,
		 sqlite3_stmt **pp_stmt,
		 const char *const s_sql,
		 ...)
{
	int ret = PC_ERR_DB_QUERY_PREP;
	char *s_query = NULL;
	va_list args;
	va_start(args, s_sql);

	s_query = sqlite3_vmprintf(s_sql, args);

	if(s_query == NULL) {
		C_LOGE("RDB: Error during preparing statement: Unable to allocate enough memory.");
		ret = PC_ERR_DB_QUERY_PREP;
		goto finish;
	}

	if(sqlite3_prepare_v2(p_db,
			      s_query,
			      strlen(s_query) + 1,
			      pp_stmt,
			      NULL) != SQLITE_OK) {
		C_LOGE("RDB: Error during preparing statement: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_PREP;
		goto finish;
	}

	if(*pp_stmt == NULL) {
		C_LOGE("RDB: Error during preparing statement: SQL statement is probably empty.");
		ret = PC_ERR_DB_QUERY_PREP;
		goto finish;
	}

	ret = PC_OPERATION_SUCCESS;

finish:
	va_end(args);
	sqlite3_free(s_query);
	return ret;
}


int check_app_label_internal(sqlite3 *p_db,
			     const char *const s_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT 1                      \
			    FROM application_view          \
			    WHERE application_view.name=%Q \
			    LIMIT 1",
			   s_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = sqlite3_step(p_stmt);
	if(ret == SQLITE_ROW) {
		// There is such application label
		ret = PC_ERR_DB_LABEL_TAKEN;
	} else if(ret == SQLITE_DONE) {
		// No such application label
		ret = PC_OPERATION_SUCCESS;
	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}
finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int add_app_internal(sqlite3 *p_db,
		     const char *const s_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT into application_view(name) VALUES(%Q)",
			   s_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int remove_app_internal(sqlite3 *p_db,
			const char *const s_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "DELETE FROM application_view \
			     WHERE application_view.name=%Q",
			   s_label_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int add_path_internal(sqlite3 *p_db,
		      const char *const s_owner_label_name,
		      const char *const s_path_label_name,
		      const char *const s_path,
		      const char *const s_access,
		      const char *const s_access_reverse,
		      const char *const s_type)
{
	RDB_LOG_ENTRY_PARAM("%s %s %s %s %s %s",
			    s_owner_label_name, s_path_label_name,
			    s_path, s_access, s_access_reverse, s_type);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT INTO path_view(owner_app_label_name, \
						  path,                 \
						  path_label_name,      \
						  access,               \
						  access_reverse,       \
						  path_type_name)       \
			     VALUES(%Q, %Q, %Q, %Q, %Q, %Q);",
			   s_owner_label_name, s_path, s_path_label_name,
			   s_access, s_access_reverse, s_type);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}

int get_app_paths_count_internal(sqlite3 *p_db,
				 const char *const s_app_label_name,
				 const char *const s_app_path_type_name,
				 int *const p_num_paths)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_app_label_name, s_app_path_type_name);

	int ret;
	int sql_ret;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT COUNT(path)                   \
			    FROM   path_view                     \
			    WHERE  owner_app_label_name = %Q AND \
	                           path_type_name = %Q",
	                   s_app_label_name, s_app_path_type_name);
	if (ret != PC_OPERATION_SUCCESS) goto finish;

	sql_ret = sqlite3_step(p_stmt);
	if (sql_ret == SQLITE_ROW) {
		ret = PC_OPERATION_SUCCESS;
		*p_num_paths = sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN);
	} else if(sql_ret == SQLITE_BUSY) {
		//base locked in exclusive mode for too long
		C_LOGE("RDB: Database is busy. RDB Connection Error returned.");
		ret = PC_ERR_DB_CONNECTION;
	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if (sqlite3_finalize(p_stmt) != SQLITE_OK) {
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	}

	return ret;
}

int get_app_paths_internal(sqlite3 *p_db,
			   const char *const s_app_label_name,
			   const char *const s_app_path_type_name,
			   const int i_num_paths,
			   char ***ppp_paths)
{
	RDB_LOG_ENTRY_PARAM("%s %s %d", s_app_label_name, s_app_path_type_name, i_num_paths);

	int ret;
	int sql_ret = SQLITE_DONE;
	int allocated_paths = 0;
	int i;
	sqlite3_stmt *p_stmt = NULL;

	// Allocate an array for paths (+1 for NULL pointer terminating *ppp_paths).
	*ppp_paths = (char **) malloc(sizeof **ppp_paths * (i_num_paths + 1));

	if (*ppp_paths == NULL) {
		C_LOGE("Cannot allocate memory");
		return PC_ERR_MEM_OPERATION;
	}

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT path                          \
			    FROM   path_view                     \
			    WHERE  owner_app_label_name = %Q AND \
		                   path_type_name = %Q",
		                   s_app_label_name, s_app_path_type_name);
	if (ret != PC_OPERATION_SUCCESS) goto finish;

	for (i = 0; i < i_num_paths; ++i) {
		if ((sql_ret = sqlite3_step(p_stmt)) != SQLITE_ROW) break;

		(*ppp_paths)[i] = strdup((const char *) sqlite3_column_text(p_stmt,
					RDB_FIRST_COLUMN));

		if ((*ppp_paths)[i] == NULL) {
			ret = PC_ERR_MEM_OPERATION;
			goto finish;
		}

		++allocated_paths;
	}
	(*ppp_paths)[allocated_paths] = NULL;

	if (allocated_paths == i_num_paths) {
		ret = PC_OPERATION_SUCCESS;
	} else if (sql_ret == SQLITE_BUSY) {
		//base locked in exclusive mode for too long
		C_LOGE("RDB: Database is busy. RDB Connection Error returned.");
		ret = PC_ERR_DB_CONNECTION;
	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if (ret != PC_OPERATION_SUCCESS) {
		for(i = 0; i < allocated_paths; ++i) {
			free((*ppp_paths)[i]);
		}

		free(*ppp_paths);
		*ppp_paths = NULL;
	}

	if (sqlite3_finalize(p_stmt) != SQLITE_OK) {
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	}

	return ret;
}


int remove_path_internal(sqlite3 *p_db,
			 const char *const s_owner_label_name,
			 const char *const s_path)
{
	int ret;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "DELETE FROM path_removal_view        \
			    WHERE  owner_app_label_name = %Q AND \
			           path = %Q",
			   s_owner_label_name, s_path);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	return ret;
}


int add_permission_internal(sqlite3 *p_db,
			    const char *const s_permission_name,
			    const char *const s_tizen_version,
			    const char *const s_permission_type_name,
			    bool fast)
{
	RDB_LOG_ENTRY_PARAM("%s %s %s", s_permission_name, s_tizen_version, s_permission_type_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

        if (fast)
                ret = prepare_stmt(p_db, &p_stmt,
                                   "INSERT INTO permission_nondel_view(name, tizen_version, type_name) \
                                   VALUES (%Q,%Q,%Q)",
                                   s_permission_name, s_tizen_version, s_permission_type_name);
        else
                ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT INTO permission_view(name, tizen_version, type_name) \
			   VALUES (%Q,%Q,%Q)",
			   s_permission_name, s_tizen_version, s_permission_type_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int get_permission_id_internal(sqlite3 *p_db,
			       const char *const s_permission_name,
			       const char *const s_tizen_version,
			       const char *const s_permission_type_name,
			       sqlite3_int64 *p_permission_id)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_permission_name, s_permission_type_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT permission_view.permission_id  \
			    FROM   permission_view                \
			    WHERE  permission_view.name = %Q AND  \
				   permission_view.tizen_version = %Q AND \
				   permission_view.type_name = %Q \
			    LIMIT  1",
			   s_permission_name, s_tizen_version, s_permission_type_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = sqlite3_step(p_stmt);
	if(ret == SQLITE_ROW) {
		ret = PC_OPERATION_SUCCESS;
		*p_permission_id = sqlite3_column_int64(p_stmt, RDB_FIRST_COLUMN);
		C_LOGD("RDB: Found permission_id = %lld for %s %s", *p_permission_id, s_permission_name, s_permission_type_name);
	} else if(ret == SQLITE_DONE) {
		C_LOGW("RDB: There is no permission_id for %s %s", s_permission_name, s_permission_type_name);
		ret = PC_ERR_DB_OPERATION;

	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));

	return ret;
}


int prepare_stmts_for_bind(sqlite3 *p_db,
			   sqlite3_stmt **pp_stmt,
			   const char *const s_query)
{
	if(sqlite3_prepare_v2(p_db,
			      s_query,
			      strlen(s_query) + 1,
			      pp_stmt,
			      NULL) != SQLITE_OK) {
		C_LOGE("RDB: Error during preparing statement: %s",
		       sqlite3_errmsg(p_db));
		return PC_ERR_DB_QUERY_PREP;
	}
	return PC_OPERATION_SUCCESS;
}


static int add_permission_label_rule(sqlite3_stmt *p_stmt,
				     const sqlite3_int64 i_permission_id,
				     const char *const s_label_name,
				     const char *const s_access,
				     const int i_is_reverse)
{
	int ret = PC_OPERATION_SUCCESS;

	// Bind values to the statement and run it:
	// Bind returns SQLITE_OK == 0 on success
	if(sqlite3_bind_int64(p_stmt, 1, i_permission_id) ||
	    sqlite3_bind_text(p_stmt, 2, s_access, RDB_AUTO_DETERM_SIZE, 0) ||
	    sqlite3_bind_text(p_stmt, 3, s_label_name, RDB_AUTO_DETERM_SIZE, 0) ||
	    sqlite3_bind_int(p_stmt, 4, i_is_reverse)) {
		C_LOGE("RDB: Error during binding to statement: %s",
		       sqlite3_errmsg(sqlite3_db_handle(p_stmt)));
		ret = PC_ERR_DB_QUERY_BIND;
		goto finish;
	}

	// Perform the insert
	ret = step_and_convert_returned_value(p_stmt);

finish:
	reset_and_unbind_stmt(p_stmt);
	return ret;
}


static int add_permission_permission_rule(sqlite3_stmt *p_stmt,
		const sqlite3_int64 i_permission_id,
		const sqlite3_int64 i_target_permission_id,
		const char *const s_access,
		const int i_is_reverse)
{
	int ret = PC_OPERATION_SUCCESS;

	if(sqlite3_bind_int64(p_stmt, 1, i_permission_id) ||
	    sqlite3_bind_int64(p_stmt, 2, i_target_permission_id)  ||
	    sqlite3_bind_text(p_stmt, 3, s_access, RDB_AUTO_DETERM_SIZE, 0) ||
	    sqlite3_bind_int(p_stmt, 4, i_is_reverse)) {
		C_LOGE("RDB: Error during binding to statement: %s",
		       sqlite3_errmsg(sqlite3_db_handle(p_stmt)));
		ret = PC_ERR_DB_QUERY_BIND;
		goto finish;
	}

	ret = step_and_convert_returned_value(p_stmt);

finish:
	reset_and_unbind_stmt(p_stmt);
	return ret;
}


static int add_permission_app_path_type_rule(sqlite3_stmt *p_stmt,
		const sqlite3_int64 i_permission_id,
		const char *const s_path_type_name,
		const char *const s_access,
		const int i_is_reverse)
{
	int ret = PC_OPERATION_SUCCESS;

	if(sqlite3_bind_int64(p_stmt, 1, i_permission_id) ||
	    sqlite3_bind_text(p_stmt, 2, s_path_type_name, RDB_AUTO_DETERM_SIZE, 0)  ||
	    sqlite3_bind_text(p_stmt, 3, s_access, RDB_AUTO_DETERM_SIZE, 0) ||
	    sqlite3_bind_int(p_stmt, 4, i_is_reverse)) {
		C_LOGE("RDB: Error during binding to statement: %s",
		       sqlite3_errmsg(sqlite3_db_handle(p_stmt)));
		ret = PC_ERR_DB_QUERY_BIND;
		goto finish;
	}

	ret = step_and_convert_returned_value(p_stmt);

finish:
	reset_and_unbind_stmt(p_stmt);
	return ret;
}

int add_permission_rules_internal(sqlite3 *p_db,
				  const sqlite3_int64 i_permission_id,
				  const char *const *const pp_smack_rules)
{
	RDB_LOG_ENTRY;

	int ret = PC_OPERATION_SUCCESS;
	char s_label[SMACK_LABEL_LEN + 1];
	char s_access[ACC_LEN + 1];
	sqlite3_int64 i_all_apps_permission_id = 1;
	int i_is_reverse = 0;
	int i;
	sqlite3_stmt *p_perm_to_label_stmt = NULL;
	sqlite3_stmt *p_perm_to_perm_stmt = NULL;
	sqlite3_stmt *p_perm_to_app_path_type_stmt = NULL;

	// Prepare stmts. They are static, so we parse SQL only once per process and reuse it.
	ret = prepare_stmts_for_bind(p_db, &p_perm_to_label_stmt,
				     "INSERT INTO permission_label_rule_view(        \
				      permission_id, access, label_name, is_reverse) \
				      VALUES(?,?,?,?)");
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = prepare_stmts_for_bind(p_db, &p_perm_to_perm_stmt,
				     "INSERT OR REPLACE INTO permission_permission_rule( \
				      permission_id, target_permission_id,               \
				      access, is_reverse)                                \
				      VALUES(?,?,str_to_access(?),?)");
	if(ret != PC_OPERATION_SUCCESS) goto finish;


	ret = prepare_stmts_for_bind(p_db, &p_perm_to_app_path_type_stmt,
				     "INSERT INTO permission_app_path_type_rule_view(        \
				      permission_id, app_path_type_name, access, is_reverse) \
				      VALUES(?,?,?,?)");
	if(ret != PC_OPERATION_SUCCESS) goto finish;


	for(i = 0; pp_smack_rules[i] != NULL ; ++i) {
		C_LOGD("RDB: Granting permission: %s", pp_smack_rules[i]);

		// Ignore empty lines
		if(strspn(pp_smack_rules[i], " \t\n") == strlen(pp_smack_rules[i]))
			continue;

		ret = parse_rule(pp_smack_rules[i], s_label, s_access, &i_is_reverse);
		if(ret != PC_OPERATION_SUCCESS) goto finish;

		// Interpret wildcards
		if(s_label[0] != '~' &&
		    s_label[strlen(s_label) - 1] != '~') {
			// It's not a wildcard!
			ret = add_permission_label_rule(p_perm_to_label_stmt,
							i_permission_id,
							s_label,
							s_access,
							i_is_reverse);
			if(ret != PC_OPERATION_SUCCESS) goto finish;

		} else if(!strcmp(s_label, "~ALL_APPS~")) {
			ret = get_permission_id_internal(p_db,
							 "ALL_APPS",
							 get_current_tizen_ver(),
							 "ALL_APPS",
							 &i_all_apps_permission_id);
			if(ret != PC_OPERATION_SUCCESS) goto finish;

			ret = add_permission_permission_rule(p_perm_to_perm_stmt,
							     i_permission_id,
							     i_all_apps_permission_id,
							     s_access,
							     i_is_reverse);
			if(ret != PC_OPERATION_SUCCESS) goto finish;

		} else if(!strcmp(s_label, "~ALL_APPS_WITH_SAME_PERMISSION~")) {
			ret = add_permission_permission_rule(p_perm_to_perm_stmt,
							     i_permission_id,
							     i_permission_id,
							     s_access,
							     i_is_reverse);
			if(ret != PC_OPERATION_SUCCESS) goto finish;

		} else if(!strcmp(s_label, "~PUBLIC_PATH~")) {
			ret = add_permission_app_path_type_rule(p_perm_to_app_path_type_stmt,
								i_permission_id,
								"PUBLIC_PATH",
								s_access,
								i_is_reverse);
			if(ret != PC_OPERATION_SUCCESS) goto finish;

		} else if(!strcmp(s_label, "~GROUP_PATH~")) {
			ret = add_permission_app_path_type_rule(p_perm_to_app_path_type_stmt,
								i_permission_id,
								"GROUP_PATH",
								s_access,
								i_is_reverse);
			if(ret != PC_OPERATION_SUCCESS) goto finish;

		} else if(!strcmp(s_label, "~SETTINGS_PATH~")) {
			ret = add_permission_app_path_type_rule(p_perm_to_app_path_type_stmt,
								i_permission_id,
								"SETTINGS_PATH",
								s_access,
								i_is_reverse);
			if(ret != PC_OPERATION_SUCCESS) goto finish;
		}
	}

	ret = PC_OPERATION_SUCCESS;

finish:
	if(p_perm_to_label_stmt &&
	    sqlite3_finalize(p_perm_to_label_stmt) != SQLITE_OK) {
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	}

	if(p_perm_to_perm_stmt &&
	    sqlite3_finalize(p_perm_to_perm_stmt) != SQLITE_OK) {
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	}

	if(p_perm_to_app_path_type_stmt &&
	    sqlite3_finalize(p_perm_to_app_path_type_stmt) != SQLITE_OK) {
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	}
	return ret;
}

static int add_label_app_path_type_rule(sqlite3_stmt *p_stmt,
					const char *const s_label_name,
					const char *const s_path_type_name,
					const char *const s_access,
					const int i_is_reverse)
{
	int ret = PC_OPERATION_SUCCESS;

	if(sqlite3_bind_text(p_stmt, 1, s_label_name, RDB_AUTO_DETERM_SIZE, 0) ||
	    sqlite3_bind_text(p_stmt, 2, s_path_type_name, RDB_AUTO_DETERM_SIZE, 0)  ||
	    sqlite3_bind_text(p_stmt, 3, s_access, RDB_AUTO_DETERM_SIZE, 0) ||
	    sqlite3_bind_int(p_stmt, 4, i_is_reverse)) {
		C_LOGE("RDB: Error during binding to statement: %s",
		       sqlite3_errmsg(sqlite3_db_handle(p_stmt)));
		ret = PC_ERR_DB_QUERY_BIND;
		goto finish;
	}

	ret = step_and_convert_returned_value(p_stmt);

finish:
	reset_and_unbind_stmt(p_stmt);
	return ret;
}


int add_additional_rules_internal(sqlite3 *p_db, const char *const *const pp_smack_rules)
{
	RDB_LOG_ENTRY;
	int ret = PC_OPERATION_SUCCESS;
	size_t i;
	char s_subject[SMACK_LABEL_LEN + 1];
	char s_object[SMACK_LABEL_LEN + 1];
	char s_access[ACC_LEN + 1];
	sqlite3_stmt *p_label_to_app_path_type_stmt = NULL;
	int is_reverse = 0;
	char *ps_subject, *ps_object;

	// Clear the label_app_path_type_rule table
	if(sqlite3_exec(p_db, "DELETE FROM label_app_path_type_rule_view;", 0, 0, 0) != SQLITE_OK) {
		C_LOGE("RDB: Error during clearing additional rules: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_OPERATION;
		goto finish;
	}

	ret = prepare_stmts_for_bind(p_db, &p_label_to_app_path_type_stmt,
				     "INSERT INTO label_app_path_type_rule_view(          \
				      label_name, app_path_type_name, access, is_reverse) \
				      VALUES(?,?,?,?)");
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	// Add rules to the database
	for(i = 0; pp_smack_rules[i] != NULL ; ++i) {

		// Ignore empty lines
		if(strspn(pp_smack_rules[i], " \t\n") == strlen(pp_smack_rules[i]))
			continue;

		// Tokenize
		ret = tokenize_rule(pp_smack_rules[i], s_subject , s_object, s_access);
		if(ret != PC_OPERATION_SUCCESS) goto finish;

		if(is_wildcard(s_subject)) {
			ps_subject = s_object;
			ps_object = s_subject;
			is_reverse = 1;
		} else {
			ps_subject = s_subject;
			ps_object = s_object;
			is_reverse = 0;
		}

		// Check validity
		if(!smack_label_is_valid(ps_subject)) {
			C_LOGE("Subject is not a valid label");
			ret = PC_ERR_INVALID_PARAM;
			goto finish;
		}

		// Add access to paths
		if(!strcmp(ps_object, "~PUBLIC_PATH~")) {
			ret = add_label_app_path_type_rule(p_label_to_app_path_type_stmt,
							   ps_subject,
							   "PUBLIC_PATH",
							   s_access,
							   is_reverse);
			if(ret != PC_OPERATION_SUCCESS) goto finish;

		} else if(!strcmp(ps_object, "~GROUP_PATH~")) {
			ret = add_label_app_path_type_rule(p_label_to_app_path_type_stmt,
							   ps_subject,
							   "GROUP_PATH",
							   s_access,
							   is_reverse);
			if(ret != PC_OPERATION_SUCCESS) goto finish;

		} else if(!strcmp(ps_object, "~SETTINGS_PATH~")) {
			ret = add_label_app_path_type_rule(p_label_to_app_path_type_stmt,
							   ps_subject,
							   "SETTINGS_PATH",
							   s_access,
							   is_reverse);
			if(ret != PC_OPERATION_SUCCESS) goto finish;
		} else if(!strcmp(ps_object, "~NPRUNTIME_PATH~")) {
			ret = add_label_app_path_type_rule(p_label_to_app_path_type_stmt,
							   ps_subject,
							   "NPRUNTIME_PATH",
							   s_access,
							   is_reverse);
			if(ret != PC_OPERATION_SUCCESS) goto finish;
		}
	}

finish:
	if(p_label_to_app_path_type_stmt &&
	    sqlite3_finalize(p_label_to_app_path_type_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}

int check_app_has_permission_internal(sqlite3 *p_db,
				      const char *const s_app_label_name,
				      const char *const s_permission_name,
				      const char *const s_permission_type_name,
				      bool *const p_is_enabled)
{
	RDB_LOG_ENTRY_PARAM("%s %s %s", s_app_label_name,
			    s_permission_name, s_permission_type_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT is_enabled              \
			    FROM   app_permission_view     \
			    WHERE  app_name = %Q AND       \
			           name = %Q AND           \
			           type_name = %Q          \
			    LIMIT  1",
			   s_app_label_name, s_permission_name, s_permission_type_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = sqlite3_step(p_stmt);
	if(ret == SQLITE_ROW) {
		ret = PC_OPERATION_SUCCESS;
		//store the result
		*p_is_enabled = (bool)sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN);
	} else if(ret == SQLITE_DONE) {
		//no entry == permission not assigned
		C_LOGD("RDB: Permission: %s of type: %s is not assigned to app: %s",
		       s_permission_name, s_permission_type_name, s_app_label_name);
		ret = PC_OPERATION_SUCCESS;
		*p_is_enabled = false;
	} else if(ret == SQLITE_BUSY) {
		//base locked in exclusive mode for too long
		C_LOGE("RDB: Database is busy. RDB Connection Error returned.");
		ret = PC_ERR_DB_CONNECTION;
	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int get_app_permissions_number_internal(sqlite3  *p_db, const char *const s_app_label_name,
					const char *const s_permission_type_name,
					int *const p_num_permissions)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_app_label_name, s_permission_type_name);

	int ret;
	int sql_ret;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT COUNT(name)         \
			    FROM   app_permission_view \
			    WHERE  app_name = %Q AND   \
				   is_enabled = 1 AND  \
				   type_name = %Q",
			   s_app_label_name, s_permission_type_name);
	if (ret != PC_OPERATION_SUCCESS) goto finish;

	sql_ret = sqlite3_step(p_stmt);
	if (sql_ret == SQLITE_ROW) {
		ret = PC_OPERATION_SUCCESS;
		*p_num_permissions = sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN);
	} else if(sql_ret == SQLITE_BUSY) {
		//base locked in exclusive mode for too long
		C_LOGE("RDB: Database is busy. RDB Connection Error returned.");
		ret = PC_ERR_DB_CONNECTION;
	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if (sqlite3_finalize(p_stmt) != SQLITE_OK) {
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	}

	return ret;
}

int get_app_permissions_internal(sqlite3 *p_db,
				 const char *const s_app_label_name,
				 const char *const s_permission_type_name,
				 const int i_num_permissions,
				 char ***ppp_perm_list)
{
	RDB_LOG_ENTRY_PARAM("%s %s %d", s_app_label_name, s_permission_type_name,
			    i_num_permissions);

	int ret;
	int sql_ret = SQLITE_DONE;
	int allocated_permissions = 0;
	int i;
	sqlite3_stmt *p_stmt = NULL;

	// Allocate an array for permissions (+1 for NULL pointer terminating *ppp_perm_list).
	*ppp_perm_list = (char **) malloc(sizeof **ppp_perm_list * (i_num_permissions + 1));
	if (*ppp_perm_list == NULL) {
		C_LOGE("Cannot allocate memory");
		return PC_ERR_MEM_OPERATION;
	}

	// Get the permissions themselves.
	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT name                \
			    FROM   app_permission_view \
			    WHERE  app_name = %Q AND   \
				   is_enabled = 1 AND  \
				   type_name = %Q",
			   s_app_label_name, s_permission_type_name);
	if (ret != PC_OPERATION_SUCCESS) goto finish;

	for (i = 0; i < i_num_permissions; ++i) {
		if ((sql_ret = sqlite3_step(p_stmt)) != SQLITE_ROW) break;

		(*ppp_perm_list)[i] = strdup((const char *) sqlite3_column_text(p_stmt,
					RDB_FIRST_COLUMN));

		if ((*ppp_perm_list)[i] == NULL) {
			ret = PC_ERR_MEM_OPERATION;
			goto finish;
		}

		++allocated_permissions;
	}
	(*ppp_perm_list)[allocated_permissions] = NULL;

	if (allocated_permissions == i_num_permissions) {
		ret = PC_OPERATION_SUCCESS;
	} else if (sql_ret == SQLITE_BUSY) {
		C_LOGE("RDB: Database is busy. RDB Connection Error returned.");
		ret = PC_ERR_DB_CONNECTION;
	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if (ret != PC_OPERATION_SUCCESS) {
		for (i = 0; i < allocated_permissions; ++i) {
			free((*ppp_perm_list)[i]);
		}
		free(*ppp_perm_list);
		*ppp_perm_list = NULL;
	}

	if (sqlite3_finalize(p_stmt) != SQLITE_OK) {
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	}

	return ret;
}

int get_permission_number(sqlite3 *p_db,
			  size_t *pi_permission_number,
			  const char *const s_permission_type_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_permission_type_name);

	int ret_db = SQLITE_ERROR;
	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT COUNT(name)      \
			   FROM permission_view     \
			   WHERE type_name = %Q AND \
				 name != %Q",
			   s_permission_type_name,
			   s_permission_type_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret_db = sqlite3_step(p_stmt);

	if(ret_db == SQLITE_ROW) {
		*pi_permission_number = (size_t)sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN);
		ret = PC_OPERATION_SUCCESS;
	} else if(ret_db == SQLITE_DONE) {
		// no return value - something went wrong
		C_LOGD("RDB: Not able to determine number of rows");
		ret = PC_ERR_DB_OPERATION;
	} else if(ret_db == SQLITE_BUSY) {
		//base locked in exclusive mode for too long
		C_LOGE("RDB: Database is busy. RDB Connection Error returned.");
		ret = PC_ERR_DB_CONNECTION;
	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));

	return ret;
}

int get_permissions_internal(sqlite3 *p_db,
			     char ***ppp_permissions,
			     size_t i_permission_number,
			     const char *const s_permission_type_name)
{
	RDB_LOG_ENTRY_PARAM("%d %s", i_permission_number, s_permission_type_name);

	int ret_db = SQLITE_ERROR;
	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;
	size_t i_allocated_count = 0;
	size_t i;

	// add one additional element to the list to end it with NULL
	*ppp_permissions = (char **)malloc((i_permission_number + 1) * sizeof(char *));

	if(*ppp_permissions == NULL) {
		RDB_LOG_ENTRY_PARAM("RDB: Error during allocating memory.\n");
		ret = PC_ERR_MEM_OPERATION;
		goto finish;
	}

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT name             \
			   FROM permission_view     \
			   WHERE type_name = %Q AND \
				 name != %Q",
			   s_permission_type_name,
			   s_permission_type_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	for(i = 0; i < i_permission_number; ++i) {
		ret_db = sqlite3_step(p_stmt);
		if(ret_db == SQLITE_ROW) {
			(*ppp_permissions)[i] = strdup((char *)sqlite3_column_text(p_stmt,
							RDB_FIRST_COLUMN));
			C_LOGD("RDB: Found permission: %s", (*ppp_permissions)[i]);
			if((*ppp_permissions)[i] == NULL) {
				ret = PC_ERR_MEM_OPERATION;
				goto finish;
			}
			++i_allocated_count;
		} else if(ret_db == SQLITE_DONE) {
			C_LOGE("RDB: Not enought permissions read.");
			ret = PC_ERR_DB_OPERATION;
			goto finish;
		} else if(ret_db == SQLITE_BUSY) {
			//base locked in exclusive mode for too long
			C_LOGE("RDB: Database is busy. RDB Connection Error returned.");
			ret = PC_ERR_DB_CONNECTION;
			goto finish;
		} else {
			C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
			ret = PC_ERR_DB_QUERY_STEP;
			goto finish;
		}
	}

	(*ppp_permissions)[i] = NULL;

	ret_db = sqlite3_step(p_stmt);
	if(ret_db != SQLITE_DONE) {
		C_LOGE("RDB: Some unread permissions left.");
		ret = PC_ERR_DB_OPERATION;
	}

finish:
	// if memory allocation succeeded only partially, clean everything up
	if(ret != PC_OPERATION_SUCCESS) {
		for(i = 0; i < i_allocated_count; ++i) {
			free((*ppp_permissions)[i]);
		}
		free(*ppp_permissions);
		*ppp_permissions = NULL;
	}

	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));

	return ret;
}

int get_apps_number(sqlite3 *p_db,
		    size_t *pi_apps_number,
		    const char *const s_permission_type_name,
		    const char *const s_permission_name)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_permission_type_name, s_permission_name);

	int ret_db = SQLITE_ERROR;
	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	// determine number of apps:
	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT COUNT(app_id)    \
			   FROM app_permission_view \
			   WHERE type_name= %Q AND  \
				 name = %Q",
			   s_permission_type_name,
			   s_permission_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret_db = sqlite3_step(p_stmt);

	if(ret_db == SQLITE_ROW) {
		*pi_apps_number = (size_t)sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN);
		ret = PC_OPERATION_SUCCESS;
	} else if(ret_db == SQLITE_DONE) {
		// no return value - something went wrong
		C_LOGD("RDB: Not able to determine number of rows");
		ret = PC_ERR_DB_OPERATION;
	} else if(ret_db == SQLITE_BUSY) {
		// base locked in exclusive mode for too long
		C_LOGE("RDB: Database is busy. RDB Connection Error returned.");
		ret = PC_ERR_DB_CONNECTION;
	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));

	return ret;
}

int get_apps_with_permission_internal(sqlite3 *p_db,
				      perm_app_status_t **pp_apps,
				      size_t i_apps_number,
				      const char *const s_permission_type_name,
				      const char *const s_permission_name)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_permission_type_name, s_permission_name);

	int ret_db = SQLITE_ERROR;
	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;
	size_t i_allocated_count = 0;
	size_t i;

	*pp_apps = (perm_app_status_t *)malloc(i_apps_number * sizeof(perm_app_status_t));

	if(*pp_apps == NULL) {
		RDB_LOG_ENTRY_PARAM("RDB: Error during allocating memory.\n");
		ret = PC_ERR_MEM_OPERATION;
		goto finish;
	}

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT app_name,        \
				   is_enabled,      \
				   is_volatile      \
			   FROM app_permission_view \
			   WHERE type_name= %Q AND  \
				 name = %Q",
			   s_permission_type_name,
			   s_permission_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	for(i = 0; i < i_apps_number; ++i) {
		ret_db = sqlite3_step(p_stmt);
		if(ret_db == SQLITE_ROW) {
			(*pp_apps)[i].app_id = strdup((char *)sqlite3_column_text(p_stmt,
						      RDB_FIRST_COLUMN));
			(*pp_apps)[i].is_enabled = sqlite3_column_int(p_stmt, RDB_SECOND_COLUMN);
			(*pp_apps)[i].is_permanent = !sqlite3_column_int(p_stmt, RDB_THIRD_COLUMN);
			C_LOGD("RDB: Found (app_id, is_enabled, is_permanent): %s, %d, %d",
			       (*pp_apps)[i].app_id,
			       (*pp_apps)[i].is_enabled,
			       (*pp_apps)[i].is_permanent);
			if((*pp_apps)[i].app_id == NULL) {
				ret = PC_ERR_MEM_OPERATION;
				goto finish;
			}
			++i_allocated_count;
		} else if(ret_db == SQLITE_DONE) {
			ret = PC_ERR_DB_OPERATION;
			C_LOGE("RDB: Not enough permissions read.");
			goto finish;
		} else if(ret_db == SQLITE_BUSY) {
			// base locked in exclusive mode for too long
			C_LOGE("RDB: Database is busy. RDB Connection Error returned.");
			ret = PC_ERR_DB_CONNECTION;
			goto finish;
		} else {
			C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
			ret = PC_ERR_DB_QUERY_STEP;
			goto finish;
		}
	}

	ret_db = sqlite3_step(p_stmt);
	if(ret_db != SQLITE_DONE) {
		C_LOGE("RDB: Some unread permissions left.");
		ret = PC_ERR_DB_OPERATION;
	}

finish:
	// if memory allocation succeeded only partially, clean everything up
	if(ret != PC_OPERATION_SUCCESS) {
		for(i = 0; i < i_allocated_count; ++i) {
			free((*pp_apps)[i].app_id);
		}
		free(*pp_apps);
		*pp_apps = NULL;
	}

	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}

int get_app_id_internal(sqlite3 *p_db,
			int *pi_app_id,
			const char *const s_app_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_app_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT application_view.app_id \
			     FROM application_view \
			     WHERE application_view.name = %Q LIMIT 1",
			   s_app_label_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = sqlite3_step(p_stmt);
	if(ret == SQLITE_ROW) {
		ret = PC_OPERATION_SUCCESS;
		*pi_app_id = sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN);

	} else if(ret == SQLITE_DONE) {
		C_LOGW("RDB: There is no app_id for %s", s_app_label_name);
		ret = PC_ERR_DB_OPERATION;

	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int add_app_permission_internal(sqlite3 *p_db,
				int i_app_id,
				const char *const s_permission_name,
				const char *const s_permission_type_name,
				const bool b_is_volatile_new,
				const bool b_is_enabled_new)
{
	RDB_LOG_ENTRY_PARAM("%d %s %s %d %d", i_app_id,
			    s_permission_name, s_permission_type_name,
			    b_is_volatile_new, b_is_enabled_new);


	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT INTO                                  \
			    app_permission_view(app_id, name, type_name, \
			    is_volatile, is_enabled)                     \
			    VALUES(%d,%Q,%Q,%d,%d)",
			   i_app_id, s_permission_name, s_permission_type_name,
			   (int)b_is_volatile_new, (int)b_is_enabled_new);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int switch_app_permission_internal(sqlite3 *p_db,
				   const int i_app_id,
				   const char *const s_permission_name,
				   const char *const s_permission_type_name,
				   const bool b_is_enabled_new)
{
	RDB_LOG_ENTRY_PARAM("%d %s %s %d", i_app_id,
			    s_permission_name, s_permission_type_name,
			    b_is_enabled_new);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "UPDATE app_permission_view \
			    SET    is_enabled=%d       \
			    WHERE  app_id = %d  AND    \
			           name =%Q AND        \
			           type_name=%Q",
			   b_is_enabled_new, i_app_id,
			   s_permission_name, s_permission_type_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;
	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int update_app_permission_internal(sqlite3 *p_db,
				   const int i_app_id,
				   const sqlite3_int64 i_permission_id,
				   const bool b_is_volatile_new,
				   const bool b_is_enabled_new)
{
	RDB_LOG_ENTRY_PARAM("%d %lld %d %d",
			    i_app_id, i_permission_id,
			    b_is_volatile_new, b_is_enabled_new);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "UPDATE app_permission \
			     SET is_volatile = %d, is_enabled=%d \
			     WHERE app_id = %d AND permission_id = %lld",
			   b_is_volatile_new, b_is_enabled_new,
			   i_app_id, i_permission_id);

	if(ret != PC_OPERATION_SUCCESS) goto finish;
	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int change_app_permission_internal(sqlite3 *p_db,
				   int i_app_id,
				   const char *const s_version,
				   const char *const s_permission_name,
				   const char *const s_permission_type_name,
				   int i_is_volatile_new,
				   int i_is_enabled_new)
{
	RDB_LOG_ENTRY_PARAM("%d %s %s %s %d %d", i_app_id, s_version,
			    s_permission_name, s_permission_type_name,
			    i_is_volatile_new, i_is_enabled_new);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;
	int i_is_volatile_old, i_is_enabled_old;
	sqlite3_int64 i_permission_id;

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT is_volatile, is_enabled, permission_id      \
			    FROM    app_permission_list_view                   \
			    WHERE   app_id = %d AND                            \
			    tizen_version=%Q AND                               \
			    permission_name=%Q AND                             \
			    permission_type_name=%Q LIMIT 1",
			   i_app_id, s_version, s_permission_name, s_permission_type_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = sqlite3_step(p_stmt);
	if(ret == SQLITE_ROW) {
		// Phi, I already have this permission...
		i_is_volatile_old = sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN);
		i_is_enabled_old = sqlite3_column_int(p_stmt, RDB_SECOND_COLUMN);

		if(i_is_volatile_old == 1 && i_is_volatile_new == 0) {
			// Confucius say, No man can down-cast volatility.
			C_LOGE("RDB: Down-casting volatility is forbidden.");
			ret = PC_ERR_DB_PERM_FORBIDDEN;
			goto finish;
		}

		if(i_is_volatile_old == i_is_volatile_new &&
		    i_is_enabled_old == i_is_enabled_new) {
			// There is no change. Nice.
			C_LOGD("RDB: Permission %s %s already exists.", s_permission_name, s_permission_type_name);
			ret = PC_OPERATION_SUCCESS;
			goto finish;
		}

		i_permission_id = sqlite3_column_int64(p_stmt, RDB_THIRD_COLUMN);

		// Finalize statement
		if(sqlite3_finalize(p_stmt) != SQLITE_OK)
			C_LOGE("RDB: Error during finalizing statement: %s",
			       sqlite3_errmsg(p_db));
		p_stmt = NULL;

		C_LOGD("RDB: Updating permission %s %s to application.", s_permission_name, s_permission_type_name);
		ret = update_app_permission_internal(p_db,
						     i_app_id,
						     i_permission_id,
						     i_is_volatile_new,
						     i_is_enabled_new);

	} else if(ret == SQLITE_DONE) {
		// Wow! A brand new permission! Omnomnom...

		if(sqlite3_finalize(p_stmt) != SQLITE_OK)
			C_LOGE("RDB: Error during finalizing statement: %s",
			       sqlite3_errmsg(p_db));
		p_stmt = NULL;

		C_LOGD("RDB: Adding permission %s %s to application.", s_permission_name, s_permission_type_name);
		ret = add_app_permission_internal(p_db,
						  i_app_id,
						  s_permission_name,
						  s_permission_type_name,
						  i_is_volatile_new,
						  i_is_enabled_new);
	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if(p_stmt && sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int revoke_app_permissions_internal(sqlite3 *p_db,
				    const char *const s_app_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_app_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "DELETE FROM app_permission_view \
			    WHERE app_permission_view.app_name=%Q;",
			   s_app_label_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int reset_app_permissions_internal(sqlite3 *p_db,
				   const char *const s_app_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_app_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "DELETE FROM app_permission_volatile_view \
			     WHERE app_permission_volatile_view.app_name=%Q;",
			   s_app_label_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}

int update_rules_in_db(sqlite3 *p_db)
{
	RDB_LOG_ENTRY;

	if(sqlite3_exec(p_db,
			"\
			-- clean temporary tables\n                                             \
			DELETE FROM all_smack_binary_rules_modified;                            \
			DELETE FROM current_smack_rule_modified;                                \
			DELETE FROM history_smack_rule_modified;                                \
			                                                                        \
			-- gather possibly modified rules\n                                     \
			INSERT INTO all_smack_binary_rules_modified                             \
			SELECT subject, object, access, is_volatile                             \
			FROM   all_smack_binary_rules_view                                      \
			WHERE  subject IN modified_label;                                       \
			                                                                        \
			INSERT INTO all_smack_binary_rules_modified                             \
			SELECT subject, object, access, is_volatile                             \
			FROM   all_smack_binary_rules_view                                      \
			WHERE  object IN modified_label AND subject NOT IN modified_label;      \
			                                                                        \
			-- prepare aggregated rules for diff algorithm\n                        \
			INSERT INTO current_smack_rule_modified                                 \
			SELECT subject, object, bitwise_or(access)                              \
			FROM   all_smack_binary_rules_modified                                  \
			GROUP BY subject, object                                                \
			ORDER BY subject, object ASC;                                           \
			                                                                        \
			INSERT INTO history_smack_rule_modified                                 \
			SELECT subject, object, bitwise_or(access)                              \
			FROM   all_smack_binary_rules                                           \
			WHERE  subject IN modified_label OR object IN modified_label            \
			GROUP BY subject, object                                                \
			ORDER BY subject, object ASC;                                           \
			                                                                        \
			-- apply changes to all_smack_binary_rules\n                            \
			DELETE FROM all_smack_binary_rules                                      \
			WHERE  subject IN modified_label OR                                     \
			       object IN modified_label;                                        \
			                                                                        \
			INSERT INTO all_smack_binary_rules                                      \
			SELECT subject, object, access, is_volatile                             \
			FROM   all_smack_binary_rules_modified;                                 \
			                                                                        \
			-- cleanup\n                                                            \
			DELETE FROM modified_label;                                             \
			",
			0, 0, 0) != SQLITE_OK) {
		C_LOGE("RDB: Error during updating rules: %s",
		       sqlite3_errmsg(p_db));
		return PC_ERR_DB_OPERATION;
	}
	return PC_OPERATION_SUCCESS;
}

int update_smack_rules(sqlite3 *p_db)
{
	RDB_LOG_ENTRY;

	int ret = PC_OPERATION_SUCCESS;
	sqlite3_stmt *p_stmt = NULL;
	const unsigned char *s_subject    = NULL;
	const unsigned char *s_object     = NULL;
	const unsigned char *s_access_add = NULL;
	const unsigned char *s_access_del = NULL;
	struct smack_accesses *smack = NULL;

	if(smack_accesses_new(&smack)) {
		C_LOGE("RDB: Error during updating smack rules: smack_accesses_new failed.");
		ret = PC_ERR_MEM_OPERATION;
		goto finish;
	}

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT * from modified_smack_rules;");
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	while((ret = sqlite3_step(p_stmt)) == SQLITE_ROW) {
		s_subject    = sqlite3_column_text(p_stmt, RDB_FIRST_COLUMN);
		s_object     = sqlite3_column_text(p_stmt, RDB_SECOND_COLUMN);
		s_access_add = sqlite3_column_text(p_stmt, RDB_THIRD_COLUMN);
		s_access_del = sqlite3_column_text(p_stmt, RDB_FOURTH_COLUMN);

		C_LOGD("RDB: Added rule to smack:: %s %s %s %s",
		       s_subject, s_object, s_access_add, s_access_del);

		if(smack_accesses_add_modify(smack,
					     (const char *) s_subject,
					     (const char *) s_object,
					     (const char *) s_access_add,
					     (const char *) s_access_del)) {
			C_LOGE("RDB: Error during updating smack rules: %s",
			       sqlite3_errmsg(p_db));
			ret = PC_ERR_INVALID_OPERATION;
			goto finish;
		}
	}
	if(ret == SQLITE_DONE) {
		ret = PC_OPERATION_SUCCESS;
	} else {
		C_LOGE("RDB: Error during updating smack rules [%d]: %s",
		       ret, sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_OPERATION;
	}

	if(smack_accesses_apply(smack)) {
		C_LOGE("RDB: Error in smack_accesses_apply");
		ret = PC_ERR_INVALID_OPERATION;
	}

finish:
	if(sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));

	smack_accesses_free(smack);
	return ret;
}

int set_app_version(sqlite3 *p_db, const char * const s_app_label_name,
		const char * const s_version)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_app_label_name, s_version);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt, "UPDATE application_view \
					   SET tizen_version=%Q    \
					   WHERE name=%Q",
					   s_version, s_app_label_name);

	if (ret != PC_OPERATION_SUCCESS)
		goto finish;

	ret = step_and_convert_returned_value(p_stmt);
	finish: if (sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	return ret;
}

int get_app_version(sqlite3 *p_db, const char * const s_app_label_name,
		char **p_version)
{
	RDB_LOG_ENTRY_PARAM("%s", s_app_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt, "SELECT tizen_version FROM application_view \
					  WHERE name=%Q;",
					  s_app_label_name);

	if (ret != PC_OPERATION_SUCCESS)
		goto finish;
	ret = sqlite3_step(p_stmt);
	if (ret == SQLITE_ROW)
	{
		*p_version = strdup((const char *) sqlite3_column_text(p_stmt, RDB_FIRST_COLUMN));
		if (*p_version)
			ret = PC_OPERATION_SUCCESS;
		else
			ret = PC_ERR_MEM_OPERATION;
	}
	else
	{
		ret = PC_ERR_DB_NO_SUCH_APP;
	}
	finish: if (sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE(
				"RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	return ret;
}

int is_version_available(sqlite3 *p_db, const char * const s_version) {
	RDB_LOG_ENTRY_PARAM("%s", s_version);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
					"SELECT tizen_version FROM tizen_version \
					 WHERE tizen_version=%Q;",
					 s_version);

	if (ret != PC_OPERATION_SUCCESS)
		goto finish;
	ret = sqlite3_step(p_stmt);
	if (ret == SQLITE_ROW)
	{
		ret = PC_OPERATION_SUCCESS;
	}
	else
	{
		ret = PC_ERR_INVALID_PARAM;
	}
	finish: if (sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	return ret;
}

int remove_all_privileges_smack_rights_internal(sqlite3 *p_db)
{
	int ret, i;
	sqlite3_stmt *p_stmt;
	const char *const statements[] = {
			"DELETE FROM permission_permission_rule;",
			"DELETE FROM permission_label_rule;",
			"DELETE FROM permission_app_path_type_rule_view WHERE "
				"permission_name != 'ALL_APPS' "
				"AND app_path_type_name != 'PUBLIC_PATH';"
		/* this rule (from every app to public paths ) should not be removed here
		 * because it will never be installed back during refresh*/
	};

	for (i = 0; i < 3; i++) {
		p_stmt = NULL;
		ret = prepare_stmt(p_db, &p_stmt, statements[i]);
		if (ret == PC_OPERATION_SUCCESS) {
			ret = sqlite3_step(p_stmt);
			if (ret != SQLITE_DONE) {
				ret = PC_ERR_DB_QUERY_STEP;
				goto exit_with_error;
			}
		} else
			goto exit_with_error;
		if (sqlite3_finalize(p_stmt) != SQLITE_OK) {
			C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
			return PC_ERR_DB_OPERATION;
		}
	}
	return PC_OPERATION_SUCCESS;

exit_with_error:
	sqlite3_finalize(p_stmt);
	return ret;
}

int clear_blacklist_settings(sqlite3 *p_db, const char* const s_tizen_version) {
	RDB_LOG_ENTRY_PARAM("%s", s_tizen_version);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	// This statement won't return error in case of no matching permission
	ret = prepare_stmt(p_db, &p_stmt, "                           \
			UPDATE app_permission SET is_blacklist_enabled = 0    \
			WHERE is_blacklist_enabled = 1 AND permission_id IN ( \
				SELECT permission_id FROM permission_view         \
				WHERE tizen_version=%Q); ",
			s_tizen_version);

	if (ret != PC_OPERATION_SUCCESS )
		goto finish;
	ret = sqlite3_step(p_stmt);
	if (ret == SQLITE_DONE)
		ret = PC_OPERATION_SUCCESS;
	else
		ret = PC_ERR_DB_QUERY_STEP;
finish:
	if (sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	return ret;
}

int remove_blacklist_permissions(sqlite3 *p_db, const char* const s_tizen_version) {
	RDB_LOG_ENTRY_PARAM("%s", s_tizen_version);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	// This statement won't return error in case of no matching permission
	ret = prepare_stmt(p_db, &p_stmt, "                         \
			UPDATE permission SET on_blacklist = 0              \
			WHERE on_blacklist = 1 AND permission_id IN (       \
				SELECT permission_id FROM permission_view       \
				WHERE tizen_version=%Q);",
			s_tizen_version);

	if (ret != PC_OPERATION_SUCCESS )
		goto finish;
	ret = sqlite3_step(p_stmt);
	if (ret == SQLITE_DONE)
		ret = PC_OPERATION_SUCCESS;
	else
		ret = PC_ERR_DB_QUERY_STEP;
finish:
	if (sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	return ret;
}

int add_to_blacklist(sqlite3 *p_db, const char* const s_permission, const char* const s_type,
		const char* const s_tizen_version)
{
	RDB_LOG_ENTRY_PARAM("%s %s %s", s_permission, s_type, s_tizen_version);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	// This statement won't return error in case of no matching permission
	ret = prepare_stmt(p_db, &p_stmt, "                             \
			UPDATE permission SET on_blacklist = 1                  \
			WHERE permission_id IN (                                \
				SELECT permission_id FROM permission_view           \
				WHERE name=%Q AND type_name=%Q AND tizen_version=%Q);",
			s_permission, s_type, s_tizen_version);

	if (ret != PC_OPERATION_SUCCESS )
		goto finish;
	ret = sqlite3_step(p_stmt);
	if (ret == SQLITE_DONE)
		ret = PC_OPERATION_SUCCESS;
	else
		ret = PC_ERR_DB_QUERY_STEP;
finish:
	if (sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	return ret;
}

int find_blacklist_permission(sqlite3* p_db, const char* const s_app_label_name,
		const char* const s_perm_type, const char* const s_permission_name, int* p_app_id,
		int* p_perm_id)
{
	RDB_LOG_ENTRY_PARAM("%s %s %s", s_app_label_name, s_perm_type, s_permission_name);

	int ret;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt, "			\
			SELECT app_id, permission_id 		\
			FROM app_permission_blacklist_view 	\
			WHERE app_name=%Q AND type_name=%Q AND name=%Q AND on_blacklist='1';",
			s_app_label_name, s_perm_type, s_permission_name);

	if (ret != PC_OPERATION_SUCCESS )
		goto finish;

	ret = sqlite3_step(p_stmt);
	if (ret == SQLITE_ROW) {
		*p_app_id = sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN);
		*p_perm_id = sqlite3_column_int(p_stmt, RDB_SECOND_COLUMN);
		ret = PC_OPERATION_SUCCESS;
	} else if (ret == SQLITE_DONE) {
		C_LOGW("RDB: Blacklist permission not found");
		ret = PC_ERR_INVALID_PARAM;
	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}
finish:
	if (sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	return ret;
}

int update_blacklist_permission_internal(sqlite3* p_db, int i_app_id, int i_perm_id, int i_enabled)
{
	RDB_LOG_ENTRY_PARAM("%d %d", i_app_id, i_perm_id);

	int ret;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt, "			\
			UPDATE app_permission 				\
			SET is_blacklist_enabled=%d 		\
			WHERE app_id=%d AND permission_id=%d;",
			i_enabled, i_app_id, i_perm_id);

	if (ret != PC_OPERATION_SUCCESS )
		goto finish;

	ret = sqlite3_step(p_stmt);
	if (ret == SQLITE_DONE)
		ret = PC_OPERATION_SUCCESS;
	else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}
finish:
	if (sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	return ret;
}

int get_blacklist_statuses_count_internal(sqlite3* p_db, const char* const s_app_label_name,
		size_t* p_perm_number)
{
	RDB_LOG_ENTRY_PARAM("%s", s_app_label_name);

	int ret;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			"SELECT COUNT(name) FROM app_permission_blacklist_view WHERE app_name=%Q",
			s_app_label_name);

	if (ret != PC_OPERATION_SUCCESS )
		goto finish;

	ret = sqlite3_step(p_stmt);
	if (ret == SQLITE_ROW) {
		*p_perm_number = sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN);
		ret = PC_OPERATION_SUCCESS;
	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}
finish:
	if (sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	return ret;
}

int get_blacklist_statuses_internal(sqlite3* p_db, const char* const s_app_label_name,
		perm_blacklist_status_t** pp_perm_list, size_t i_perm_number)
{
	RDB_LOG_ENTRY_PARAM("%s %d", s_app_label_name, i_perm_number);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;
	size_t i = 0;

	if (i_perm_number == 0) {
		*pp_perm_list = 0;
		return PC_OPERATION_SUCCESS;
	}

	ret = prepare_stmt(p_db, &p_stmt, "					\
			SELECT name,type_name, is_blacklist_enabled \
			FROM app_permission_blacklist_view 			\
			WHERE app_name=%Q",
			s_app_label_name);

	if (ret != PC_OPERATION_SUCCESS )
		goto finish;

	*pp_perm_list = (perm_blacklist_status_t*) malloc(
			i_perm_number * sizeof(perm_blacklist_status_t));
	if (!*pp_perm_list) {
		ret = PC_ERR_MEM_OPERATION;
		goto finish;
	}

	while ((ret = sqlite3_step(p_stmt)) == SQLITE_ROW && i < i_perm_number) {
		(*pp_perm_list)[i].permission_name = strdup(
				(const char*) sqlite3_column_text(p_stmt, RDB_FIRST_COLUMN));
		(*pp_perm_list)[i].type = str2app_type(
				(const char*) sqlite3_column_text(p_stmt, RDB_SECOND_COLUMN));
		(*pp_perm_list)[i].is_enabled = sqlite3_column_int(p_stmt, RDB_THIRD_COLUMN);

		C_LOGD("RDB: Blacklist permission: %s for app: %s type: %d is enabled: %d",
				(*pp_perm_list)[i].permission_name,
				s_app_label_name,
				(*pp_perm_list)[i].type,
				(*pp_perm_list)[i].is_enabled);
		i++;
	}
	if (ret == SQLITE_DONE)
		ret = PC_OPERATION_SUCCESS;
	else
		ret = PC_ERR_DB_QUERY_STEP;
finish:
	if (sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	return ret;
}

int add_friend_entry_internal(sqlite3* p_db, const char* const s_pkg_id1,
		const char* const s_pkg_id2)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_pkg_id1, s_pkg_id2);

	int ret;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
		"INSERT INTO friends(label_id1, label_id2) VALUES (	\
		(SELECT label_id FROM label WHERE name=%Q),		\
		(SELECT label_id FROM label WHERE name=%Q))",
		s_pkg_id1, s_pkg_id2);

	if (ret != PC_OPERATION_SUCCESS)
		goto finish;

	ret = sqlite3_step(p_stmt);
	if (ret == SQLITE_DONE) {
		ret = PC_OPERATION_SUCCESS;
	} else {
		C_LOGE("RDB: Error during friend adding: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if (sqlite3_finalize(p_stmt) != SQLITE_OK)
		C_LOGE("RDB: Error during finalizing statement: %s", sqlite3_errmsg(p_db));
	return ret;
}
