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
* @file        rules-db.c
* @author      Jan Olszak (j.olszak@samsung.com)
* @version     1.0
* @brief       This file contains declaration of the API to rules database.
*/

#include <stdlib.h>

#include "privilege-control.h"
#include "rules-db-internals.h"

static sqlite3 *p_db__          = NULL;
static int i_session_ret_code__ = PC_OPERATION_SUCCESS;

/**
 * Prepare to modify the database.
 *
 * @ingroup RDB internal functions
 *
 * @param  pp_db pointer to a pointer to a SQLite3 database object
 * @return       PC_OPERATION_SUCCESS on success,
 *               error code otherwise
 */
static int rdb_begin(sqlite3 **pp_db)
{
	RDB_LOG_ENTRY;

	// If rdb_modification_start was called we use a global connection.
	if(p_db__) {
		*pp_db = p_db__;
		return PC_OPERATION_SUCCESS;
	}

	int ret = open_rdb_connection(pp_db);
	if(ret != PC_OPERATION_SUCCESS) return ret;

	if(sqlite3_exec(*pp_db, "BEGIN EXCLUSIVE TRANSACTION", 0, 0, 0)
	    != SQLITE_OK) {
		C_LOGE("RDB: Error during transaction begin: %s",
		       sqlite3_errmsg(*pp_db));
		return PC_ERR_DB_CONNECTION;
	}

	ret = save_smack_rules(*pp_db);
	if(ret != PC_OPERATION_SUCCESS) return ret;

	return PC_OPERATION_SUCCESS;
}


/**
 * Finish database modification.
 * If previous operation returned an error try to rollback changes.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db pointer to a SQLite3 database object
 * @param  ret  previous return code
 */
static void rdb_end(sqlite3 *p_db, int ret)
{
	RDB_LOG_ENTRY;

	if(ret == PC_OPERATION_SUCCESS &&
	    (ret = update_rules_in_db(p_db))
	    != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB: Error during updating rules in the database: %d", ret);;
	}

	if(have_smack()) {
		if(ret == PC_OPERATION_SUCCESS &&
		    (ret = update_smack_rules(p_db))
		    != PC_OPERATION_SUCCESS) {
			C_LOGE("RDB: Error updating smack rules: %d", ret);
		}
	}

	// Finish transaction
	C_LOGD("RDB: Closing connection.");
	if(ret == PC_OPERATION_SUCCESS) {
		if(sqlite3_exec(p_db, "COMMIT TRANSACTION", 0, 0, 0)
		    != SQLITE_OK) {
			C_LOGE("RDB: Error during transaction commit: %s",
			       sqlite3_errmsg(p_db));
		}
	} else if(ret == PC_ERR_DB_CONNECTION) {
		/* Life is pointless. I can't even rollback...*/
		C_LOGE("RDB: No rollback nor commit.");
	} else if(sqlite3_exec(p_db, "ROLLBACK TRANSACTION", 0, 0, 0)
		  != SQLITE_OK) {
		C_LOGE("RDB: Error during transaction rollback: %s",
		       sqlite3_errmsg(p_db));
	}

	if(sqlite3_close(p_db)) {
		C_LOGE("RDB: Error during closing the database. Error: %s", sqlite3_errmsg(p_db));
	}
}


static void update_ret_code(int i_ret)
{
	i_session_ret_code__ = i_session_ret_code__ ? i_session_ret_code__ : i_ret;
}


int rdb_modification_start(void)
{
	if(p_db__) {
		// We have to finish the previous session:
		C_LOGW("RDB: rdb_modification_finish was not called!");
		rdb_modification_finish();
	}

	return rdb_begin(&p_db__);
}


void rdb_modification_finish(void)
{
	if(p_db__) {
		rdb_end(p_db__, i_session_ret_code__);
		p_db__ = NULL;
		i_session_ret_code__ = PC_OPERATION_SUCCESS;
	}
}


int rdb_add_application(const char *const s_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = check_app_label_internal(p_db, s_label_name);
	if(ret == PC_ERR_DB_LABEL_TAKEN) {
		ret = PC_OPERATION_SUCCESS;
		C_LOGW("RDB: There is an application with label: %s", s_label_name);

	} else if(ret == PC_OPERATION_SUCCESS) {
		// There is no such label yet.
		ret = add_app_internal(p_db, s_label_name);
		if(ret != PC_OPERATION_SUCCESS) goto finish;
	}

	ret = add_modified_label_internal(p_db, s_label_name);
finish:
	if(p_db__) update_ret_code(ret); else rdb_end(p_db, ret);
	return ret;
}


int rdb_remove_application(const char *const s_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = remove_app_internal(p_db, s_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_modified_label_internal(p_db, s_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_modified_apps_path_internal(p_db, s_label_name);
finish:
	if(p_db__) update_ret_code(ret); else rdb_end(p_db, ret);
	return ret;
}


int rdb_add_path(const char *const s_owner_label_name,
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
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_path_internal(p_db,
				s_owner_label_name,
				s_path_label_name,
				s_path,
				s_access,
				s_access_reverse,
				s_type);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_modified_label_internal(p_db, s_path_label_name);
finish:
	if(p_db__) update_ret_code(ret); else rdb_end(p_db, ret);
	return ret;
}


int rdb_add_permission_rules(const char *const s_permission_name,
			     const char *const s_permission_type_name,
			     const char *const *const pp_smack_rules)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_permission_name, s_permission_type_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;
	sqlite3_int64 permission_id = -1;

	ret = rdb_begin(&p_db);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_permission_internal(p_db,
				      s_permission_name,
				      s_permission_type_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = get_permission_id_internal(p_db,
					 s_permission_name,
					 s_permission_type_name,
					 &permission_id);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_modified_permission_internal(p_db, permission_id);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	if(pp_smack_rules != NULL) {
		ret = add_permission_rules_internal(p_db,
						    permission_id,
						    pp_smack_rules);
	}

finish:
	if(p_db__) update_ret_code(ret); else rdb_end(p_db, ret);
	return ret;
}


int rdb_enable_app_permissions(const char *const s_app_label_name,
			       const app_type_t i_permission_type,
			       const char *const *const pp_permissions_list,
			       const bool   b_is_volatile)
{
	RDB_LOG_ENTRY_PARAM("%s %d %d", s_app_label_name, i_permission_type,(int)b_is_volatile);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;
	char *s_permission_name = NULL;
	int i;
	int i_app_id = 0;

	const char* s_permission_type_name = app_type_name(i_permission_type);
	const char* s_permission_group_type_name = app_type_group_name(i_permission_type);

	ret = rdb_begin(&p_db);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = get_app_id_internal(p_db, &i_app_id, s_app_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	// Add permissions specific for the permission type:
	ret = change_app_permission_internal(p_db,
					     i_app_id,
					     s_permission_type_name,
					     s_permission_type_name,
					     b_is_volatile,
					     RDB_ENABLE);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	// Add permissions from the list:
	for(i = 0; pp_permissions_list[i] != NULL; ++i) {
		// Ignore empty lines
		if(strspn(pp_permissions_list[i], " \t\n")
		    == strlen(pp_permissions_list[i]))
			continue;

		ret = base_name_from_perm(pp_permissions_list[i], &s_permission_name);
		if(ret != PC_OPERATION_SUCCESS) goto finish;

		ret = change_app_permission_internal(p_db,
						     i_app_id,
						     s_permission_name,
						     s_permission_group_type_name,
						     b_is_volatile,
						     RDB_ENABLE);
		if(ret != PC_OPERATION_SUCCESS) goto finish;
		free(s_permission_name);
	}

	ret = add_modified_label_internal(p_db, s_app_label_name);
finish:
	if(p_db__) update_ret_code(ret); else rdb_end(p_db, ret);
	return ret;
}


int rdb_disable_app_permissions(const char *const s_app_label_name,
				const app_type_t i_permission_type,
				const char *const *const pp_permissions_list)
{
	RDB_LOG_ENTRY_PARAM("%s %d", s_app_label_name, i_permission_type);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;
	char *s_permission_name = NULL;
	int i, i_app_id;
	const char* s_permission_group_type_name = app_type_group_name(i_permission_type);

	ret = rdb_begin(&p_db);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = get_app_id_internal(p_db, &i_app_id, s_app_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	for(i = 0; pp_permissions_list[i] != NULL ; ++i) {
		// Ignore empty lines
		if(strspn(pp_permissions_list[i], " \t\n")
		    == strlen(pp_permissions_list[i]))
			continue;

		ret = base_name_from_perm(pp_permissions_list[i], &s_permission_name);
		if(ret != PC_OPERATION_SUCCESS) goto finish;

		ret = switch_app_permission_internal(p_db,
						     i_app_id,
						     s_permission_name,
						     s_permission_group_type_name,
						     RDB_DISABLE);
		if(ret != PC_OPERATION_SUCCESS) goto finish;

		free(s_permission_name);
	}

	ret = add_modified_label_internal(p_db, s_app_label_name);
finish:
	if(p_db__) update_ret_code(ret); else rdb_end(p_db, ret);
	return ret;
}


int rdb_revoke_app_permissions(const char *const s_app_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_app_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = revoke_app_permissions_internal(p_db, s_app_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_modified_label_internal(p_db, s_app_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_modified_apps_path_internal(p_db, s_app_label_name);

finish:
	if(p_db__) update_ret_code(ret); else rdb_end(p_db, ret);
	return ret;
}


int rdb_reset_app_permissions(const char *const s_app_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_app_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = reset_app_permissions_internal(p_db, s_app_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_modified_label_internal(p_db, s_app_label_name);
finish:
	if(p_db__) update_ret_code(ret); else rdb_end(p_db, ret);
	return ret;
}


int rdb_add_additional_rules(const char *const *const pp_smack_rules)
{
	RDB_LOG_ENTRY;

	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_additional_rules_internal(p_db,
					    pp_smack_rules);

finish:
	if(p_db__) update_ret_code(ret); else rdb_end(p_db, ret);
	return ret;
}