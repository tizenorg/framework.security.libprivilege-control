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
static bool b_shared_transaction__ = false;
static const char* PERMISSIONS_FILTER = "permissions.filter";

typedef enum {
	RDB_TRANSACTION_EXCLUSIVE,
	RDB_TRANSACTION_SHARED_READ
} rdb_transaction_type_t;

/**
 * Prepare to modify the database.
 *
 * @ingroup RDB internal functions
 *
 * @param   pp_db             pointer to a pointer to a SQLite3 database object
 * @param   transaction_type  indicates whether the transaction is exclusive or shared
 * @return                    PC_OPERATION_SUCCESS on success, error code otherwise
 */
static int rdb_begin(sqlite3 **pp_db, rdb_transaction_type_t transaction_type)
{
	RDB_LOG_ENTRY;

	// If rdb_modification_start was called we use a global connection.
	// Since global connection is always opened only for exclusive transactions, temporary
	// tables are already created and b_shared_transaction is set to false.
	if(p_db__) {
		*pp_db = p_db__;
		return PC_OPERATION_SUCCESS;
	}

	// Shared transaction doesn't need temporary tables because SMACK labels won't be modified.
	bool b_create_temporary_tables = transaction_type != RDB_TRANSACTION_SHARED_READ;
	int ret = open_rdb_connection(pp_db, b_create_temporary_tables);
	if(ret != PC_OPERATION_SUCCESS) return ret;

	if(transaction_type == RDB_TRANSACTION_EXCLUSIVE) {
		b_shared_transaction__ = false;
		ret = sqlite3_exec(*pp_db, "BEGIN EXCLUSIVE TRANSACTION", 0, 0, 0);
	}
	else if(transaction_type == RDB_TRANSACTION_SHARED_READ) {
		b_shared_transaction__ = true;
		ret = sqlite3_exec(*pp_db, "BEGIN DEFERRED TRANSACTION", 0, 0, 0);
	}
	else {
		C_LOGE("RDB: Bad transaction type specified: %d",
		       (int)transaction_type);
		return PC_ERR_INVALID_PARAM;
	}

	if(ret != SQLITE_OK) {
		C_LOGE("RDB: Error during transaction begin: %s",
		       sqlite3_errmsg(*pp_db));
		b_shared_transaction__ = false;
		return PC_ERR_DB_CONNECTION;
	}

	return ret;
}


/**
 * Commit database modification.
 * If previous operation returned an error try to rollback changes.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db           pointer to a SQLite3 database object
 * @param  i_session_ret  session return code
 * @return                PC_OPERATION_SUCCESS on success,
 *                        error code otherwise
 */
static int rdb_end(sqlite3 *p_db, int i_session_ret)
{
	RDB_LOG_ENTRY;

	int ret = PC_OPERATION_SUCCESS;

	// No error during the session, make updates
	if(i_session_ret == PC_OPERATION_SUCCESS && !b_shared_transaction__) {
		ret = update_rules_in_db(p_db);
		if(ret != PC_OPERATION_SUCCESS) {
			C_LOGE("RDB: Error during updating rules in the database: %d", ret);
			goto finish;
		}

		if(have_smack()) {
			ret = update_smack_rules(p_db);
			if(ret != PC_OPERATION_SUCCESS) {
				C_LOGE("RDB: Error updating smack rules: %d", ret);
				goto finish;
			}
		}
	}

finish:
	// End transaction in a way
	// that depends on the ret and i_session_ret code.
	if(i_session_ret == PC_OPERATION_SUCCESS &&
	    ret == PC_OPERATION_SUCCESS) {
		if(sqlite3_exec(p_db, "COMMIT TRANSACTION", 0, 0, 0)
		    != SQLITE_OK) {
			C_LOGE("RDB: Error during transaction commit: %s",
			       sqlite3_errmsg(p_db));
			ret = PC_ERR_DB_CONNECTION;
		}

	} else if(i_session_ret == PC_ERR_DB_CONNECTION ||
		  ret == PC_ERR_DB_CONNECTION) {
		// Life is pointless. I can't even rollback...
		C_LOGE("RDB: No rollback nor commit.");
		ret = PC_ERR_DB_CONNECTION;

	} else {
		// Some other error code
		if(sqlite3_exec(p_db, "ROLLBACK TRANSACTION", 0, 0, 0)
		    != SQLITE_OK) {
			C_LOGE("RDB: Error during transaction rollback: %s",
			       sqlite3_errmsg(p_db));
			if(ret == PC_OPERATION_SUCCESS)
				ret = PC_ERR_DB_CONNECTION;
		}
	}

	if(sqlite3_close(p_db)) {
		C_LOGE("RDB: Error during closing the database. Error: %s",
		       sqlite3_errmsg(p_db));
		if(ret == PC_OPERATION_SUCCESS)
			ret = PC_ERR_DB_CONNECTION;
	}

	return ret;
}

/**
 * Finish database modification.
 * If global transaction is opened update session return code,
 * otherwise end the transaction.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db           pointer to a SQLite3 database object
 * @param  i_session_ret  session return code
 * @return                PC_OPERATION_SUCCESS on success,
 *                        error code otherwise
 */
static int rdb_finish(sqlite3 *p_db, int i_session_ret)
{
	if(p_db__) {
		if(i_session_ret_code__ == PC_OPERATION_SUCCESS)
			i_session_ret_code__ = i_session_ret;
		return i_session_ret;
	} else {
		int ret = rdb_end(p_db, i_session_ret);
		return i_session_ret != PC_OPERATION_SUCCESS ? i_session_ret : ret;
	}
}


int rdb_modification_start(void)
{
	if(p_db__) {
		// We have to finish the previous session:
		C_LOGW("RDB: rdb_modification_finish was not called!");
		rdb_modification_finish();
	}

	return rdb_begin(&p_db__, RDB_TRANSACTION_EXCLUSIVE);
}


int rdb_modification_finish(void)
{
	if(p_db__) {
		int ret = rdb_end(p_db__, i_session_ret_code__);
		p_db__ = NULL;
		i_session_ret_code__ = PC_OPERATION_SUCCESS;
		return ret;
	} else {
		return PC_OPERATION_SUCCESS;
	}
}

int rdb_modification_rollback(void)
{
	if(p_db__) {
		if(i_session_ret_code__ == PC_OPERATION_SUCCESS) {
			// Trigger rollback
			i_session_ret_code__ = PC_ERR_INVALID_OPERATION;
		}
		return rdb_modification_finish();
	} else {
		C_LOGE("RDB: Error nothing to rollback");
		return PC_ERR_INVALID_OPERATION;
	}
}

int rdb_add_application(const char *const s_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);
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
	return rdb_finish(p_db, ret);
}


int rdb_remove_application(const char *const s_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_modified_label_internal(p_db, s_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_modified_apps_path_internal(p_db, s_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = remove_app_internal(p_db, s_label_name);

finish:
	return rdb_finish(p_db, ret);
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

	ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);
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
	return rdb_finish(p_db, ret);
}


int rdb_get_app_paths(const char *const s_app_label_name,
		      const char *const s_app_path_type_name,
		      char ***ppp_paths)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_app_label_name, s_app_path_type_name);

	int ret;
	int i_num_paths;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_SHARED_READ);
	if (ret != PC_OPERATION_SUCCESS) goto finish;

	ret = get_app_paths_count_internal(p_db,
					   s_app_label_name,
					   s_app_path_type_name,
					   &i_num_paths);
	if (ret != PC_OPERATION_SUCCESS) goto finish;

	ret = get_app_paths_internal(p_db, s_app_label_name,
				     s_app_path_type_name,
				     i_num_paths,
				     ppp_paths);
finish:
	return rdb_finish(p_db, ret);
}

int rdb_remove_path(const char *const s_owner_label_name,
		    const char *const s_path)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_owner_label_name, s_path);

	int ret;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);
	if (ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_modified_paths_label_internal(p_db, s_path);
	if (ret != PC_OPERATION_SUCCESS) goto finish;

	ret = remove_path_internal(p_db, s_owner_label_name, s_path);
finish:
	return rdb_finish(p_db, ret);
}


int rdb_add_permission_rules(const char *const s_permission_name,
			     const char *const s_tizen_version,
			     const char *const s_permission_type_name,
                             const char *const *const pp_smack_rules,
                             bool fast)
{
	RDB_LOG_ENTRY_PARAM("%s %s %s", s_permission_name, s_tizen_version, s_permission_type_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;
	sqlite3_int64 permission_id = -1;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_permission_internal(p_db,
				      s_permission_name,
				      s_tizen_version,
                                      s_permission_type_name,
                                      fast);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = get_permission_id_internal(p_db,
					 s_permission_name,
					 s_tizen_version,
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
	return rdb_finish(p_db, ret);
}


int rdb_enable_app_permissions(const char *const s_app_label_name,
			       const app_type_t i_permission_type,
			       const char *const *const pp_permissions_list,
			       const bool   b_is_volatile)
{
	RDB_LOG_ENTRY_PARAM("%s %d %d", s_app_label_name, i_permission_type, (int)b_is_volatile);
	char **tmp = pp_permissions_list;
	while (*tmp != NULL) {
		C_LOGD("\tpermission: %s\n", *tmp);
		tmp++;
	}


	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;
	char *s_permission_name = NULL;
	int i;
	int i_app_id = 0;
	char *s_version = NULL;

	const char *s_permission_type_name = app_type_name(i_permission_type);
	const char *s_permission_group_type_name = app_type_group_name(i_permission_type);

	ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = get_app_id_internal(p_db, &i_app_id, s_app_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = get_app_version(p_db, s_app_label_name, &s_version);
	if (ret != PC_OPERATION_SUCCESS)
		goto finish;

	// Add permissions specific for the permission type:
	ret = change_app_permission_internal(p_db,
					     i_app_id,
					     s_version,
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
						     s_version,
						     s_permission_name,
						     s_permission_group_type_name,
						     b_is_volatile,
						     RDB_ENABLE);
		free(s_permission_name);
		if(ret != PC_OPERATION_SUCCESS) goto finish;
	}

	ret = add_modified_label_internal(p_db, s_app_label_name);

finish:
	free(s_version);
	return rdb_finish(p_db, ret);
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
	const char *s_permission_group_type_name = app_type_group_name(i_permission_type);

	ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);
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
		free(s_permission_name);
		if(ret != PC_OPERATION_SUCCESS) goto finish;
	}

	ret = add_modified_label_internal(p_db, s_app_label_name);

finish:
	return rdb_finish(p_db, ret);
}


int rdb_revoke_app_permissions(const char *const s_app_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_app_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_modified_label_internal(p_db, s_app_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_modified_apps_path_internal(p_db, s_app_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = revoke_app_permissions_internal(p_db, s_app_label_name);

finish:
	return rdb_finish(p_db, ret);
}


int rdb_reset_app_permissions(const char *const s_app_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_app_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = reset_app_permissions_internal(p_db, s_app_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_modified_label_internal(p_db, s_app_label_name);

finish:
	return rdb_finish(p_db, ret);
}


int rdb_add_additional_rules(const char *const *const pp_smack_rules)
{
	RDB_LOG_ENTRY;

	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	// Old rules may disappear, so mark as modified
	ret = add_modified_additional_rules_internal(p_db);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = add_additional_rules_internal(p_db, pp_smack_rules);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	// New rules appear, so also mark as modified
	ret = add_modified_additional_rules_internal(p_db);

finish:
	return rdb_finish(p_db, ret);
}

int rdb_app_has_permission(const char *const s_app_label_name,
			   const char *const s_permission_type_name,
			   const char *const s_permission_name,
			   bool *const p_is_enabled)
{
	RDB_LOG_ENTRY_PARAM("%s %s %s", s_app_label_name,
			    s_permission_type_name, s_permission_name);
	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_SHARED_READ); //shared readonly transaction
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = check_app_has_permission_internal(p_db,
						s_app_label_name,
						s_permission_name,
						s_permission_type_name,
						p_is_enabled);

finish:
	return rdb_finish(p_db, ret);
}

int rdb_app_get_permissions(const char *const s_app_label_name,
			    const char *const s_permission_type_name,
			    char ***ppp_perm_list)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_app_label_name, s_permission_type_name);

	int ret = PC_ERR_DB_OPERATION;
	int i_num_permissions;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_SHARED_READ);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = get_app_permissions_number_internal(p_db,
						  s_app_label_name,
						  s_permission_type_name,
						  &i_num_permissions);
	if (ret != PC_OPERATION_SUCCESS) goto finish;

	ret = get_app_permissions_internal(p_db,
					   s_app_label_name,
					   s_permission_type_name,
					   i_num_permissions,
					   ppp_perm_list);

finish:
	return rdb_finish(p_db, ret);
}

int rdb_get_permissions(char ***ppp_permissions, const char *const s_permission_type_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_permission_type_name);
	int ret = PC_ERR_DB_OPERATION;
	size_t i_permission_number;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_SHARED_READ);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = get_permission_number(p_db, &i_permission_number, s_permission_type_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = get_permissions_internal(p_db,
				       ppp_permissions,
				       i_permission_number,
				       s_permission_type_name);

finish:
	return rdb_finish(p_db, ret);
}

int rdb_get_apps_with_permission(perm_app_status_t **pp_apps,
				 size_t *pi_apps_number,
				 const char *const s_permission_type_name,
				 const char *const s_permission_name)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_permission_type_name, s_permission_name);
	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_SHARED_READ);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = get_apps_number(p_db,
			      pi_apps_number,
			      s_permission_type_name,
			      s_permission_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = get_apps_with_permission_internal(p_db,
						pp_apps,
						*pi_apps_number,
						s_permission_type_name,
						s_permission_name);

finish:
	return rdb_finish(p_db, ret);
}

int rdb_set_app_version(const char * const s_app_label_name,
		const char * const s_version)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_app_label_name, s_version);
	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);
	if (ret != PC_OPERATION_SUCCESS)
		goto finish;
	ret = set_app_version(p_db, s_app_label_name, s_version);

	finish: return rdb_finish(p_db, ret);
}

int rdb_get_app_version(const char * const s_app_label_name, char ** p_version)
{
	RDB_LOG_ENTRY_PARAM("%s", s_app_label_name);
	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_SHARED_READ);
	if (ret != PC_OPERATION_SUCCESS)
		goto finish;
	ret = get_app_version(p_db, s_app_label_name, p_version);

finish:
	ret = rdb_finish(p_db, ret);
	if ((ret != PC_OPERATION_SUCCESS) && *p_version) {
		free(*p_version);
		*p_version = NULL;
	}
	return ret;
}

int rdb_is_version_available(const char * const s_version) {
	RDB_LOG_ENTRY_PARAM("%s", s_version);
	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	ret = rdb_begin(&p_db, RDB_TRANSACTION_SHARED_READ);
	if (ret != PC_OPERATION_SUCCESS)
		goto finish;
	ret = is_version_available(p_db, s_version);

	finish: return rdb_finish(p_db, ret);
}

int rdb_remove_all_privileges_smack_rights(void)
{

	sqlite3 *p_db = NULL;
	int ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);
	if (ret != PC_OPERATION_SUCCESS)
		goto finish;
	ret = remove_all_privileges_smack_rights_internal(p_db);
	if (ret != PC_OPERATION_SUCCESS)
		goto finish;

	// Old rules may disappear, so mark all apps with any privilege
	// assigned as modified
	ret = add_modified_all_apps_with_any_permission(p_db);

	finish: return rdb_finish(p_db, ret);
}

int rdb_load_blacklist(const char * s_dir, const char * s_tizen_version) {
	char* path = NULL;
	FILE *file = NULL;
	char* line = NULL;
	size_t size;
	char* saveptr = NULL;
	char* permission = NULL;
	char* type = NULL;
	sqlite3 *p_db = NULL;
	int ret = 0;

	RDB_LOG_ENTRY_PARAM("%s", s_dir, s_tizen_version);

	if (!s_tizen_version)
		s_tizen_version = TIZEN_VERSION;

	ret = asprintf(&path, "%s/%s", s_dir, PERMISSIONS_FILTER);
	if (ret == -1) {
		C_LOGE("RDB: asprintf failed");
		goto finish;
	}

	ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);
	if (ret != PC_OPERATION_SUCCESS )
		goto finish;

	// mark existing blacklist permission rules as modified
	ret = add_modified_blacklist_permissions_internal(p_db, s_tizen_version);
	if (ret != PC_OPERATION_SUCCESS )
		goto finish;

	// remove existing blacklist and blacklist settings even if there's no file
	ret = clear_blacklist_settings(p_db, s_tizen_version);
	if (ret != PC_OPERATION_SUCCESS )
		goto finish;

	ret = remove_blacklist_permissions(p_db, s_tizen_version);
	if (ret != PC_OPERATION_SUCCESS )
		goto finish;

	file = fopen(path, "r");
	if (!file) {
		C_LOGW("RDB: Failed to open blacklist file: %s", path);
	} else {
		while (getline(&line, &size, file) > 0) {
			permission = strtok_r(line, " \t\r\n", &saveptr);
			if (!permission)
				continue;

			type = strtok_r(NULL, " \t\r\n", &saveptr);
			if (!type) {
				C_LOGE("RDB: Skipping permission %s with no type", permission);
				continue;
			}

			ret = add_to_blacklist(p_db, permission, type, s_tizen_version);

			// ignore errors and try to add another one
			if (ret != PC_OPERATION_SUCCESS ) {
				C_LOGE("RDB: Failed to add permission: %s of type: %s version: %s to blacklist.",
						permission, type, s_tizen_version);
			}
		}

		// mark new blacklist permission rules as modified
		ret = add_modified_blacklist_permissions_internal(p_db, s_tizen_version);
		if (ret != PC_OPERATION_SUCCESS )
			goto finish;
	}

finish:
	if (file != NULL )
		fclose(file);
	free(path);
	free(line);

	return rdb_finish(p_db, ret);
}

int rdb_update_blacklist_permissions(const char* const s_app_label_name,
		app_type_t i_permission_type, const char** pp_perm_list, bool b_enable)
{
	const char *type = app_type_name(i_permission_type);
	if (!type)
		return PC_ERR_INVALID_PARAM;
	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	RDB_LOG_ENTRY_PARAM("%s %s", s_app_label_name, type);

	ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);
	if (ret != PC_OPERATION_SUCCESS )
		goto finish;

	while (*pp_perm_list) {
		int app_id;
		int perm_id;
		char* base_api_perm_name AUTO_FREE;

		// try to parse it as http://tizen.org...
		ret = base_name_from_perm(*pp_perm_list, &base_api_perm_name);
		if (ret == PC_ERR_INVALID_PARAM){
			ret = find_blacklist_permission(p_db, s_app_label_name, type, *pp_perm_list, &app_id,
					&perm_id);
		} else if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("Error %d during creating base name from: %s", ret, pp_perm_list);
			goto finish;
		} else {
			ret = find_blacklist_permission(p_db, s_app_label_name, type, base_api_perm_name,
					&app_id, &perm_id);
		}

		if (ret != PC_OPERATION_SUCCESS )
			break;

		ret = update_blacklist_permission_internal(p_db, app_id, perm_id, b_enable ? 1 : 0);
		if (ret != PC_OPERATION_SUCCESS )
			break;
		pp_perm_list++;
	}
	// Mark app label as modified
	if (ret == PC_OPERATION_SUCCESS )
		ret = add_modified_label_internal(p_db, s_app_label_name);

finish:
	return rdb_finish(p_db, ret);
}

int rdb_get_blacklist_statuses(const char* const s_app_label_name,
		perm_blacklist_status_t** pp_perm_list, size_t* p_perm_number)
{
	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	RDB_LOG_ENTRY_PARAM("%s", s_app_label_name);

	ret = rdb_begin(&p_db, RDB_TRANSACTION_SHARED_READ);
	if (ret != PC_OPERATION_SUCCESS )
		goto finish;

	ret = get_blacklist_statuses_count_internal(p_db, s_app_label_name, p_perm_number);
	if (ret != PC_OPERATION_SUCCESS )
		goto finish;

	ret = get_blacklist_statuses_internal(p_db, s_app_label_name, pp_perm_list, *p_perm_number);
finish:
	return rdb_finish(p_db, ret);
}

int rdb_add_friend_entry(const char* s_pkg_id1, const char *s_pkg_id2) {
	int ret = PC_ERR_DB_OPERATION;
	sqlite3 *p_db = NULL;

	RDB_LOG_ENTRY_PARAM("%s %s", s_pkg_id1, s_pkg_id2);
	ret = rdb_begin(&p_db, RDB_TRANSACTION_EXCLUSIVE);

	ret = add_friend_entry_internal(p_db, s_pkg_id1, s_pkg_id2);
	if (ret != PC_OPERATION_SUCCESS)
		goto finish;

	ret = add_modified_label_internal(p_db, s_pkg_id1);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB: Failed to set label #1: %s as modified", s_pkg_id1);
		goto finish;
	};

	ret = add_modified_label_internal(p_db, s_pkg_id2);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB: Failed to set label #2: %s as modified", s_pkg_id2);
	};

finish:
	return rdb_finish(p_db, ret);
}
