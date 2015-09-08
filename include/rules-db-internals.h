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
 * @file        rules-db-internals.h
 * @author      Jan Olszak (j.olszak@samsung.com)
 * @version     1.0
 * @brief       This file contains definition of rules database API.
 */

#include <sqlite3.h>
#include "rules-db.h"

#ifndef _RULES_DB_INTERNALS_H_
#define _RULES_DB_INTERNALS_H_

#define ACC_LEN 6

// Templates:
#define SMACK_APP_LABEL_TEMPLATE "~APP~"

// Open database flags:
#define RDB_READWRITE_FLAG SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_PRIVATECACHE
#define RDB_READONLY_FLAG SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_PRIVATECACHE

// Bind function defines:
#define RDB_FIRST_PARAM  1 /// Bind to the first parameter
#define RDB_SECOND_PARAM 2 /// Bind to the second parameter

#define RDB_AUTO_DETERM_SIZE -1 // Determine the size of the

// Getting values
#define RDB_FIRST_COLUMN  0
#define RDB_SECOND_COLUMN 1
#define RDB_THIRD_COLUMN  2
#define RDB_FOURTH_COLUMN 3

#define RDB_DISABLE 0
#define RDB_ENABLE  1

#define RDB_LOG_ENTRY_PARAM(format, ...) C_LOGD("RDB: Entering function %s. Args: " format, __func__, ##__VA_ARGS__)
#define RDB_LOG_ENTRY C_LOGD("RDB: Entering function %s", __func__)


/**
 * Add the label to the temporary table with modified labels.
 * We use this table to speed up generating modified smack rules.
 *
 * If label is not in this table, but rule changed
 * Smack will not get the rule in runtime.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db         pointer to a SQLite3 database object
 * @param  s_label_name label name
 * @return              PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_modified_label_internal(sqlite3 *p_db, const char *const s_label_name);


/**
 * Adds label names of applications with the permission to modified labels.
 * Used when permission is going to change or have changed and we're going to
 * change some accesses granted by this permission.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db            pointer to a SQLite3 database object
 * @return                 PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_modified_permission_internal(sqlite3 *p_db, sqlite3_int64 i_permission_id);


/**
 * Adds to modified labels all label names of applications that have at least
 * one permission assigned and enabled.
 * Used when permissions rules have been cleared, to refresh smack accesses.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db            pointer to a SQLite3 database object
 * @return                 PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_modified_all_apps_with_any_permission(sqlite3 *p_db);


/**
 * Adds all label names from additional rules to modified labels.
 * Used when additional rules are inserted into the database.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db  pointer to a SQLite3 database object
 * @return       PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_modified_additional_rules_internal(sqlite3 *p_db);


/**
 * Adds label names of the application's folders to the modified labels.
 * Used during removing application.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db             pointer to a SQLite3 database object
 * @param  s_app_label_name label of the application
 * @return                  PC_OPERATION_SUCCESS on success,
 *                          error code otherwise
 */
int add_modified_apps_path_internal(sqlite3 *p_db, const char *const s_app_label_name);

/**
 * Adds path label's name to the modified labels.
 * Used during removing path.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db   pointer to a SQLite3 database object
 * @param  s_path the path
 * @return        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_modified_paths_label_internal(sqlite3 *p_db, const char *const s_path);

/**
 * Adds label names of applications with the blacklist permissions to modified labels.
 * Used when blacklist permission is going to change and we're going to change some
 * accesses granted by this permission.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db   				pointer to a SQLite3 database object
 * @param  s_path 				the path
 * @param  s_tizen_version      tizen version in format %d.%d.%d
 * @return        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_modified_blacklist_permissions_internal(sqlite3 *p_db, const char * const s_tizen_version);

/**
 * Open a connection with the database and perform an initialization.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                      pointer to a SQLite3 database object
 * @param  b_create_temporary_tables variable denoting if temporary tables should be created
 * @return                           PC_OPERATION_SUCCESS on success, error code otherwise
 */
int open_rdb_connection(sqlite3 **pp_db, bool b_create_temporary_tables);


/**
 * Write variables into the query and create a SQLite statement.
 * One should use the SQLite3 format strings like '%Q'.
 *
 * For a lot of generic queries use binding.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db    pointer to a SQLite3 database object
 * @param  pp_stmt buffer for a pointer to the constructed statement
 * @return         PC_OPERATION_SUCCESS on success, error code otherwise
 */
int prepare_stmt(sqlite3 *p_db,
		 sqlite3_stmt **pp_stmt,
		 const char   *const s_sql,
		 ...);

/**
 * Check if the label is available for an application.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db         pointer to a SQLite3 database object
 * @param  s_label_name application's label name
 * @return              PC_OPERATION_SUCCESS when label free
 *                      PC_ERR_DB_LABEL_TAKEN when label taken
 *                      error code otherwise
 */
int check_app_label_internal(sqlite3 *p_db,
			     const char  *const s_label_name);


/**
 * Adds the application to the database.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db         pointer to a SQLite3 database object
 * @param  s_label_name application's label name
 * @return              PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_app_internal(sqlite3 *p_db,
		     const char  *const s_label_name);


/**
 * Removes the application from the database together with its permissions and paths.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db         pointer to a SQLite3 database object
 * @param  s_label_name application's label name
 * @return              PC_OPERATION_SUCCESS on success, error code otherwise
 */
int remove_app_internal(sqlite3 *p_db,
			const char   *const s_label_name);


/**
 * Add a path to the database
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db               pointer to a SQLite3 database object
 * @param  s_owner_label_name label name of the paths owner
 * @param  s_path_label_name  path's label name
 * @param  s_path             the path
 * @param  s_access           owner to path label access rights
 * @param  s_access_reverse   path label to owner access rights
 * @param  s_type             path's type name
 * @return                    PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_path_internal(sqlite3 *p_db,
		      const char *const s_owner_label_name,
		      const char *const s_path_label_name,
		      const char *const s_path,
		      const char *const s_access,
		      const char *const s_access_reverse,
		      const char *const s_type);

/**
 * Remove path for the specified application and delete it's label if it's no longer used.
 *
 * @param  p_db               pointer to a SQLite3 database object
 * @param  s_owner_label_name owner application
 * @param  s_path             the path
 * @return                    PC_OPERATION_SUCCESS on success, error code otherwise
 */
int remove_path_internal(sqlite3 *p_db,
			 const char *const s_owner_label_name,
			 const char *const s_path);


/**
 * Get number of paths of the specified type for the given application.
 *
 * @param  p_db                 pointer to a SQLite3 database object
 * @param  s_app_label_name     application's label name
 * @param  s_app_path_type_name name of the path type to get
 * @param  p_num_paths          buffer for the return value
 * @return                      PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int get_app_paths_count_internal(sqlite3 *p_db,
				 const char *const s_app_label_name,
				 const char *const s_app_path_type_name,
				 int *const p_num_paths);


/**
 * Get paths of the specified type for the given application.
 *
 * @ingroup RDB API functions
 *
 * @param  p_db                 pointer to a SQLite3 database object
 * @param  s_app_label_name     application's label name
 * @param  s_app_path_type_name name of the path type to get
 * @param  i_num_paths          number of paths
 * @param  ppp_paths            buffer for return value
 * @return                      PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int get_app_paths_internal(sqlite3 *p_db,
			   const char *const s_app_label_name,
			   const char *const s_app_path_type_name,
			   const int i_num_paths,
			   char ***ppp_paths);


/**
 * Add a permission with a given name and of a give type
 * and return its internal permission id.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  s_permission_name      permission name
 * @param  s_permission_type_name permission type name
 * @param  s_tizen_version        tizen version in format %d.%d.%d for which permission will be added
 * @param  fast                   informs not to delete old rules during redefining permission.
 *                                it makes it run faster, but be caution using this durig
 *                                api-feature redefinition: not all rules will be deleted.
 * @return                        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_permission_internal(sqlite3 *p_db,
			    const char *const s_permission_name,
			    const char *const s_tizen_version,
                            const char *const s_permission_type_name,
                            bool fast);

/**
 * Gets the id of the permission
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  s_permission_name      permission name
 * @param  s_tizen_version        tizen version in format %d.%d.%d for which permission will be returned
 * @param  s_permission_type_name permission type name
 * @param  p_permission_id        buffer for the id of the new permission
 * @return                        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int get_permission_id_internal(sqlite3 *p_db,
			       const char *const s_permission_name,
			       const char *const s_tizen_version,
			       const char *const s_permission_type_name,
			       sqlite3_int64 *p_permission_id);

/**
 * Adds a list of smack permissions to the database.
 * s_permision_name has to appear either in the subject or the object of the rule.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db            pointer to a SQLite3 database object
 * @param  i_permission_id permission id for which we ad permission rules
 * @param  pp_smack_rules  a list of smack rules, that we want to apply. Not empty!
 * @return                 PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_permission_rules_internal(sqlite3 *p_db,
				  sqlite3_int64 i_permission_id,
				  const char  *const *const pp_smack_rules);


/**
 * Check if an app has a permission that is specified by the name.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  i_app_id               application id
 * @param  s_permission_name      permission name
 * @param  s_permission_type_name permission type name
 * @param  p_is_enabled           buffer for return value
 * @return                        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int check_app_has_permission_internal(sqlite3 *p_db,
				      const char *const s_app_label_name,
				      const char *const s_permission_name,
				      const char *const s_permission_type_name,
				      bool *const p_is_enabled);

/**
 * Get number of the permissions for given application type.
 *
 * @ingroup RDB internal functions
 *
 * @param p_db                   pointer to a SQLite3 database object
 * @param pi_permission_number   number of found permissions
 * @param s_permission_type_name permission's type
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int get_permission_number(sqlite3 *p_db,
			  size_t *pi_permission_number,
			  const char *const s_permission_type_name);

/**
 * Get the list of the permissions for given application type.
 *
 * @ingroup RDB internal functions
 *
 * @param p_db                   pointer to a SQLite3 database object
 * @param ppp_permissions        list of all permissions
 * @param i_permission_number    number of found permissions
 * @param s_permission_type_name permission's type

 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int get_permissions_internal(sqlite3 *p_db,
			     char ***ppp_permissions,
			     size_t i_permission_number,
			     const char *const s_permission_type_name);

/**
 * Get number of apps for given app type with given permission.
 *
 * @ingroup RDB internal functions
 *
 * @param p_db                   pointer to a SQLite3 database object
 * @param pi_apps_number         number of found apps
 * @param s_permission_type_name permission's type
 * @param s_permission_name      permission's name
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int get_apps_number(sqlite3 *p_db,
		    size_t *pi_apps_number,
		    const char *const s_permission_type_name,
		    const char *const s_permission_name);

/**
 * Get the list of the applications's statuses of given type with particular permission.
 *
 * @ingroup RDB internal functions
 *
 * @param p_db                   pointer to a SQLite3 database object
 * @param pp_apps                list of application's statuses
 * @param i_apps_number          number of found applicationa
 * @param s_permission_type_name permission's type
 * @param s_permission_name      permission's name
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int get_apps_with_permission_internal(sqlite3 *p_db,
				      perm_app_status_t **pp_apps,
				      size_t i_apps_number,
				      const char *const s_permission_type_name,
				      const char *const s_permission_name);

/**
 * Get number of permission of a certain type for the specified app.
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  s_app_label_name       application label's name
 * @param  s_permission_type_name permission type's name
 * @param  p_num_permissions      buffer for return value
 * @return                        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int get_app_permissions_number_internal(sqlite3  *p_db,
					const char *const s_app_label_name,
					const char *const s_permission_type_name,
					int *const p_num_permissions);

/**
 * Get permissions for the specified app.
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  s_app_label_name       application label's name
 * @param  s_permission_type_name permission type's name
 * @param  i_num_permissions      number of permissions of the specified type
 * @param  ppp_perm_list          buffer for return value
 * @return                        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int get_app_permissions_internal(sqlite3 *p_db,
				 const char *const s_app_label_name,
				 const char *const s_permission_type_name,
				 const int i_num_permissions,
				 char ***ppp_perm_list);


/**
 * Gets the internal app id of an application with a given name.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db             pointer to a SQLite3 database object
 * @param  pi_app_id        pointer to where the app is should be returned
 * @param  s_app_label_name label name of the application
 * @return                  PC_OPERATION_SUCCESS on success, error code otherwise
 */
int get_app_id_internal(sqlite3 *p_db,
			int *pi_app_id,
			const char *const s_app_label_name);


/**
 * Add a new permission to an application.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  i_app_id               application id
 * @param  s_permission_name      permission name
 * @param  s_permission_type_name permission type name
 * @param  b_is_volatile_new      is the permission volatile
 * @param  b_is_enabled_new       is the permission enabled
 * @return                        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_app_permission_internal(sqlite3 *p_db,
				int i_app_id,
				const char *const s_permission_name,
				const char *const s_permission_type_name,
				const bool b_is_volatile_new,
				const bool b_is_enabled_new);


/**
 * Enable or disable a permission for a given application.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  i_app_id               application id
 * @param  s_permission_name      permission name
 * @param  s_permission_type_name permission type name
 * @param  b_is_enabled_new       is the permission enabled
 * @return                        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int switch_app_permission_internal(sqlite3 *p_db,
				   const int i_app_id,
				   const char *const s_permission_name,
				   const char *const s_permission_type_name,
				   const bool b_is_enabled_new);


/**
 * Update an existing permission of an application.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db              pointer to a SQLite3 database object
 * @param  i_app_id          application id
 * @param  i_permission_id   id of the permission
 * @param  b_is_volatile_new is the permission volatile
 * @param  b_is_enabled_new  is the permission enabled
 * @return                   PC_OPERATION_SUCCESS on success, error code otherwise
 */
int update_app_permission_internal(sqlite3 *p_db,
				   const int i_app_id,
				   const sqlite3_int64 i_permission_id,
				   const bool b_is_volatile_new,
				   const bool b_is_enabled_new);


/**
 * Change a permission for an application.
 * Function modifies or adds a permission.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  i_app_id               application id
 * @param  s_permission_name      permission name
 * @param  s_permission_type_name permission type name
 * @param  i_is_volatile_new      is the permission volatile
 * @param  i_is_enabled_new       is the permission enabled
 * @return                        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int change_app_permission_internal(sqlite3 *p_db,
				   int i_app_id,
				   const char *const s_version,
				   const char *const s_permission_name,
				   const char *const s_permission_type_name,
				   int i_is_volatile_new,
				   int i_is_enabled_new);


/**
 * Delete all permissions of the application.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db             pointer to a SQLite3 database object
 * @param  s_app_label_name applications label name
 * @return                  PC_OPERATION_SUCCESS on success, error code otherwise
 */
int revoke_app_permissions_internal(sqlite3 *p_db,
				    const char *const s_app_label_name);


/**
 * Delete all volatile permissions of the application.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db             pointer to a SQLite3 database object
 * @param  s_app_label_name applications label name
 * @return                  PC_OPERATION_SUCCESS on success, error code otherwise
 */
int reset_app_permissions_internal(sqlite3 *p_db,
				   const char *const s_app_label_name);


/**
 * Prepare tables with smack rules.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db pointer to a SQLite3 database object
 * @return      PC_OPERATION_SUCCESS on success, error code otherwise
 */
int update_rules_in_db(sqlite3 *p_db);


/**
 * Updates smack rules. Only rules that change are refreshed.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db pointer to a SQLite3 database object
 * @return      PC_OPERATION_SUCCESS on success, error code otherwise
 */
int update_smack_rules(sqlite3 *p_db);


/**
 * Add additional rules to the database.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db           pointer to a SQLite3 database object
 * @param  pp_smack_rules a list of smack rules
 * @return                PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_additional_rules_internal(sqlite3 *p_db,
				  const char  *const *const pp_smack_rules);

/**
 * Set privilege version for specific app.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                  pointer to a SQLite3 database object
 * @param  s_app_label_name      application's label name
 * @param  s_version             version to set
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int set_app_version(sqlite3 *p_db, const char * const s_app_label_name,
        const char * const s_version);

/**
 * Get privilege version for specific app.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                  pointer to a SQLite3 database object
 * @param  s_app_label_name      application's label name
 * @param  p_version             return version
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int get_app_version(sqlite3 *p_db, const char * const s_app_label_name,
            char **p_version);

/**
 * Remove all privileges' smack rights
 */
int remove_all_privileges_smack_rights_internal(sqlite3 *p_db);

/**
 * Clears blacklist settings.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                  pointer to a SQLite3 database object
 * @param  s_tizen_version       permission version
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int clear_blacklist_settings(sqlite3 *p_db, const char* const s_tizen_version);

/**
 * Removes all permissions from blacklist
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                  pointer to a SQLite3 database object
 * @param  s_tizen_version       permission version
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int remove_blacklist_permissions(sqlite3 *p_db, const char* const s_tizen_version);

/**
 * Adds permission to blacklist.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                  pointer to a SQLite3 database object
 * @param  s_permission          permission name
 * @param  s_type                permissison type
 * @param  s_tizen_version       permission version
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int add_to_blacklist(sqlite3* p_db, const char* const s_permission, const char* const s_type,
		const char* const s_tizen_version);

/**
 * Finds blacklist permission of given name, app and type
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  s_app_label_name       application's label name
 * @param  s_perm_type            permission type
 * @param  s_permission_name      permission name
 * @param  p_app_id               pointer to application id
 * @param  p_perm_id              pointer to permission id
 * @return                        PC_OPERATION_SUCCESS on success,
 *                                PC_ERR_* on error
 */
int find_blacklist_permission(sqlite3* p_db, const char* const s_app_label_name,
		const char* const s_perm_type, const char* const s_permission_name, int* p_app_id,
		int* p_perm_id);

/**
 * Updates blacklist permissions for given app permission
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  i_app_id               application id
 * @param  i_perm_id              permission id
 * @param  i_enabled              blacklist permission setting
 * @return                        PC_OPERATION_SUCCESS on success,
 *                                PC_ERR_* on error
 */
int update_blacklist_permission_internal(sqlite3* p_db, int i_app_id, int i_perm_id, int i_enabled);

/**
 * Returns blacklist permissions' statuses count
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  s_app_label_name       application's label name
 * @param  p_perm_number          number of statuses
 * @return                        PC_OPERATION_SUCCESS on success,
 *                                PC_ERR_* on error
 */
int get_blacklist_statuses_count_internal(sqlite3* p_db, const char* const s_app_label_name,
		size_t* p_perm_number);

/**
 * Returns blacklist permissions' statuses
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  s_app_label_name       application's label name
 * @param  pp_perm_list           array for permission statuses
 * @param  i_perm_number          number of statuses
 * @return                        PC_OPERATION_SUCCESS on success,
 *                                PC_ERR_* on error
 */
int get_blacklist_statuses_internal(sqlite3* p_db, const char* const s_app_label_name,
		perm_blacklist_status_t** pp_perm_list, size_t i_perm_number);

/**
 * Adds two applications as friends
 *
 * @ingroup RDB internal functions
 *
 * @param  s_pkg_id1             application #1 label name
 * @param  s_pkg_id2             application #2 label name
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int add_friend_entry_internal(sqlite3* p_db, const char* const s_pkg_id1,
		const char* const s_pkg_id2);
#endif // _RULES_DB_INTERNALS_H_
