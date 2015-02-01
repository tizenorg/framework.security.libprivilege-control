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
 * @file        rules-db.h
 * @author      Jan Olszak (j.olszak@samsung.com)
 * @version     1.0
 * @brief       This file contains definition of rules database API.
 */

#ifndef _RULES_DB_H_
#define _RULES_DB_H_

#include "privilege-control.h" // For error codes
#include "common.h"

#define RDB_PATH "/opt/dbspace/.rules-db.db3"


/**
 * Starts a session with the database.
 * Begins transaction.
 *
 * @ingroup RDB API functions
 *
 * @return  PC_OPERATION_SUCCESS on success,
 *          error code otherwise
 */
int rdb_modification_start(void);


/**
 * Finishes the session with the database.
 * Commits or rollbacks.
 *
 * @ingroup RDB API functions
 * @return  PC_OPERATION_SUCCESS on success,
 *          error code of the session otherwise
 */
int rdb_modification_finish(void);


/**
 * Rollbacks last transaction and finishes session
 * with the database.
 *
 * @ingroup RDB API functions
 * @return  PC_OPERATION_SUCCESS on success,
 *          error code otherwise
 */
int rdb_modification_rollback(void);


/**
 * Add application label to the database.
 * If label present: do nothing.
 *
 * @ingroup RDB API functions
 *
 * @param  s_label_name s_label_name application label
 * @return              PC_OPERATION_SUCCESS on success,
 *                      error code otherwise
 */
int rdb_add_application(const char *const s_label_name);


/**
 * Remove application label from the table.
 * Used during uninstalling application.
 *
 * @ingroup RDB API functions
 *
 * @param  s_label_name application's label name
 * @return              PC_OPERATION_SUCCESS on success,
 *                      error code otherwise
 */
int rdb_remove_application(const char *const s_label_name);


/**
 * Add a path to the database.
 *
 * @ingroup RDB API functions
 *
 * @param  s_owner_label_name owner application's label name
 * @param  s_path_label_name  path's label name
 * @param  s_path             the path
 * @param  s_access           owner to path label access rights
 * @param  s_access_reverse   path label to owner access rights
 * @param  s_type             type of path
 * @return                    PC_OPERATION_SUCCESS on success,
 *                            error code otherwise
 */
int rdb_add_path(const char *const s_owner_label_name,
		 const char *const s_path_label_name,
		 const char *const s_path,
		 const char *const s_access,
		 const char *const s_access_reverse,
		 const char *const s_type);


/**
 * Get paths of the specified type for the given application.
 *
 * @ingroup RDB API functions
 *
 * @param s_app_label_name     application's label name
 * @param s_app_path_type_name name of the path type to get
 * @param ppp_paths            buffer for return value
 * @return                     PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int rdb_get_app_paths(const char *const s_app_label_name,
		      const char *const s_app_path_type_name,
		      char ***ppp_paths);


/**
 * Remove path and all rules associated with it from the database.
 *
 * @ingroup RDB API functions
 *
 * @param  s_owner_label_name owner application's label name
 * @param  s_path             the path
 * @return                    PC_OPERATION_SUCCESS on success,
 *                            error code otherwise
 */
int rdb_remove_path(const char *const s_owner_label_name,
		    const char *const s_path);


/**
 * Add permission with the given name and type and add smack rules.
 *
 * @ingroup RDB API functions
 *
 * @param  s_permission_name      new permission's name
 * @param  s_tizen_version        tizen version in format %d.%d.%d for which permission will be added
 * @param  s_permission_type_name new permission's type
 * @param  pp_smack_rules         a table of smack accesses to apply
 * @return                        PC_OPERATION_SUCCESS on success,
 *                                error code otherwise
 */
int rdb_add_permission_rules(const char  *const s_permission_name,
			     const char *const s_tizen_version,
			     const char  *const s_permission_type_name,
			     const char *const *const pp_smack_rules);


/**
 * Enable permissions from the list.
 * If there were no such permissions, we adds them.
 * One can't change permissions from non volatile to volatile,
 * One can change permissions from volatile to non volatile,
 * but it's suspicious...
 *
 * @ingroup RDB API functions
 *
 * @param  s_app_label_name       application's label name
 * @param  i_permission_type      permission's type id
 * @param  pp_permissions_list    array of permissions to parse
 * @param  b_is_volatile          are the new permissions volatile
 * @return                        PC_OPERATION_SUCCESS on success,
 *                                error code otherwise
 */
int rdb_enable_app_permissions(const char  *const s_app_label_name,
			       const app_type_t i_permission_type,
			       const char *const *const pp_permissions_list,
			       const bool b_is_volatile);


/**
 * Disable permissions from the list.
 *
 * @ingroup RDB API functions
 *
 * @param  s_app_label_name       application's label name
 * @param  i_permission_type      permission's type id
 * @param  pp_permissions_list    array of permissions to parse
 * @return                        PC_OPERATION_SUCCESS on success,
 *                                error code otherwise
 */
int rdb_disable_app_permissions(const char  *const s_app_label_name,
				const app_type_t i_permission_type,
				const char *const *const pp_permissions_list);


/**
 * Revokes all permissions from the application by.
 * deleting all permissions from app_permission table.
 *
 * @ingroup RDB API functions
 *
 * @param  s_app_label_name application's label name
 * @return                  PC_OPERATION_SUCCESS on success,
 *                          error code otherwise
 */
int rdb_revoke_app_permissions(const char *const s_app_label_name);


/**
 * Revokes all volatile permissions from the application by.
 * deleting all permissions from app_permission table.
 *
 * @ingroup RDB API functions
 *
 * @param  s_app_label_name application's label name
 * @return                  PC_OPERATION_SUCCESS on success,
 *                          error code otherwise
 */
int rdb_reset_app_permissions(const char *const s_app_label_name);

/**
 * Add the additional rules to the database. Erase the previous rules.
 *
 * @ingroup RDB API functions
 *
 * @param  pp_smack_rules NULL terminated table of rules
 * @return                PC_OPERATION_SUCCESS on success,
 *                        error code otherwise
 */
int rdb_add_additional_rules(const char *const *const pp_smack_rules);


/**
 * Check if app has the privilege that is specified by the name.
 *
 * @ingroup RDB API functions
 *
 * @param  s_app_label_name       application's label name
 * @param  s_permission_type_name permission's type name
 * @param  s_permission_name      permission name
 * @param  p_is_enabled           buffer for return value
 * @return                        PC_OPERATION_SUCCESS on success,
 *                                error code otherwise
 */
int rdb_app_has_permission(const char *const s_app_label_name,
			   const char *const s_permission_type_name,
			   const char *const s_permission_name,
			   bool *const p_is_enabled);

/**
 * Get permissions for the specified app.
 *
 * @ingroup RDB API functions
 *
 * @param  s_app_label_name       application label's name
 * @param  s_permission_type_name permission type's name
 * @param  ppp_perm_list          buffer for return value
 * @return                        PC_OPERATION_SUCCESS on success,
 *                                error code otherwise
 */
int rdb_app_get_permissions(const char *const s_app_label_name,
			    const char *const s_permission_type_name,
			    char ***ppp_perm_list);

/**
 *  Get the list of the permissions for given application type.
 *
 * @ingroup RDB API functions
 *
 * @param ppp_permissions        buffer for all of the found permissions
 * @param s_permission_type_name permission's type
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int rdb_get_permissions(char ***ppp_permissions, const char *const s_permission_type_name);

/**
 * Get the list of apps for given app type with given permission.
 *
 * @ingroup RDB API functions
 *
 * @param pp_apps                list of application's statuses
 * @param pi_apps_number         number of found apps
 * @param s_permission_type_name permission's type
 * @param s_permission_name      permission's name
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int rdb_get_apps_with_permission(perm_app_status_t **pp_apps,
				 size_t *pi_apps_number,
				 const char *const s_permission_type_name,
				 const char *const s_permission_name);

/**
 * Set privilege version for specific app.
 *
 * @ingroup RDB API functions
 *
 * @param s_app_label_name       application's label name
 * @param s_version              version to set
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int rdb_set_app_version(const char * const s_app_label_name,
		const char * const s_version);

/**
 * Get privilege version for specific app.
 *
 * @ingroup RDB API functions
 *
 * @param s_app_label_name       application's label name
 * @param p_version              return version
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int rdb_get_app_version(const char * const s_app_label_name, char **p_version);

/**
 * Remove all privileges smack rights from database
 */
int rdb_remove_all_privileges_smack_rights(void);

/**
 * Reloads permission blacklist
 *
 * @ingroup RDB API functions
 *
 * @param  s_dir                 Directory containing permission black list file
 * @param  s_tizen_version       tizen version
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int rdb_load_blacklist(const char * s_dir, const char * s_tizen_version);

/**
 * Updates blacklist permissions
 *
 * @ingroup RDB API functions
 *
 * @param s_app_label_name       application's label name
 * @param i_permission_type      permission type
 * @param pp_perm_list           list of permissions to enable
 * @param b_enable               enable/disable flag
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int rdb_update_blacklist_permissions(const char* const s_app_label_name,
		app_type_t i_permission_type, const char** pp_perm_list, bool b_enable);

/**
 * Returns blacklist permission statuses
 *
 * @ingroup RDB API functions
 *
 * @param  s_app_label_name      application's label name
 * @param  pp_perm_list          array for permission statuses
 * @param  p_perm_number         number of permissions found
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int rdb_get_blacklist_statuses(const char* const s_app_label_name,
		perm_blacklist_status_t** pp_perm_list, size_t* p_perm_number);

/**
 * Adds two applications as friends
 *
 * @ingroup RDB API functions
 *
 * @param  s_pkg_id1             application #1 label name
 * @param  s_pkg_id2             application #2 label name
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int rdb_add_friend_entry(const char* s_pkg_id1, const char *s_pkg_id2);

#endif /*_RULES_DB_H_*/
