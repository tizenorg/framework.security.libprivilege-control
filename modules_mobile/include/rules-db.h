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
#define RDB_BOOT_FILE_PATH "/opt/etc/smack/boot-rules.smack"
#define RDB_BOOT_FILE_PATH_NEW "/opt/etc/smack/boot-rules-new.smack"


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
 *
 */
void rdb_modification_finish(void);


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
 * Add permission with the given name and type and add smack rules.
 *
 * @ingroup RDB API functions
 *
 * @param  s_permission_name      new permission's name
 * @param  s_permission_type_name new permission's type
 * @param  pp_smack_rules         a table of smack accesses to apply
 * @return                        PC_OPERATION_SUCCESS on success,
 *                                error code otherwise
 */
int rdb_add_permission_rules(const char  *const s_permission_name,
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

#endif /*_RULES_DB_H_*/
