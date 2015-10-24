/*
 * libprivilege control
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Kidong Kim <kd0228.kim@samsung.com>
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

#include <stdbool.h>
#include <sys/types.h>
#include <security-server-perm-types.h>

#ifndef _PRIVILEGE_CONTROL_H_
#define _PRIVILEGE_CONTROL_H_

/* Macros for converting preprocessor token to string */
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifndef API
#define API __attribute__((visibility("default")))
#endif // API

#define DEPRECATED __attribute__((deprecated))
#define UNUSED __attribute__((unused))

/* error codes */
#define	PC_OPERATION_SUCCESS		((int)0)
#define PC_ERR_FILE_OPERATION		-1
#define PC_ERR_MEM_OPERATION		-2
#define PC_ERR_NOT_PERMITTED		-3
#define PC_ERR_INVALID_PARAM		-4
#define PC_ERR_INVALID_OPERATION	-5
#define PC_ERR_DB_OPERATION		-6

/// Label is taken by another application
#define PC_ERR_DB_LABEL_TAKEN           -7

/// Query fails during preparing a SQL statement
#define PC_ERR_DB_QUERY_PREP            -8

/// Query fails during binding to a SQL statement
#define PC_ERR_DB_QUERY_BIND            -9

/// Query fails during stepping a SQL statement
#define PC_ERR_DB_QUERY_STEP            -10

/// Unable to establish a connection with the database
#define PC_ERR_DB_CONNECTION            -11

/// There is no application with such app_id
#define PC_ERR_DB_NO_SUCH_APP           -12

/// There already exists a permission with this name and type
#define PC_ERR_DB_PERM_FORBIDDEN        -13


/**
 * Gets smack label of a process, based on its pid.
 *
 * @param  pid          pid of process
 * @param  smack_label  label of process
 * @return              PC_OPERATION_SUCCESS on success PC_ERR_* on error.
 */
int get_smack_label_from_process(pid_t pid, char *smack_label);

/**
 * Checks if process with pid has access to object.
 * This function checks if subject has access to object via smack_have_access() function.
 * If YES then returns access granted. In NO then function checks if process with pid has
 * CAP_MAC_OVERRIDE capability. If YES then returns access granted.
 * If NO then returns access denied.
 *
 * @param  pid          pid of process
 * @param  object       label of object to access
 * @param  access_type  smack access type.
 * @return              0 (no access) or 1 (access) or -1 (error)
 */
int smack_pid_have_access(pid_t pid,
			  const char *object,
			  const char *access_type);

/**
 * Set DAC and SMACK privileges for application.
 * This function is meant to be called by the application launcher just before
 * it launches an application. It will setup DAC and SMACK privileges based
 * on app type and accesses.
 * It must be called with root privileges, which will be dropped in the function.
 *
 * @param  name  package name
 * @param  type  application type (currently distinguished types:
 *               "wgt", "wgt_partner", "wgt_platform",
 *               "tpk", "osp", "osp_partner", "osp_platform",
 *               "rpm", "efl")
 * @param  path  file system path to the binary
 * @return       PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_set_privilege(const char* name, const char* type, const char* path);

/**
 * Set DAC and SMACK privileges for application.
 * This function is meant to be called by the debug application launcher just before
 * it launches an application. It will setup DAC and SMACK privileges based
 * on app type and accesses.
 * It must be called with root privileges, which will be dropped in the function.
 *
 * @param  name  package name
 * @param  type  application type (currently distinguished types:
 *               "wgt", "wgt_partner", "wgt_platform" and other)
 * @param  path  file system path to the binary
 * @return       PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_set_privilege_debug(const char* name, const char* type, const char* path);

/**
 * For a UNIX socket endpoint determine the other side's pkg_id. Caller is
 * responsible for freeing the return widget id.
 *
 * @param  sockfd  socket file descriptor
 * @return         id of the connecting widget on success, NULL on failure.
 */
char* perm_app_id_from_socket(int sockfd);

/**
 * Adds an application to the database if it doesn't already exist. It is needed
 * for tracking lifetime of an application. It must be called by privileged
 * user, before using any other perm_app_* function regarding that application.
 * It must be called within database transaction started with perm_begin() and
 * finished with perm_end(). It may be called more than once during installation.
 *
 * @param  pkg_id  application identifier
 * @return         PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_install(const char* pkg_id);

/**
 * Removes an application from the database with it's permissions, rules and
 * directories, enabling future installation of the application with the same
 * pkg_id. It is needed for tracking lifetime of an application. It must be
 * called by privileged user and within database transaction started with
 * perm_begin() and finished with perm_end().
 *
 * @param  pkg_id  application identifier
 * @return         PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_uninstall(const char* pkg_id);

/**
 * Grants SMACK permissions to an application, based on permissions list. It is
 * intended to be called during that application installation. The permissions
 * will be persistent. It must be called by privileged user and within database
 * transaction started with perm_begin() and finished with perm_end().
 *
 * @param  pkg_id     application identifier
 * @param  app_type   application type
 * @param  perm_list  array of permission names, last element must be NULL
 * @return            PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_setup_permissions(const char* pkg_id, app_type_t app_type,
			       const char** perm_list);

/**
 * Grants SMACK permissions to an application, based on permissions list. It was
 * intended to be called during that application installation. Permissions
 * granted as volatile will not be present after system boot. It must be called
 * by privileged user and within database transaction started with perm_begin()
 * and finished with perm_end().
 * In new code please call perm_app_setup_permissions during your application
 * installation instead of this function.
 *
 * @param  pkg_id      application identifier
 * @param  app_type    application type
 * @param  perm_list   array of permission names, last element must be NULL
 * @param  persistent  boolean for choosing between persistent and temporary rules
 * @return             PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_enable_permissions(const char* pkg_id, app_type_t app_type, const char** perm_list, bool persistent);

/**
 * Removes previously granted SMACK permissions based on permissions list.
 * It will remove given permissions from an application, leaving other granted
 * permissions untouched. Results will be persistent. It must be called by
 * privileged user and within database transaction started with perm_begin()
 * and finished with perm_end().
 *
 * @param  pkg_id     application identifier
 * @param  app_type   application type
 * @param  perm_list  array of permission names, last element must be NULL
 * @return            PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_disable_permissions(const char* pkg_id, app_type_t app_type, const char** perm_list);

/**
 * Removes all application's permissions, rules and directories registered in
 * the database. It must be called by privileged user and within database
 * transaction started with perm_begin() and finished with perm_end().
 *
 * @param  pkg_id  application identifier
 * @return         PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_revoke_permissions(const char* pkg_id);

/**
 * Removes all application's permissions which are not persistent. It must be
 * called by privileged user and within database transaction started with
 * perm_begin() and finished with perm_end().
 *
 * @param  pkg_id  application identifier
 * @return         PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_reset_permissions(const char* pkg_id);

/**
 * Checks if an application has the privilege that is specified by the name.
 * It must be called by privileged user.
 *
 * @param  pkg_id           application identifier
 * @param  app_type         application type
 * @param  permission_name  permission name
 * @param  is_enabled       buffer for return value
 * @return                  PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_has_permission(const char *pkg_id,
			    app_type_t app_type,
			    const char *permission_name,
			    bool *is_enabled);

/**
 * Get the list of the permissions for given application type
 * Caller is responsible for freeing allocated memory.
 * *ppp_permissions is a pointer to an array consisting of char pointers,
 * terminated with NULL pointer. Memory allocated with each
 * of these pointer except for the last one (NULL) should be freed,
 * followed by freeing *ppp_permissions itself.
 *
 * @param ppp_permissions list of all permissions
 * @param app_type        application type
 * @return                PC_OPERATION_SUCCESS on success,
 *                        PC_ERR_* on error
 */
int perm_get_permissions(char ***ppp_permissions, app_type_t app_type);

/**
 * Get the list of the applications of given type with particular permission.
 * Caller is responsible for freeing allocated memory
 * using perm_free_apps_list()
 *
 * @param pp_apps           list of application's statuses
 * @param pi_apps_number    number of found application
 * @param app_type          application type
 * @param s_permission_name permission name
 * @return                  PC_OPERATION_SUCCESS on success,
 *                          PC_ERR_* on error
 */
int perm_get_apps_with_permission(perm_app_status_t **pp_apps,
				  size_t *pi_apps_number,
				  app_type_t app_type,
				  const char *s_permission_name);

/**
 * Free the list of the applications allocated with
 * perm_get_apps_with_permission().
 *
 * @param pp_apps       list of application's statuses
 * @param i_apps_number number of applications on the list
 */
void perm_free_apps_list(perm_app_status_t *pp_apps,
			 size_t i_apps_number);

/**
 * Get permissions for the specified app.
 *
 * In case of success caller is responsible for freeing memory allocated by it.
 * Each cell in *ppp_perm_list except for the last (NULL) should be freed, followed by freeing
 * *ppp_perm_list itself.
 *
 * In case of error an error code is returned and, provided that ppp_perm_list is not NULL,
 * *ppp_perm_list is set to NULL.
 *
 * @param  pkg_id        application identifier
 * @param  app_type      application type
 * @param  ppp_perm_list buffer for return value
 * @return               PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_get_permissions(const char *pkg_id, app_type_t app_type, char ***ppp_perm_list);

/**
 * Sets SMACK labels for an application directory (recursively) or for an executable/symlink
 * file. The exact behavior depends on app_path_type argument:
 * 	- APP_PATH_PRIVATE: label with app's label, set access label on everything
 *    and execute label on executable files and symlinks to executable files
 *
 * 	- APP_PATH_GROUP: label with given shared_label, set access label on
 * 	  everything and enable transmute on directories. Also give pkg_id full access
 * 	  to the shared label.
 *
 * 	- APP_PATH_PUBLIC: label with autogenerated label, set access label on
 * 	  everything and enable transmute on directories. Give full access to the label to
 * 	  pkg_id and RX access to all other applications.
 *
 * 	- APP_PATH_SETTINGS: label with autogenerated label, set access label on
 * 	  everything and enable transmute on directories. Give full access to the label to
 * 	  pkg_id and RWX access to all appsetting applications.
 *
 * 	- PERM_APP_PATH_NPRUNTIME: label executable file or symlink to an exec given in path param
 * 	  with label "<pkg_id>.npruntime". Set execute label on it.
 * 	  Give pkg_id RW access to new created label and give new label RXAT access to pkg_id.
 *
 * 	- APP_PATH_ANY_LABEL: label with given shared_label. Set access label on
 * 	  everything and execute label on executable files and symlinks to
 * 	  executable files.
 *
 * This function should be called during application installation. Results will
 * be persistent on the file system. It must be called by privileged user and
 * within database transaction started with perm_begin() and finished with
 * perm_end().
 *
 * @param  pkg_id         application identifier
 * @param  path           file or directory path
 * @param  app_path_type  application path type
 * @param  shared_label   optional argument for APP_PATH_GROUP_RW and
 *                        APP_PATH_ANY_LABEL path type; type is const char*
 * @return                PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_setup_path(const char* pkg_id, const char* path, app_path_type_t app_path_type, ...);

/**
 * Get paths of the specified type for the given application.
 *
 * Provided type must be one of PERM_APP_PATH_GROUP, PERM_APP_PATH_PUBLIC, PERM_APP_PATH_SETTINGS,
 * PERM_APP_PATH_NPRUNTIME, as other types are not stored in the database.
 *
 * In case of success caller is responsible for freeing memory allocated by it.
 * Each cell in *ppp_paths except for the last (NULL) should be freed, followed by freeing
 * *ppp_paths itself.
 *
 * In case of error an error code is returned and, provided that ppp_paths is not NULL,
 * *ppp_paths is set to NULL.
 *
 * @param  pkg_id        application identifier
 * @param  app_path_type type of path
 * @param  ppp_paths     buffer for return value
 * @return               PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_get_paths(const char* pkg_id, app_path_type_t app_path_type, char*** ppp_paths);

/**
 * Remove path and all rules associated with it from the database.
 *
 * This does not remove data from the filesystem.
 *
 * @param  pkg_id application identifier
 * @param  path   path to remove
 * @return        PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_remove_path(const char* pkg_id, const char *path);

/**
 * Make two applications "friends", by giving them both full permissions on
 * each other.
 * Results will be persistent on the file system. Must be called after
 * perm_app_enable_permissions() has been called for each application.
 * It must be called by privileged user.
 *
 * @param pkg_id1 first application identifier
 * @param pkg_id2 second application identifier
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_add_friend(const char* pkg_id1, const char* pkg_id2);

/**
 * Adds new feature to the database.
 * It must be called by privileged user and within database transaction
 * started with perm_begin() and finished with perm_end().
 *
 * Function contains redundant and deprecated arguments
 * associated with gids list. This is the reason why perm_define_permission
 * should be used instead. It gives the same functionality, but comes without
 * the last two arguments.
 *
 * @param  app_type          application type
 * @param  api_feature_name  name of newly added feature
 * @param  smack_rule_set    set of rules required by the feature - NULL terminated
 *                           list of NULL terminated rules.
 * @param  list_of_db_gids   deprecated attribute, use NULL or an error occurs
 * @param  list_size         deprecated attribute, use 0 or an error occurs
 * @return                   PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_add_api_feature(app_type_t app_type,
			 const char* api_feature_name,
			 const char** smack_rule_set,
			 const gid_t* list_of_db_gids,
			 size_t list_size);

/**
 * Adds new permission (api feature) to the database.
 * It must be called by privileged user and within database transaction
 * started with perm_begin() and finished with perm_end().
 *
 * @param  app_type          application type
 * @param  permission_name   name of newly added permission (api feature)
 * @param  smack_rule_set    set of rules granted by the permission - NULL terminated
 *                           list of NULL terminated rules.
 * @return                   PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_define_permission(app_type_t app_type,
			   const char* permission_name,
			   const char** smack_rule_set);


/**
 * Adds new permission (api feature) to the database.
 * It must be called by privileged user and within database transaction
 * started with perm_begin() and finished with perm_end().
 *
 * @param  app_type          application type
 * @param  permission_name   name of newly added permission (api feature)
 * @param  smack_rule_set    set of rules granted by the permission - NULL terminated
 *                           list of NULL terminated rules.
 * @param  tizen_version     string representing tizen version.
 * @param  fast              informs not to delete old rules during redefining permission.
 *                           it makes it run faster, but be caution using this durig
 *                           api-feature redefinition: not all rules will be deleted.
 * @return                   PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_define_permission_5(app_type_t app_type,
			      const char* api_feature_name,
			      const char* tizen_version,
			      const char** smack_rules,
			      bool fast);

/**
 * Starts exclusive database transaction. Run before functions modifying
 * database.
 *
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_begin(void);

/**
 * Ends exclusive database transaction. Run after functions modifying database.
 * If an error occurred during the transaction then all modifications will be
 * rolled back.
 *
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_end(void);

/**
* Run to rollback any privilege modification.
*
* @return PC_OPERATION_SUCCESS on success,
*         PC_ERR_* on error
*/
int perm_rollback(void);

/**
 * Adds additional rules to the database. The rules can use wild-cards and labels.
 * It must be called within database transaction started with perm_begin() and
 * finished with perm_end().
 *
 * @param  set_smack_rule_set  an array of rules, NULL terminated
 * @return                     PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_add_additional_rules(const char** set_smack_rule_set);

/**
 * Get message connected to error code.
 *
 * @param errnum error code
 * @return string describing the error code
 */
const char* perm_strerror(int errnum);

/**
 * Set privilege version for specific app. This function has to be
 * called before assigning any privileges, otherwise incorrect versions
 * of privileges will be assigned. If this function is not called,
 * default privilege version is the current tizen version. The provided
 * version has to be available in smack-privilege-config package, that
 * is installed on the target device, otherwise that version is not
 * supported.
 *
 * @param s_app_label_name       application's label name
 * @param s_version              version to set
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_INVALID_PARAM on unsupported version,
 *                               PC_ERR_* on error
 */
int perm_app_set_privilege_version(const char* const s_app_label_name,
		const char * const s_version);

/**
 * Get privilege version for specific app.
 *
 * @param s_app_label_name       application's label name
 * @param p_version              return version - this should be freed
 * @return                       PC_OPERATION_SUCCESS on success,
 *                               PC_ERR_* on error
 */
int perm_app_get_privilege_version(const char* const s_app_label_name,
		char **p_version);

/**
 * Perform a configuration refresh on a rule database.
 *
 * @param dir: directory's path, from which information will be read.
 * File names in that directory are checked to match permission file format
 * "PREFIX_apiFeatureName.smack" (PREFIX has to match application type
 * (WRT_, EFL_, OSP_, etc). If the filename matches the format, proper permission
 * will be reloaded from file: rules defined in files will replace rules in database.
 *
 * If subdirectory of given @ref dir has name that matches format "%d.%d.%d", e.g.
 * "2.2.0", then files from that subdirectory will be also read and loaded to database
 * as if they were privileges of tizen in version matching subdirectory name.
 * if @ref dir is set to NULL, the standard directory ("/usr/share/privilege-control/")
 * is taken as parameter.
 * @param clear_not_found_permissions: input flag for indicating need of additional
 * resetting all privileges: if true, all privileges' SMACK rules that are not described
 * in one of files found in @ref dir will be cleared. The entries for privileges'
 * names and versions and applciation's privileges will be left in database, but the
 * privilege-rule mapping will be cleared for every privilege not found on @ref dir.
 * If set to 0, there will be no additional changes on database except updating of
 * found privileges's rules.
 * @return PC_OPERATION_SUCCESS on success, one of error codes otherwise.
 */
API int perm_db_configuration_refresh(const char *const dir,
		int clear_not_found_permissions);

/**
 * Allows selected blacklisted permissions to be used by given application.
 * Applications won't be  able to use blacklisted permission when they are
 * disabled and they are disabled by default. Passing permission name that
 * is not on a black list will result in an error.
 *
 * It must be called by privileged
 * user and within database transaction started with perm_begin() and finished
 * with perm_end().
 *
 * @param  s_app_label_name application identifier
 * @param  perm_type        permission type
 * @param  pp_perm_list     array of blacklist permission names. Supports both
 *                          url format (http://tizen.org/permission/...)
 *                          and file format (org.tizen.permission...). Last
 *                          element must be NULL.
 *
 * @return                  PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_enable_blacklist_permissions(const char* const s_app_label_name,
		app_type_t perm_type,
		const char** pp_perm_list);

/**
 * Disables selected blacklisted permissions for given application. This
 * setting overrides permissions requested by app during installation as well
 * as permissions enabled with perm_app_enable_permissions(). Passing
 * permission name that is not on a black list or is not enabled will result in
 * an error.
 *
 * It must be called by privileged user and within database transaction started
 * with perm_begin() and finished with perm_end().
 *
 * @param  s_app_label_name application identifier
 * @param  perm_type        permission type
 * @param  pp_perm_list     array of blacklist permission names. Supports both
 *                          url format (http://tizen.org/permission/...)
 *                          and file format (org.tizen.permission...). Last
 *                          element must be NULL.
 *
 * @return                  PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_disable_blacklist_permissions(const char* const s_app_label_name,
		app_type_t perm_type,
		const char** pp_perm_list);

/**
 * Returns a list of black list permissions and their status (enabled/disabled)
 * for given app.
 *
 * @param  s_app_label_name application identifier
 * @param  pp_perm_list     array of blacklist permission structures containing
 *                          permission name and its status. Returned
 *                          permissions are in URL format
 *                          (http://tizen.org.permission/...) Free it with
 *                          perm_free_blacklist_statuses(...)
 * @param  p_perm_number    size of the blacklist permission array
 *
 * @return                  PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_get_blacklist_statuses(const char* const s_app_label_name,
		perm_blacklist_status_t** pp_perm_list,
		size_t* p_perm_number);

/**
 * Free the list of blacklist statuses allocated with
 * perm_app_get_blacklist_statuses(...).
 *
 * @param  p_perm_list   array of blacklist permission structures containing
 *                       permission name and its status.
 * @param  i_perm_number size of the blacklist permission array
 */
void perm_free_blacklist_statuses(perm_blacklist_status_t* p_perm_list,
		size_t i_perm_number);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _PRIVILEGE_CONTROL_H_
