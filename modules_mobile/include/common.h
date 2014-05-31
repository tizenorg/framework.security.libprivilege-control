/*
 * libprivilege control
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Rafal Krypa <r.krypa@samsung.com>
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

#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <dlog.h>
#include <fts.h>
#include <stdbool.h>
#include <sys/smack.h>
#include "privilege-control.h"

#ifdef LOG_TAG
    #undef LOG_TAG
#endif // LOG_TAG
#ifndef LOG_TAG
    #define LOG_TAG "PRIVILEGE_CONTROL"
#endif // LOG_TAG

// conditional log macro for dlogutil (debug)
#ifdef DLOG_DEBUG_ENABLED
#define C_LOGD(...) SLOGD(__VA_ARGS__)
#define SECURE_C_LOGD(...) SECURE_SLOGD(__VA_ARGS__)
#else
#define C_LOGD(...) do { } while(0)
#define SECURE_C_LOGD(...) do { } while(0)
#endif //DLOG_DEBUG_ENABLED

// conditional log macro for dlogutil (warning)
#ifdef DLOG_WARN_ENABLED
#define C_LOGW(...) SLOGW(__VA_ARGS__)
#define SECURE_C_LOGW(...) SECURE_SLOGW(__VA_ARGS__)
#else
#define C_LOGW(...) do { } while(0)
#define SECURE_C_LOGW(...) do { } while(0)
#endif //DLOG_WARN_ENABLED

// conditional log macro for dlogutil (error)
#ifdef DLOG_ERROR_ENABLED
#define C_LOGE(...) SLOGE(__VA_ARGS__)
#define SECURE_C_LOGE(...) SECURE_SLOGE(__VA_ARGS__)
#else
#define C_LOGE(...) do { } while(0)
#define SECURE_C_LOGE(...) do { } while(0)
#endif //DLOG_ERROR_ENABLED

/* for SECURE_LOG* purpose */
#undef _SECURE_
#ifndef _SECURE_LOG
#define _SECURE_ (0)
#else
#define _SECURE_ (1)
#endif
#undef LOG_
#define LOG_(id, prio, tag, fmt, arg...) \
    ( __dlog_print(id, prio, tag, "%s: %s(%d) > " fmt, __MODULE__, __func__, __LINE__, ##arg))
#undef SECURE_LOG_
#define SECURE_LOG_(id, prio, tag, fmt, arg...) \
    (_SECURE_ ? ( __dlog_print(id, prio, tag, "%s: %s(%d) > [SECURE_LOG] " fmt, __MODULE__, __func__, __LINE__, ##arg)) : (0))

#define SECURE_LOGD(format, arg...) SECURE_LOG_(LOG_ID_MAIN, DLOG_DEBUG, LOG_TAG, format, ##arg)
#define SECURE_LOGI(format, arg...) SECURE_LOG_(LOG_ID_MAIN, DLOG_INFO, LOG_TAG, format, ##arg)
#define SECURE_LOGW(format, arg...) SECURE_LOG_(LOG_ID_MAIN, DLOG_WARN, LOG_TAG, format, ##arg)
#define SECURE_LOGE(format, arg...) SECURE_LOG_(LOG_ID_MAIN, DLOG_ERROR, LOG_TAG, format, ##arg)
/****************************/

void freep(void *p);
void closep(int *fd);
void fclosep(FILE **f);
void smack_freep(struct smack_accesses **smack);
void fts_closep(FTS **f);
#define AUTO_FREE       __attribute__ ((cleanup(freep)))       = NULL
#define AUTO_CLOSE      __attribute__ ((cleanup(closep)))      = -1
#define AUTO_FCLOSE     __attribute__ ((cleanup(fclosep)))     = NULL
#define AUTO_SMACK_FREE __attribute__ ((cleanup(smack_freep))) = NULL
#define AUTO_FTS_CLOSE  __attribute__ ((cleanup(fts_closep)))   = NULL

#define SMACK_RULES_DIR          "/opt/etc/smack-app/accesses.d/"
#define SMACK_STARTUP_RULES_FILE "/opt/etc/smack-app-early/accesses.d/rules"
#define SMACK_LOADED_APP_RULES   "/var/run/smack-app/"

#define SMACK_APP_LABEL_TEMPLATE        "~APP~"
#define SMACK_SHARED_DIR_LABEL_TEMPLATE "~APP_SHARED_DIR~"
#define ACC_LEN 6

int smack_label_is_valid(const char* smack_label);

int load_smack_from_file(const char* app_id, struct smack_accesses** smack, int *fd, char** path);
int load_smack_from_file_early(const char* app_id, struct smack_accesses** smack, int *fd, char** path);
int smack_mark_file_name(const char *app_id, char **path);
bool file_exists(const char* path);
int smack_file_name(const char* app_id, char** path);
inline int have_smack(void);
int base_name_from_perm(const char *perm, char **name);


/**
 * Set EXEC label on executable file or symlink to executable file
 *
 * @param label label to be set
 * @param path  link to exec file or symbolic link to exec file
 * @return      PC_OPERATION_SUCCESS on success,
 *              error code otherwise
 */
int set_exec_label(const char *label, const char *path);


/**
 * Get the permission family type name.
 *
 * @ingroup RDB internal functions
 *
 * @param  app_type type of the application
 * @return          PC_OPERATION_SUCCESS on success,
 *                  error code otherwise
 */
const char* app_type_name(app_type_t app_type);

/**
 * Get the permission type name
 *
 * @ingroup RDB internal functions
 *
 * @param  app_type type of the application
 * @return          PC_OPERATION_SUCCESS on success,
 *                  error code otherwise
 */
const char* app_type_group_name(app_type_t app_type);

/**
 * Divide a Smack rule into subject, object and access
 *
 * @ingroup RDB internal functions
 *
 * @param  s_rule    the rule
 * @param  s_subject buffer for the subject
 * @param  s_object  buffer for the object
 * @param  s_access  buffer for the access
 * @return           PC_OPERATION_SUCCESS on success,
 *                   error code otherwise
 */
int tokenize_rule(const char *const s_rule,
		  char s_subject[],
		  char s_object[],
		  char s_access[]);

/**
 * Check if the label is a wildcard.
 *
 * @ingroup RDB internal functions
 *
 * @param  s_label the label
 * @return         is the label a wildcard?
 */
bool is_wildcard(const char *const s_label);

/**
 * Divides the rule into subject, object and access strings.
 *
 * @ingroup RDB internal functions
 *
 * @param  s_rule         the string that we parse
 * @param  s_label        buffer for the label
 * @param  s_access       buffer for the access
 * @param  pi_is_reverse  buffer for the is_reversed
 * @return                PC_OPERATION_SUCCESS on success,
 *                        error code otherwise
 */
int parse_rule(const char *const s_rule,
	       char s_label[],
	       char s_access[],
	       int *pi_is_reverse);

/**
 * Validate if all rules in the array can be parsed.
 *
 * @param  pp_permissions_list array of permissions to check
 * @return                     PC_OPERATION_SUCCESS on success,
 *                             error code otherwise
 */
int validate_all_rules(const char *const *const pp_permissions_list);

#endif /* COMMON_H_ */
