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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <sys/smack.h>

#include "common.h"


/* TODO: implement such function in libsmack instead */
int smack_label_is_valid(const char *smack_label)
{
	SECURE_C_LOGD("Entering function: %s. Params: smack_label=%s",
		      __func__, smack_label);

	int i;

	if(!smack_label || smack_label[0] == '\0' || smack_label[0] == '-')
		goto err;

	for(i = 0; smack_label[i]; ++i) {
		if(i >= SMACK_LABEL_LEN)
			goto err;
		switch(smack_label[i]) {
		case '~':
		case ' ':
		case '/':
		case '"':
		case '\\':
		case '\'':
			goto err;
		default:
			break;
		}
	}

	return 1;
err:
	SECURE_C_LOGE("Invalid SMACK label %s", smack_label);
	return 0;
}

int tokenize_rule(const char *const s_rule,
		  char s_subject[],
		  char s_object[],
		  char s_access[])
{
	char tmp_s_dump[2] = "\0";
	int ret = 0;

	ret = sscanf(s_rule, "%" TOSTRING(SMACK_LABEL_LEN) "s%*[ \t\n\r]%" TOSTRING(SMACK_LABEL_LEN)
	             "s%*[ \t\n\r]%" TOSTRING(ACC_LEN) "s%1s", s_subject, s_object,s_access,
	             tmp_s_dump);

	if (ret != 3) {
		C_LOGE("RDB: Failed to tokenize the rule: <%s>. %d tokens needed, %d found.",
		       s_rule, 3, ret);
		return PC_ERR_INVALID_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}


bool is_wildcard(const char *const s_label)
{
	return 	!strcmp(s_label, "~ALL_APPS~") ||
		!strcmp(s_label, "~ALL_APPS_WITH_SAME_PERMISSION~") ||
		!strcmp(s_label, "~PUBLIC_PATH~") ||
		!strcmp(s_label, "~GROUP_PATH~") ||
		!strcmp(s_label, "~SETTINGS_PATH~") ||
		!strcmp(s_label, "~NPRUNTIME_PATH~");
}


int parse_rule(const char *const s_rule,
	       char s_label[],
	       char s_access[],
	       int *pi_is_reverse)
{
	int ret = PC_OPERATION_SUCCESS;
	char tmp_s_subject[SMACK_LABEL_LEN + 1];
	char tmp_s_object[SMACK_LABEL_LEN + 1];

	bool b_subject_is_template;
	bool b_object_is_template;

	// Tokenize
	ret = tokenize_rule(s_rule, tmp_s_subject, tmp_s_object, s_access);
	if(ret != PC_OPERATION_SUCCESS) return ret;

	// Check SMACK_APP_LABEL_TEMPLATE
	b_subject_is_template = (bool) !strcmp(tmp_s_subject, SMACK_APP_LABEL_TEMPLATE);
	b_object_is_template = (bool) !strcmp(tmp_s_object, SMACK_APP_LABEL_TEMPLATE);
	if((b_subject_is_template && b_object_is_template) ||
	    (!b_subject_is_template && !b_object_is_template)) {
		C_LOGE("RDB: Incorrect rule format in rule: %s", s_rule);
		ret = PC_ERR_INVALID_PARAM;
		return ret;
	}

	// Check label validity and copy rules
	if(b_subject_is_template) {
		// Not reversed
		if(!smack_label_is_valid(tmp_s_object) &&
		    !is_wildcard(tmp_s_object)) {
			C_LOGE("RDB: Incorrect subject label: %s", tmp_s_object);
			return ret;
		}
		strcpy(s_label, tmp_s_object);
		if(pi_is_reverse != NULL) *pi_is_reverse = 0;
	} else if(b_object_is_template) {
		// Reversed
		if(!smack_label_is_valid(tmp_s_subject) &&
		    !is_wildcard(tmp_s_subject)) {
			C_LOGE("RDB: Incorrect subject label: %s", tmp_s_subject);
			return ret;
		}
		strcpy(s_label, tmp_s_subject);
		if(pi_is_reverse != NULL) *pi_is_reverse = 1;
	}

	return PC_OPERATION_SUCCESS;
}


int validate_all_rules(const char *const *const pp_permissions_list)
{
	int i;
	char s_label[SMACK_LABEL_LEN + 1];
	char s_access[ACC_LEN + 1];

	// Parse and check rules.
	for(i = 0; pp_permissions_list[i] != NULL; ++i) {
		// C_LOGE("RDB: Validating rules: %s", pp_permissions_list[i]);

		// Ignore empty lines
		if(strspn(pp_permissions_list[i], " \t\n")
		    == strlen(pp_permissions_list[i]))
			continue;

		if(parse_rule(pp_permissions_list[i], s_label, s_access, NULL)
		    != PC_OPERATION_SUCCESS) {
			C_LOGE("RDB: Invalid parameter");
			return PC_ERR_INVALID_PARAM;
		}

		// Check the other label
		if(!is_wildcard(s_label) &&
		    !smack_label_is_valid(s_label)) {
			C_LOGE("RDB: Incorrect object label: %s", s_label);
			return PC_ERR_INVALID_PARAM;
		}
	}

	return PC_OPERATION_SUCCESS;
}

/* Auto cleanup stuff */
void freep(void *p)
{
	free(*(void **) p);
}

void closep(int *fd)
{
	if(*fd >= 0)
		close(*fd);
}

void fclosep(FILE **f)
{
	if(*f)
		fclose(*f);
}

int have_smack(void)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	static int have_smack = -1;

	if(-1 == have_smack) {
		if(NULL == smack_smackfs_path()) {
			C_LOGD("Libprivilege-control: no smack found on phone");
			have_smack = 0;
		} else {
			C_LOGD("Libprivilege-control: found smack on phone");
			have_smack = 1;
		}
	}

	return have_smack;
}

inline const char* app_type_name(app_type_t app_type)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d",
				__func__, app_type);

	switch (app_type) {
	case PERM_APP_TYPE_WRT:
		C_LOGD("App type = WRT");
		return "WRT";
	case PERM_APP_TYPE_OSP:
		C_LOGD("App type = OSP");
		return "OSP";
	case PERM_APP_TYPE_WRT_PARTNER:
		C_LOGD("App type = WRT_partner");
		return "WRT_partner";
	case PERM_APP_TYPE_WRT_PLATFORM:
		C_LOGD("App type = WRT_platform");
		return "WRT_platform";
	case PERM_APP_TYPE_OSP_PARTNER:
		C_LOGD("App type = OSP_partner");
		return "OSP_partner";
	case PERM_APP_TYPE_OSP_PLATFORM:
		C_LOGD("App type = OSP_platform");
		return "OSP_platform";
	case PERM_APP_TYPE_EFL:
		C_LOGD("App type = EFL");
		return "EFL";
	case PERM_APP_TYPE_EFL_PARTNER:
		C_LOGD("App type = EFL_partner");
		return "EFL_partner";
	case PERM_APP_TYPE_EFL_PLATFORM:
		C_LOGD("App type = EFL_platform");
		return "EFL_platform";
	default:
		C_LOGD("App type = other");
		return NULL;
	}
}

const char *get_current_tizen_ver(void)
{
	return TIZEN_VERSION;
}

inline const char* app_type_group_name(app_type_t app_type)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d",
				__func__, app_type);

	switch (app_type) {
	case PERM_APP_TYPE_WRT:
	case PERM_APP_TYPE_WRT_PARTNER:
	case PERM_APP_TYPE_WRT_PLATFORM:
		C_LOGD("App type group name = WRT");
		return "WRT";
	case PERM_APP_TYPE_OSP:
	case PERM_APP_TYPE_OSP_PARTNER:
	case PERM_APP_TYPE_OSP_PLATFORM:
		C_LOGD("App type group name = OST");
		return "OSP";
	case PERM_APP_TYPE_EFL:
	case PERM_APP_TYPE_EFL_PARTNER:
	case PERM_APP_TYPE_EFL_PLATFORM:
		C_LOGD("App type = EFL");
		return "EFL";
	default:
		return NULL;
	}
}

const char* app_path_type_name(app_path_type_t app_path_type)
{
	SECURE_C_LOGD("Entering function %s. Params: app_path_type=%d", __func__, app_path_type);

	switch(app_path_type) {
	case PERM_APP_PATH_GROUP:
		return "GROUP_PATH";
	case PERM_APP_PATH_PUBLIC:
		return "PUBLIC_PATH";
	case PERM_APP_PATH_SETTINGS:
		return "SETTINGS_PATH";
	case PERM_APP_PATH_NPRUNTIME:
		return "NPRUNTIME_PATH";
	case PERM_APP_PATH_PRIVATE:
	case PERM_APP_PATH_ANY_LABEL:
	default:
		// App path type not stored in the database, return NULL;
		return NULL;
	}
}
