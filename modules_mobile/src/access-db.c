/*
 * libprivilege control
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Janusz Kozerski <j.kozerski@samsung.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/smack.h>
#include <dlog.h>
#include <ctype.h>

#include "access-db.h"
#include "privilege-control.h"
#include "common.h"

typedef enum {
	DB_APP_TYPE_GROUPS,
	DB_APP_TYPE_COUNT /* Dummy enum element to get number of elements */
} db_app_type_t;

const char* db_file_names[DB_APP_TYPE_COUNT] = {
		"/opt/dbspace/.privilege_control_app_gids.db"
};

typedef struct element_s {
	struct element_s* next;
	char* value;
} element_t;

static element_t* add_element (element_t* elem, const char* value)
{
	SECURE_C_LOGD("Entering function: %s. Params: value=%s",
				__func__, value);

	if (NULL == elem)
		return NULL;

	element_t* new_element = malloc(sizeof(element_t));
	if (NULL == new_element)
		return NULL;

	new_element->value = malloc(sizeof(char) * (SMACK_LABEL_LEN + 1) );
	if (NULL == new_element->value) {
		free(new_element);
		return NULL;
	}

	strncpy(new_element->value, value, SMACK_LABEL_LEN);
	new_element->value[SMACK_LABEL_LEN] = '\0';
	new_element->next = NULL;
	elem->next = new_element;

	return new_element;
}


static int remove_list(element_t* first_elem)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	element_t* current = NULL;

	while (NULL != first_elem) {
		current = first_elem;
		first_elem = first_elem->next;
		if (current->value)
			free(current->value);
		free(current);
	}
	return 0;
}


static int add_id_to_database_internal(const char * id, db_app_type_t app_type)
{
	SECURE_C_LOGD("Entering function: %s. Params: id=%s",
				__func__, id);

	FILE* file_db AUTO_FCLOSE;
	const char* db_file_name = db_file_names[app_type];

	SECURE_C_LOGD("Opening database file %s.", db_file_name);
	file_db = fopen(db_file_name, "a");
	if (NULL == file_db) {
		SECURE_C_LOGE("Error while opening database file: %s", db_file_name);
		return PC_ERR_FILE_OPERATION;
	}

	if (0 > fprintf(file_db, "%s\n", id)) {
		SECURE_C_LOGE("Write label %s to database failed (error: %s)", id, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}


static int get_all_ids_internal (char *** ids, int * len, db_app_type_t app_type)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	int ret;
	FILE* file_db AUTO_FCLOSE;
	const char* db_file_name = db_file_names[app_type];
	char smack_label[SMACK_LABEL_LEN + 1];
	element_t* begin_of_list = NULL;

	SECURE_C_LOGD("Opening database file %s.", db_file_name);
	file_db = fopen(db_file_name, "r");
	if (NULL == file_db) {
		SECURE_C_LOGE("Error while opening database file: %s", db_file_name);
		ret = PC_ERR_FILE_OPERATION;
		goto out;
	}

	// intialization of list of smack labels
	*len = 0;
	begin_of_list = malloc(sizeof(element_t));
	if (begin_of_list == NULL ) {
		C_LOGE("Error while allocating memory");
		ret = PC_ERR_MEM_OPERATION;
		goto out;
	}
	begin_of_list->next  = NULL;
	begin_of_list->value = NULL;
	element_t* current = begin_of_list;

	// reading from file ("database")
	// notice that first element always stays with empty "value"
	while (fscanf(file_db, "%" TOSTRING(SMACK_LABEL_LEN) "s\n", smack_label) == 1) {
		smack_label[SMACK_LABEL_LEN] = '\0';
		if (!smack_label_is_valid(smack_label)) {
			SECURE_C_LOGD("Found entry in database, but it's not correct SMACK label: \"%s\"", smack_label);
			continue;
		}
		SECURE_C_LOGD("Found installed label: \"%s\"", smack_label);
		++(*len);
		current = add_element(current, smack_label);
		if (NULL == current) {
			*len = 0;
			C_LOGE("Error while adding smack label to the list.");
			ret = PC_ERR_MEM_OPERATION;
			goto out;
		}
	}

	if (*len > 0) {
		C_LOGD("Allocating memory for list of %d labels", *len);
		*ids = malloc((*len) * sizeof(char*));
		if (NULL == *ids) {
			*len = 0;
			C_LOGE("Error while allocating memory for list of labels.");
			ret = PC_ERR_MEM_OPERATION;
			goto out;
		}
		current = begin_of_list->next;
		int i;
		for (i=0; i < *len; ++i) {
			C_LOGD("Allocating memory for \"%s\" label", current->value);
			(*ids)[i] = malloc((SMACK_LABEL_LEN + 1) * sizeof(char));
			if (NULL == (*ids)[i]) {
				ret = PC_ERR_MEM_OPERATION;
				int j;
				for (j = 0; j < i; ++j)
					free((*ids)[j]);
				free(*ids);
				*ids = NULL;
				*len = 0;
				C_LOGE("Error while allocating memory for \"%s\" label", current->value);
				goto out;
			}
			strncpy((*ids)[i], current->value, SMACK_LABEL_LEN);
			(*ids)[i][SMACK_LABEL_LEN] = '\0';
			current = current->next;
		}
	}
	else {
		C_LOGD("No labels found!");
		*ids = NULL;
	}

	ret =  PC_OPERATION_SUCCESS;


out:
	remove_list(begin_of_list);

	return ret;
}


int add_app_gid(const char *app_id, unsigned gid)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s, gid=%u",
				__func__, app_id, gid);

	char *field = NULL;
	int ret;

	ret = asprintf(&field, "%u:%s", gid, app_id);
	if (ret == -1)
	{
		C_LOGE("asprintf failed.");
		return PC_ERR_MEM_OPERATION;
	}

	ret = add_id_to_database_internal(field, DB_APP_TYPE_GROUPS);
	free(field);

	return ret;
}


int get_app_gids(const char *app_id, unsigned **gids, int *len)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
				__func__, app_id);

	char** fields AUTO_FREE;
	int len_tmp, ret, i;

	ret = get_all_ids_internal(&fields, &len_tmp, DB_APP_TYPE_GROUPS);
	if (ret != PC_OPERATION_SUCCESS)
	{
		C_LOGE("get_all_ids_internal failed.");
		return ret;
	}

	*len = 0;
	*gids = NULL;
	for (i = 0; i < len_tmp; ++i) {
		const char *field = fields[i];
		const char *app_id_tmp = NULL;
		unsigned gid = 0;

		for (; *field; ++field) {
			if (*field == ':') {
				app_id_tmp = field + 1;
				break;
			}
			if (isdigit(*field)) {
				gid = gid * 10 + *field - '0';
			} else {
				C_LOGE("Invalid format of group id read from groups database: %s", fields[i]);
				ret = PC_ERR_FILE_OPERATION;
				goto out;
			}
		}

		if (!app_id_tmp) {
			C_LOGE("No group id found.");
			ret = PC_ERR_FILE_OPERATION;
			goto out;
		}

		if (NULL == app_id) {
			*len = 0;
			return PC_OPERATION_SUCCESS;
		}

		if (!strcmp(app_id, app_id_tmp)) {
			unsigned *gids_realloc = realloc(*gids, sizeof(unsigned) * (*len + 1));
			if (gids_realloc == NULL) {
				C_LOGE("Memory allocation failed.");
				ret = PC_ERR_MEM_OPERATION;
				goto out;
			}
			*gids = gids_realloc;
			(*gids)[(*len)++] = gid;
		}
	}

	ret = PC_OPERATION_SUCCESS;
out:
	for (i = 0; i < len_tmp; ++i)
		free(fields[i]);

	if (ret != PC_OPERATION_SUCCESS) {
		free(*gids);
		*len = 0;
	}

	return ret;
}