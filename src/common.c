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
#include <errno.h>
#include <unistd.h>
#include <sys/smack.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <iri.h>
#include <dirent.h>             // For iterating directories
#include <glob.h>               // For glob
#include <obstack.h>            // For obstack implementation


#include "common.h"
#include "privilege-control.h"
#include "rules-db.h"

#define API_FEATURE_LOADER_LOG(format, ...) C_LOGD(format, ##__VA_ARGS__)


// Obstack configuration
#define obstack_chunk_alloc malloc
#define obstack_chunk_free  free
#define vector_init(V)              obstack_init(&(V))
#define vector_push_back_ptr(V, I)  obstack_ptr_grow(&(V), (I))
#define vector_finish(V)            obstack_finish(&(V))
#define vector_free(V)              obstack_free(&(V), NULL)
typedef struct obstack vector_t;
static const size_t ui_smack_ext_len__ = 6; // = strlen(".smack");


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


int set_exec_label(const char *label, const char *path)
{
	struct stat st;

	if(stat(path, &st) < 0) {
		SECURE_C_LOGE("stat failed for %s (Error = %s)", path, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	// check if it's a link
	if((st.st_mode & S_IFLNK) != 0) {
		SECURE_C_LOGD("%s is a symbolic link", path);
		char* target AUTO_FREE;
		target = realpath(path, NULL);
		if(!target) {
			SECURE_C_LOGE("getting link target for %s failed (Error = %s)",
				      path, strerror(errno));
			return PC_ERR_FILE_OPERATION;
		}

		if(stat(target, &st) < 0) {
			SECURE_C_LOGE("stat failed for %s (Error = %s)", target, strerror(errno));
			return PC_ERR_FILE_OPERATION;
		}

		if((st.st_mode & (S_IXUSR | S_IFREG)) != (S_IXUSR | S_IFREG)) {
			SECURE_C_LOGE("%s is not a regular executable file.", target);
			return PC_ERR_FILE_OPERATION;
		}
	} else if((st.st_mode & (S_IXUSR | S_IFREG)) != (S_IXUSR | S_IFREG)) {
		SECURE_C_LOGE("%s is not a regular executable file nor a symbolic link.", path);
		return PC_ERR_FILE_OPERATION;
	}

	SECURE_C_LOGD("smack_lsetlabel (label: %s (type: SMACK_LABEL_EXEC), path: %s)",
	              label, path);
	if (smack_lsetlabel(path, label, SMACK_LABEL_EXEC) != 0) {
		SECURE_C_LOGE("smack_lsetlabel failed.");
		return PC_ERR_FILE_OPERATION;
	}
	return PC_OPERATION_SUCCESS;
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
	char tmp_s_access[ACC_LEN + 1];

	bool b_subject_is_template;
	bool b_object_is_template;

	// Tokenize
	ret = tokenize_rule(s_rule, tmp_s_subject, tmp_s_object, tmp_s_access);
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
	strcpy(s_access, tmp_s_access);

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

void fts_closep(FTS **f)
{
	if(*f)
		fts_close(*f);

}

static int load_smack_from_file_generic(const char *app_id, struct smack_accesses **smack, int *fd, char **path, bool is_early)
{
	/* Notice that app_id is ignored when flag is_early is set.
	 * It's because all of the "early rules" (for all apps) should
	 * be in one common file: SMACK_STARTUP_RULES_FILE
	 */
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
		      __func__, app_id);

	int ret;

	if(is_early) {
		if(0 > asprintf(path, "%s", SMACK_STARTUP_RULES_FILE)) {
			*path = NULL;
			C_LOGE("asprintf failed.");
			return PC_ERR_MEM_OPERATION;
		}
	} else {
		ret = smack_file_name(app_id, path);
		if(ret != PC_OPERATION_SUCCESS)
			return ret;
	}

	if(smack_accesses_new(smack)) {
		C_LOGE("smack_accesses_new failed.");
		return PC_ERR_MEM_OPERATION;
	}

	*fd = open(*path, O_CREAT | O_RDWR, 0644);
	if(*fd == -1) {
		C_LOGE("file open failed (error: %s)", strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	if(flock(*fd, LOCK_EX)) {
		C_LOGE("flock failed");
		return PC_ERR_INVALID_OPERATION;
	}

	if(smack_accesses_add_from_file(*smack, *fd)) {
		C_LOGE("smack_accesses_add_from_file failed.");
		return PC_ERR_INVALID_OPERATION;
	}

	/* Rewind the file */
	if(lseek(*fd, 0, SEEK_SET) == -1) {
		C_LOGE("lseek failed.");
		return PC_ERR_FILE_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

int load_smack_from_file(const char *app_id, struct smack_accesses **smack, int *fd, char **path)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
		      __func__, app_id);

	return load_smack_from_file_generic(app_id, smack, fd, path, 0);
}

int load_smack_from_file_early(const char *app_id, struct smack_accesses **smack, int *fd, char **path)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
		      __func__, app_id);

	return load_smack_from_file_generic(app_id, smack, fd, path, 1);
}

int smack_mark_file_name(const char *app_id, char **path)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
		      __func__, app_id);

	if(asprintf(path, SMACK_LOADED_APP_RULES "/%s", app_id) == -1) {
		C_LOGE("asprintf failed.");
		*path = NULL;
		return PC_ERR_MEM_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

bool file_exists(const char *path)
{
	SECURE_C_LOGD("Entering function: %s. Params: path=%s",
		      __func__, path);

	SECURE_C_LOGD("Opening file %s.", path);
	FILE *file = fopen(path, "r");
	if(file) {
		fclose(file);
		return true;
	}
	return false;
}

int smack_file_name(const char *app_id, char **path)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
		      __func__, app_id);

	if(asprintf(path, SMACK_RULES_DIR "/%s", app_id) == -1) {
		C_LOGE("asprintf failed.");
		*path = NULL;
		return PC_ERR_MEM_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
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

app_type_t str2app_type(const char* const name)
{
	app_type_t type;
	SECURE_C_LOGD("Entering function: %s. Params: name=%s", __func__, name);

	for (type = PERM_APP_TYPE_FIRST; type <= PERM_APP_TYPE_LAST; type++) {
		const char* type_name = app_type_name(type);
		if (NULL == type_name)
			continue;
		if (0 == strcmp(type_name, name))
			return type;
	}
	return PERM_APP_TYPE_OTHER;
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

/**
 * This function changes permission URI to basename for file name.
 * For e.g. from http://tizen.org/privilege/contact.read will be
 * created basename : org.tizen.privilege.contact.read
 */
int base_name_from_perm(const char *s_perm, char **ps_name)
{
	SECURE_C_LOGD("Entering function: %s. Params: perm=%s",
				__func__, s_perm);

	iri_t *piri_parsed = NULL;
	char *pc_rest_slash = NULL;

	piri_parsed = iri_parse(s_perm);
	if (piri_parsed == NULL || piri_parsed->host == NULL) {
		SECURE_C_LOGE("Bad permission format : %s", s_perm);
		iri_destroy(piri_parsed);
		return PC_ERR_INVALID_PARAM;
	}

	ssize_t i_host_size = strlen(piri_parsed->host);
	ssize_t i_path_start = 0;
	char * pc_host_dot = NULL;

	if(piri_parsed->path) {
		pc_host_dot = strrchr(piri_parsed->host, '.');
		i_path_start = i_host_size;
	}

	int ret = asprintf(ps_name, "%s%s%.*s%s",
			   pc_host_dot ? pc_host_dot + 1 : "",
			   pc_host_dot ? "." : "",
			   pc_host_dot ? pc_host_dot - piri_parsed->host : i_host_size,
			   piri_parsed->host,
			   piri_parsed->path ? piri_parsed->path : "");
	if (ret == -1) {
		C_LOGE("asprintf failed");
		iri_destroy(piri_parsed);
		return PC_ERR_MEM_OPERATION;
	}

	pc_rest_slash = *ps_name + i_path_start;
	while ((pc_rest_slash = strchr(pc_rest_slash, '/'))) {
		*pc_rest_slash = '.';
	}

	iri_destroy(piri_parsed);
	return PC_OPERATION_SUCCESS;
}



bool has_prefix(const char *const s_str, const char *const s_prefix)
{
	return !strncmp(s_str, s_prefix, strlen(s_prefix));
}

bool has_smack_ext(const char *const s_str)
{
	return strlen(s_str) > ui_smack_ext_len__ &&
	       !strncmp(&s_str[strlen(s_str) - ui_smack_ext_len__], ".smack", ui_smack_ext_len__);
}

int wrt_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "WRT.smack");
}

int wrt_partner_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "WRT_partner.smack");
}

int wrt_platform_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "WRT_platform.smack");
}

int wrt_family_filter(const struct dirent *entry)
{
	return has_prefix(entry->d_name, "WRT_") &&
	       !has_prefix(entry->d_name, "WRT_partner") &&
	       !has_prefix(entry->d_name, "WRT_platform") &&
	       has_smack_ext(entry->d_name);
}

int osp_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "OSP.smack");
}

int osp_partner_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "OSP_partner.smack");
}

int osp_platform_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "OSP_platform.smack");
}

int osp_family_filter(const struct dirent *entry)
{
	return has_prefix(entry->d_name, "OSP_") &&
	       !has_prefix(entry->d_name, "OSP_partner") &&
	       !has_prefix(entry->d_name, "OSP_platform") &&
	       has_smack_ext(entry->d_name);
}

int efl_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "EFL.smack");
}

int efl_partner_filter(const struct dirent *entry)
{
    return !strcmp(entry->d_name, "EFL_partner.smack");
}

int efl_platform_filter(const struct dirent *entry)
{
    return !strcmp(entry->d_name, "EFL_platform.smack");
}

int efl_family_filter(const struct dirent *entry)
{
	return has_prefix(entry->d_name, "EFL_") &&
	       !has_prefix(entry->d_name, "EFL_partner") &&
	       !has_prefix(entry->d_name, "EFL_platform") &&
	       has_smack_ext(entry->d_name);
}

int additional_rules_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "ADDITIONAL_RULES.smack");;
}

void load_rules_from_file(const char *s_rules_file_path,
			  const char *s_permission_name,
			  const app_type_t app_type,
			  const char *s_tizen_version)
{
	FILE *p_file       = NULL;
	char *s_rule       = NULL;
	char **rules_array = NULL;
	size_t i_num_rules = 0;
	size_t i           = 0;
	int ret;
	vector_t rules_vector;
	if (!s_tizen_version)
		s_tizen_version = TIZEN_VERSION;

	p_file = fopen(s_rules_file_path, "r");
	if(!p_file) goto finish;

	API_FEATURE_LOADER_LOG("Loading permission: %s  \n", s_permission_name);

	vector_init(rules_vector);
	while(getline(&s_rule, &i, p_file) > 0) {
		char *comment = strchr(s_rule, '\'');
		if (comment != NULL) *comment = 0;
		vector_push_back_ptr(rules_vector, s_rule);
		++i_num_rules;
		s_rule = NULL;
	}
	vector_push_back_ptr(rules_vector, NULL);

	rules_array = vector_finish(rules_vector);

	ret = perm_define_permission_for_tizen_version(app_type, s_permission_name, s_tizen_version, (const char **)rules_array);
	if(ret != PC_OPERATION_SUCCESS)
		API_FEATURE_LOADER_LOG("Error %d\n", ret);

finish:
	if(p_file != NULL) fclose(p_file);
	if(rules_array != NULL) {
		for(i = 0; i < i_num_rules; ++i) {
			free(rules_array[i]);
		}
		vector_free(rules_vector);
	}
}


char *get_permission_name(const char *s_file_name, const char *s_prefix)
{
	int i_prefix_len = strlen(s_prefix);

	// Allocate memory
	int i_perm_name_len = strlen(s_file_name);
	char *s_permission_name = (char *) malloc(i_perm_name_len + 1);
	if(!s_permission_name) {
		API_FEATURE_LOADER_LOG("Error during allocating memory.\n");
		return NULL;
	}

	strncpy(s_permission_name,
		&(s_file_name[i_prefix_len]),
		i_perm_name_len - i_prefix_len - ui_smack_ext_len__);

	s_permission_name[i_perm_name_len - i_prefix_len - ui_smack_ext_len__ ] = '\0';

	return s_permission_name;
}

void load_permission_family(int (*filter)(const struct dirent *),
			    const char const *s_prefix,
			    const app_type_t app_type,
			    const char const *s_dir,
			    const char const *s_tizen_version)
{
	int i, num_files          = 0;
	struct dirent **file_list = NULL;
	char *s_path              = NULL;
	char *s_permission_name   = NULL;


	num_files = scandir(s_dir, &file_list, filter, alphasort);
	for(i = 0; i < num_files; ++i) {
		if(asprintf(&s_path, "%s/%s", s_dir, file_list[i]->d_name) < 0) continue;
		if(s_path[0] == '\0') {
			free(s_path);
			continue;
		}

		s_permission_name = get_permission_name(file_list[i]->d_name, s_prefix);
		load_rules_from_file(s_path, s_permission_name, app_type, s_tizen_version);

		free(file_list[i]);
		free(s_path);
		free(s_permission_name);
		s_path = NULL;
		s_permission_name = NULL;
	}
	free(file_list);
}

void load_permission_type_rules(int (*filter)(const struct dirent *),
			       const char const *s_permission_name,
			       const app_type_t app_type,
			       const char const *s_dir,
			       const char const *s_tizen_version)
{
	char *s_path              = NULL;
	struct dirent **file_list = NULL;
	int i, num_files;

	num_files = scandir(s_dir, &file_list, filter, alphasort);
	for(i = 0; i < num_files; ++i) {
		if(asprintf(&s_path, "%s/%s", s_dir, file_list[i]->d_name) < 0) continue;
		if(s_path[0] == '\0') {
			free(s_path);
			continue;
		}

		load_rules_from_file(s_path, s_permission_name, app_type, s_tizen_version);

		free(file_list[i]);
		free(s_path);
		s_path = NULL;
	}
	free(file_list);
}

void load_from_dir(const char  *const s_dir, const char *const tizen_ver)
{

	API_FEATURE_LOADER_LOG("Loading rules from directory...\n");
	if(perm_begin()) return;

	// Load rules specific to permission's types:
	load_permission_type_rules(wrt_filter,          "WRT",          PERM_APP_TYPE_WRT,          s_dir, tizen_ver);
	load_permission_type_rules(wrt_partner_filter,  "WRT_partner",  PERM_APP_TYPE_WRT_PARTNER,  s_dir, tizen_ver);
	load_permission_type_rules(wrt_platform_filter, "WRT_platform", PERM_APP_TYPE_WRT_PLATFORM, s_dir, tizen_ver);
	load_permission_type_rules(osp_filter,          "OSP",          PERM_APP_TYPE_OSP,          s_dir, tizen_ver);
	load_permission_type_rules(osp_partner_filter,  "OSP_partner" , PERM_APP_TYPE_OSP_PARTNER,  s_dir, tizen_ver);
	load_permission_type_rules(osp_platform_filter, "OSP_platform", PERM_APP_TYPE_OSP_PLATFORM, s_dir, tizen_ver);
	load_permission_type_rules(efl_filter,          "EFL",          PERM_APP_TYPE_EFL,          s_dir, tizen_ver);
	load_permission_type_rules(efl_partner_filter,  "EFL_partner",  PERM_APP_TYPE_EFL_PARTNER,  s_dir, tizen_ver);
	load_permission_type_rules(efl_platform_filter, "EFL_platform", PERM_APP_TYPE_EFL_PLATFORM, s_dir, tizen_ver);

	// Load rules for each permission type:
	load_permission_family(wrt_family_filter, "WRT_", PERM_APP_TYPE_WRT, s_dir, tizen_ver);
	load_permission_family(osp_family_filter, "OSP_", PERM_APP_TYPE_OSP, s_dir, tizen_ver);
	load_permission_family(efl_family_filter, "EFL_", PERM_APP_TYPE_EFL, s_dir, tizen_ver);

	// Reload blacklist
	rdb_load_blacklist(s_dir, tizen_ver);

	perm_end();
	API_FEATURE_LOADER_LOG("Done.\n");
}

void load_permissions_for_all_versions(const char  *const s_dir)
{
	DIR *dir;
	struct dirent *ent;
	char *realp;
	API_FEATURE_LOADER_LOG("Loading permissions from '%s' as if they were for version of %s\n", s_dir, TIZEN_VERSION);
	load_from_dir(s_dir, TIZEN_VERSION);
	if ((dir = opendir(s_dir)) != NULL) {
		while ((ent = readdir(dir)) != NULL) {
			if ((ent->d_type == DT_DIR) && (strcmp(".", ent->d_name))) {
				if (-1 == asprintf(&realp, "%s/%s", s_dir, ent->d_name))
					C_LOGE("asprintf failed.");
				else {
					API_FEATURE_LOADER_LOG("Loading permissions from '%s' as if they were for version of %s\n", realp, ent->d_name);
					load_from_dir(realp, ent->d_name);
					free (realp);
				}
			}
		}
		closedir (dir);
	} else {
		API_FEATURE_LOADER_LOG("Opening directory %s failed: %m", s_dir );
	}
}

void load_single_file(const char *const s_file_path, const char *tizen_ver)
{
	API_FEATURE_LOADER_LOG("Loading rules from file...\n");
	if(perm_begin()) return;

	char *s_permission_name = NULL;
	char *s_file_name;
	struct dirent file;

	if(!has_smack_ext(s_file_path)) {
		API_FEATURE_LOADER_LOG("File doesn't have smack extension: %s\n", s_file_path);
		perm_end();
		return;
	}

	s_file_name = basename(s_file_path);
	strncpy(file.d_name, s_file_name, sizeof(file.d_name)-1);
        file.d_name[sizeof(file.d_name)-1] = '\0';

	// Load as the right type of permission
	if(wrt_family_filter(&file)) {
		s_permission_name = get_permission_name(s_file_name, "WRT_");
		load_rules_from_file(s_file_path, s_permission_name, PERM_APP_TYPE_WRT, tizen_ver);

	} else if(osp_family_filter(&file)) {
		s_permission_name = get_permission_name(s_file_name, "OSP_");
		load_rules_from_file(s_file_path, s_permission_name, PERM_APP_TYPE_OSP, tizen_ver);

	} else if(efl_family_filter(&file)) {
		s_permission_name = get_permission_name(s_file_name, "EFL_");
		load_rules_from_file(s_file_path, s_permission_name, PERM_APP_TYPE_EFL, tizen_ver);

	} else {
		API_FEATURE_LOADER_LOG("Unknown api-feature type: %s\n", s_file_path);
	}

	free(s_permission_name);

	perm_end();
	API_FEATURE_LOADER_LOG("Done.\n");
}

void load_from_file(const char *const s_name_pattern, const char *const tizen_ver)
{
	API_FEATURE_LOADER_LOG("Loading rules from file(s) matching pattern: %s, tizen version is %s\n",
			       s_name_pattern, tizen_ver);
	int ret;
	glob_t g;
	ret = glob(s_name_pattern, 0, NULL, &g);

	if(ret == GLOB_ABORTED) {
		API_FEATURE_LOADER_LOG("Cannot open given directory\n");
		goto finish;
	}
	if(ret == GLOB_NOMATCH) {
		API_FEATURE_LOADER_LOG("No match found for given pattern\n");
		goto finish;
	}
	if(ret == GLOB_NOSPACE) {
		API_FEATURE_LOADER_LOG("Not enough memory\n");
		goto finish;
	}
	if(ret != 0) {
		API_FEATURE_LOADER_LOG("Error during file(s) loading\n");
		goto finish;
	}

	size_t i;
	for(i = 0; i < g.gl_pathc; ++i)
		load_single_file(g.gl_pathv[i], tizen_ver);

finish:
	globfree(&g);

	API_FEATURE_LOADER_LOG("Loading rules from file(s) matching pattern: %s done.\n",
			       s_name_pattern);
}

void load_additional_rules(const char *const s_rules_file_path)
{
	FILE *p_file       = NULL;
	char *s_rule       = NULL;
	char **rules_array = NULL;
	size_t i_num_rules = 0;
	size_t i           = 0;
	int ret;
	vector_t rules_vector;

	API_FEATURE_LOADER_LOG("Loading additional rules from file...\n");

	p_file = fopen(s_rules_file_path, "r");
	if(!p_file) goto finish;


	vector_init(rules_vector);
	while(getline(&s_rule, &i, p_file) > 0) {
		vector_push_back_ptr(rules_vector, s_rule);
		API_FEATURE_LOADER_LOG("Loading rule: %s", s_rule);
		++i_num_rules;
		s_rule = NULL;
	}
	vector_push_back_ptr(rules_vector, NULL);

	rules_array = vector_finish(rules_vector);

	ret = perm_add_additional_rules((const char **)rules_array);
	if(ret != PC_OPERATION_SUCCESS)
		API_FEATURE_LOADER_LOG("Error %d\n", ret);

finish:
	if(p_file != NULL) fclose(p_file);
	if(rules_array != NULL) {
		for(i = 0; i < i_num_rules; ++i) {
			free(rules_array[i]);
		}
		vector_free(rules_vector);
	}

	API_FEATURE_LOADER_LOG("Done.\n");
}

const char* get_current_container_id(void)
{
	const char *path = "/proc/1/environ";
	const char *lxc_name_label = "LIBVIRT_LXC_NAME=";

	static const char *container_name = NULL;
	static bool container_name_resolved = false;

	FILE *file;
	char *buff = NULL;
	size_t size = 0;
	char *occurence;

	// avoid parsing "environ" every call
	if(container_name_resolved) {
		return container_name;
	}

	SECURE_C_LOGD("Checking container name...");

	do {
		file = fopen(path, "rb");
	} while(file == NULL && errno == EINTR);
	if(NULL == file) {
		SECURE_C_LOGE("Cannot open file %s (errno: %s)", path, strerror(errno));
		goto finish;
	}

	while(getdelim(&buff, &size, 0, file) != -1)
	{
		// extract value of "LIBVIRT_LXC_NAME"
		occurence = strstr(buff, lxc_name_label);
		if(NULL != occurence) {
			container_name = occurence + strlen(lxc_name_label);
			break;
		}
	}

	if(NULL != container_name) {
		SECURE_C_LOGD("LXC container name: %s", container_name);
	} else {
		SECURE_C_LOGD("LXC container name not found in %s"
			" - assuming process is running in host", path);
		if (NULL != buff) {
			free(buff);
		}
	}

finish:
	if(file != NULL) fclose(file);
	container_name_resolved = true;
	return container_name;
}

const char* attach_label_prefix(const char *const str)
{
	const char *prefix_separator = "::";

	if(NULL == str) return NULL;

	const char *prefix = get_current_container_id();
	char *output = NULL;

	// do not add any prefix nor separator when running in host
	if(NULL == prefix) {
	    output = strdup(str);
	} else {
	    const size_t str_len = strlen(str);
		const size_t prefix_len = strlen(prefix) + strlen(prefix_separator);
		output = (char*)malloc(prefix_len + str_len + 1);
		if(NULL == output) return NULL;
		strcpy(output, prefix);
		strcat(output, prefix_separator);
		strcat(output, str);
	}

	return output;
}
