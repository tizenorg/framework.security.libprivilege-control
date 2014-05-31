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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <fts.h>
#include <errno.h>
#include <math.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/smack.h>
#include <linux/capability.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <search.h>

#include "privilege-control.h"
#include "access-db.h"
#include "common.h"
#include "rules-db.h"

#define APP_GID	5000
#define APP_UID	5000
#define ADMIN_GROUP	6504
#define DEVELOPER_GID	5100
#define DEVELOPER_UID	5100

#define APP_USER_NAME	"app"
#define DEV_USER_NAME	"developer"

#define APP_HOME_DIR	TOSTRING(HOMEDIR) "/app"
#define DEV_HOME_DIR	TOSTRING(HOMEDIR) "/developer"

#define APP_GROUP_PATH	TOSTRING(SHAREDIR) "/app_group_list"
#define DEV_GROUP_PATH	TOSTRING(SHAREDIR) "/dev_group_list"

#define SMACK_SRC_FILE_SUFFIX   "_src_file"
#define SMACK_SRC_DIR_SUFFIX    "_src_dir"
#define SMACK_DATA_SUFFIX       "_data"
#define WRT_BASE_DEVCAP         "WRT"
#define WRT_CLIENT_PATH         "/usr/bin/wrt-client"
#define ACC_LEN                 6
#define TIZEN_PRIVILEGE_ANTIVIRUS  "http://tizen.org/privilege/antivirus"
#define TIZEN_PRIVILEGE_APPSETTING "http://tizen.org/privilege/appsetting"
#define PATH_RULES_PUBLIC_RO       "PATH_RULES_PUBLIC_RO.smack"
#define PATH_RULES_GROUP_RW        "PATH_RULES_GROUP_RW.smack"

typedef struct {
	char user_name[10];
	int uid;
	int gid;
	char home_dir[64];
	char group_list[64];
} new_user;

/**
 * Return values
 * <0 - error
 * 0 - skip
 * 1 - label
 */
typedef int (*label_decision_fn)(const FTSENT*);
enum {
	DECISION_SKIP = 0,
	DECISION_LABEL = 1
};

__attribute__ ((destructor))
static void libprivilege_destructor()
{
	SECURE_C_LOGD("Entering function: %s.", __func__);
	perm_end();
}

API int perm_begin(void)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);
	return rdb_modification_start();
}

API int perm_end(void)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	return rdb_modification_finish();
}

API int control_privilege(void)//deprecated
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	if(getuid() == APP_UID)	// current user is 'app'
		return PC_OPERATION_SUCCESS;

	if(perm_app_set_privilege("com.samsung.", NULL, NULL) == PC_OPERATION_SUCCESS)
		return PC_OPERATION_SUCCESS;
	else {
		C_LOGE("perm_app_set_privilege failed (not permitted).");
		return PC_ERR_NOT_PERMITTED;
	}
}

/**
 * TODO: this function should be moved to libsmack in open-source.
 */
API int get_smack_label_from_process(pid_t pid, char *smack_label)
{
	SECURE_C_LOGD("Entering function: %s. Params: pid=%i", __func__, pid);

	int ret;
	int fd AUTO_CLOSE;
	int PATH_MAX_LEN = 64;
	char path[PATH_MAX_LEN + 1];

	if (pid < 0) {
		C_LOGE("invalid param pid.");
		ret = PC_ERR_INVALID_PARAM;
		goto out;
	}

	if(smack_label == NULL) {
		C_LOGE("Invalid param smack_label (NULL).");
		ret = PC_ERR_INVALID_PARAM;
		goto out;
	}

	bzero(smack_label, SMACK_LABEL_LEN + 1);
	if (!have_smack()) { // If no smack just return success with empty label
		C_LOGD("No SMACK. Returning empty label");
		ret = PC_OPERATION_SUCCESS;
		goto out;
	}

	bzero(path, PATH_MAX_LEN + 1);
	snprintf(path, PATH_MAX_LEN, "/proc/%d/attr/current", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		SECURE_C_LOGE("Cannot open file %s (errno: %s)", path, strerror(errno));
		ret = PC_ERR_FILE_OPERATION;
		goto out;
	}

	ret = read(fd, smack_label, SMACK_LABEL_LEN);
	if (ret < 0) {
		SECURE_C_LOGE("Cannot read from file %s", path);
		ret = PC_ERR_FILE_OPERATION;
		goto out;
	}

	SECURE_C_LOGD("smack_label=%s", smack_label);

	ret = PC_OPERATION_SUCCESS;

out:
	return ret;
}

API int smack_pid_have_access(pid_t pid,
								const char* object,
								const char *access_type)
{
	SECURE_C_LOGD("Entering function: %s. Params: pid=%i, object=%s, access_type=%s",
				__func__, pid, object, access_type);

	int ret;
	char pid_subject_label[SMACK_LABEL_LEN + 1];
	cap_t cap;
	cap_flag_value_t cap_v;

	if (!have_smack()) {
		C_LOGD("No SMACK. Return access granted");
		return 1;
	}

	if (pid < 0) {
		C_LOGE("Invalid pid.");
		return -1;
	}

	if(object == NULL) {
		C_LOGE("Invalid object param.");
		return -1;
	}

	if(access_type == NULL) {
		C_LOGE("Invalid access_type param");
		return -1;
	}

	//get SMACK label of process
	ret = get_smack_label_from_process(pid, pid_subject_label);
	if (PC_OPERATION_SUCCESS != ret) {
		SECURE_C_LOGE("get_smack_label_from_process %d failed: %d", pid, ret);
		return -1;
	}
	SECURE_C_LOGD("pid %d has label: %s", pid, pid_subject_label);

	// do not call smack_have_access() if label is empty
	if (pid_subject_label[0] != '\0') {
		ret = smack_have_access(pid_subject_label, object, access_type);
		if ( -1 == ret) {
			C_LOGE("smack_have_access failed.");
			return -1;
		}
		if ( 1 == ret ) { // smack_have_access return 1 (access granted)
			C_LOGD("smack_have_access returned 1 (access granted)");
			return 1;
		}
	}

	// smack_have_access returned 0 (access denied). Now CAP_MAC_OVERRIDE should be checked
	C_LOGD("smack_have_access returned 0 (access denied)");
	cap = cap_get_pid(pid);
	if (cap == NULL) {
		C_LOGE("cap_get_pid failed");
		return -1;
	}
	ret = cap_get_flag(cap, CAP_MAC_OVERRIDE, CAP_EFFECTIVE, &cap_v);
	if (0 != ret) {
		C_LOGE("cap_get_flag failed");
		return -1;
	}

	if (cap_v == CAP_SET) {
		C_LOGD("pid %d has CAP_MAC_OVERRIDE", pid);
		return 1;

	} else {
		C_LOGD("pid %d doesn't have CAP_MAC_OVERRIDE", pid);
		return 0;
	}
}

static int set_dac(const char *smack_label, const char *pkg_name)
{
	SECURE_C_LOGD("Entering function: %s. Params: smack_label=%s, pkg_name=%s",
				__func__, smack_label, pkg_name);

	FILE* fp_group = NULL;	// /etc/group
	uid_t t_uid = -1;		// uid of current process
	gid_t *glist = NULL;	// group list
	gid_t temp_gid = -1;	// for group list
	char buf[10] = {0, };		// contents in group_list file
	int glist_cnt = 0;		// for group list
	int result;
	int i;
	new_user usr;
	unsigned *additional_gids = NULL;

	/*
	 * initialize user structure
	 */
	C_LOGD("Initialize user structure");
	memset(usr.user_name, 0x00, 10);
	memset(usr.home_dir, 0x00, 64);
	memset(usr.group_list, 0x00, 64);
	usr.uid = -1;
	usr.gid = -1;

	t_uid = getuid();
	C_LOGD("Current uid is %d", t_uid);

	if(t_uid == 0)	// current user is 'root'
	{
		if(!strncmp(pkg_name, "developer", 9))
		{
			strncpy(usr.user_name, DEV_USER_NAME, sizeof(usr.user_name));
			usr.uid = DEVELOPER_UID;
			usr.gid = DEVELOPER_GID;
			strncpy(usr.home_dir, DEV_HOME_DIR, sizeof(usr.home_dir));
			strncpy(usr.group_list, DEV_GROUP_PATH, sizeof(usr.group_list));
		}
		else
		{
			strncpy(usr.user_name, APP_USER_NAME, sizeof(usr.user_name));
			usr.uid = APP_UID;
			usr.gid = APP_GID;
			strncpy(usr.home_dir, APP_HOME_DIR, sizeof(usr.home_dir));
			strncpy(usr.group_list, APP_GROUP_PATH, sizeof(usr.group_list));
		}

		/*
		 * get group information
		 */
		C_LOGD("Get group information");
		SECURE_C_LOGD("Opening file %s.", usr.group_list);
		if(!(fp_group = fopen(usr.group_list, "r")))
		{
			C_LOGE("fopen failed.");
			result = PC_ERR_FILE_OPERATION;	// return -1
			goto error;
		}

		while(fgets(buf, 10, fp_group) != NULL)
		{
			errno = 0;
			temp_gid = strtoul(buf, 0, 10);
			if(errno != 0)	// error occured during strtoul()
			{
				C_LOGE("Cannot change string to integer: %s", buf);
				result = PC_ERR_INVALID_OPERATION;
				goto error;
			}

			glist = (gid_t*)realloc(glist, sizeof(gid_t) * (glist_cnt + 1));
			if(!glist)
			{
				result = PC_ERR_MEM_OPERATION;	// return -2
				C_LOGE("Cannot allocate memory");
				goto error;
			}
			glist[glist_cnt] = temp_gid;
			glist_cnt++;
		}
		fclose(fp_group);
		fp_group = NULL;

		/*
		 * in case of dialer, add admin to glist
		 */
		if(!strncmp(pkg_name, "com.samsung.phone", 17) || !strncmp(pkg_name, "com.samsung.call", 16) ||
		   !strncmp(pkg_name, "phone-tabui-efl", 15) || !strncmp(pkg_name, "com.samsung.dialer", 18) ||
		   !strncmp(pkg_name, "com.samsung.w-dialer2", 21))
		{
			gid_t *glist_new;
			C_LOGD("Dialer app - add admin to glist");
			glist_new = (gid_t*)realloc(glist, sizeof(gid_t) * (glist_cnt + 1));
			if (glist_new == NULL) {
				result = PC_ERR_MEM_OPERATION;	// return -2
				C_LOGE("Memory allocation failed");
				goto error;
			}
			glist = glist_new;
			glist[glist_cnt] = ADMIN_GROUP;	// 6504
			glist_cnt++;
		}

		if(NULL != smack_label)
		{
			gid_t *glist_new;
			int i, cnt;

			result = get_app_gids(smack_label, &additional_gids, &cnt);
			if (result != PC_OPERATION_SUCCESS)
				goto error;

			if (cnt > 0) {
				glist_new = (gid_t*)realloc(glist, sizeof(gid_t) * (glist_cnt + cnt));
				if (glist_new == NULL) {
					result = PC_ERR_MEM_OPERATION;	// return -2
					C_LOGE("Memory allocation failed");
					goto error;
				}
				glist = glist_new;
				for (i = 0; i < cnt; ++i) {
					C_LOGD("Additional GID based on enabled permissions: %u", additional_gids[i]);
					glist[glist_cnt++] = additional_gids[i];
				}
			}
		}

		/*
		 * setgroups()
		 */
		C_LOGD("Adding process to the following groups:");
		for(i=0; i<glist_cnt; ++i) {
			SECURE_C_LOGD("glist [ %d ] = %d", i, glist[i]);
		}
		C_LOGD("Calling setgroups()");
		if(setgroups(glist_cnt, glist) != 0)
		{
			C_LOGE("setgroups failed");
			result = PC_ERR_NOT_PERMITTED;	// return -3
			goto error;
		}
		if(glist != NULL)
		{
			free(glist);
			glist = NULL;
		}

		/*
		 * setuid() & setgid()
		 */
		C_LOGD("setgid( %d ) & setuid( %d )", usr.gid, usr.uid);
		if(setgid(usr.gid) != 0)	// fail
		{
			C_LOGE("Failed to execute setgid().");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}
		if(setuid(usr.uid) != 0)	// fail
		{
			C_LOGE("Failed to execute setuid().");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}

		SECURE_C_LOGD("setenv(): USER = %s, HOME = %s", usr.user_name, usr.home_dir);
		if(setenv("USER", usr.user_name, 1) != 0)	//fail
		{
			C_LOGE("Failed to execute setenv() [USER].");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}
		if(setenv("HOME", usr.home_dir, 1) != 0)	// fail
		{
			C_LOGE("Failed to execute setenv() [HOME].");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}
	}
	else	// current user is not only 'root' but 'app'
	{
		C_LOGE("Current user is NOT root");
		result = PC_ERR_NOT_PERMITTED;	// return -3
		goto error;
	}

	result = PC_OPERATION_SUCCESS;

error:
	if(fp_group != NULL)
		fclose(fp_group);
	if(glist != NULL)
		free(glist);
	free(additional_gids);

	return result;
}

/**
 * Get SMACK label from EXEC label of a file.
 * SMACK label should be freed by caller
 *
 * @param path file path to take label from
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
static int get_smack_from_binary(char **smack_label, const char* path, app_type_t type)
{
	SECURE_C_LOGD("Entering function: %s. Params: path=%s, type=%d",
				__func__, path, type);
	int ret;

	*smack_label = NULL;
	if (type == PERM_APP_TYPE_WRT
	|| type == PERM_APP_TYPE_WRT_PARTNER
	|| type == PERM_APP_TYPE_WRT_PLATFORM) {
		ret = smack_lgetlabel(path, smack_label, SMACK_LABEL_EXEC);
	} else {
		ret = smack_getlabel(path, smack_label, SMACK_LABEL_EXEC);
	}
	if (ret != 0) {
		C_LOGE("Getting exec label from file %s failed", path);
		return PC_ERR_INVALID_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

/**
 * Set process SMACK label.
 * This function is emulating EXEC label behavior of SMACK for programs
 * run by dlopen/dlsym instead of execv.
 *
 * @param smack label
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
static int set_smack_for_self (char *smack_label)
{
	SECURE_C_LOGD("Entering function: %s. Params: smack_label=%s",
				__func__, smack_label);
	int ret;

	if (smack_label == NULL) {
		/* No label to set, just return with success */
		C_LOGD("No label to set, just return with success.");
		ret = PC_OPERATION_SUCCESS;
	}
	else {
		SECURE_C_LOGD("smack_label=%s", smack_label);
		if (have_smack()) {
			ret = smack_set_label_for_self(smack_label);
			C_LOGD("smack_set_label_for_self returned %d", ret);
		} else
			ret = PC_OPERATION_SUCCESS;
	}

	return ret;
}

static int is_widget(const char* path)
{
	SECURE_C_LOGD("Entering function: %s. Params: path=%s",
				__func__, path);
	char buf[sizeof(WRT_CLIENT_PATH)];
	int ret;

	ret = readlink(path, buf, sizeof(WRT_CLIENT_PATH));
	if (ret == -1)
		C_LOGD("readlink(%s) returned error: %s. Assuming that app is not a widget", path, strerror(errno));
	else if (ret == sizeof(WRT_CLIENT_PATH))
		C_LOGD("%s is not a widget", path);
	if (ret == -1 || ret == sizeof(WRT_CLIENT_PATH))
		return 0;
	buf[ret] = '\0';
	C_LOGD("buf=%s", buf);

	ret = !strcmp(WRT_CLIENT_PATH, buf);
	C_LOGD("%s is %s widget", path, ret ? "a" : "not a");
	return (ret);
}

/**
 * Partially verify, that the type given for app is correct.
 * This function will use some heuristics to check whether the app type is right.
 * It is intended for security hardening to catch privilege setting for the
 * app type not corresponding to the actual binary.
 * Beware - when it detects an anomaly, the whole process will be terminated.
 *
 * @param type claimed application type
 * @param path file path to executable
 * @return return void on success, terminate the process on error
 */
static app_type_t verify_app_type(const char* type, const char* path)
{
	SECURE_C_LOGD("Entering function: %s. Params: type=%s, path=%s",
				__func__, type, path);

	/* TODO: this should actually be treated as error, but until the old
	 * set_privilege API is removed, it must be ignored */
	if (path == NULL) {
		C_LOGD("PKG_TYPE_OTHER");
		return APP_TYPE_OTHER; /* good */
	}

	if (is_widget(path)) {
		if (!strcmp(type, "wgt")) {
			C_LOGD("PKG_TYPE_WRT");
			return PERM_APP_TYPE_WRT; /* good */
		} else if (!strcmp(type, "wgt_partner")) {
			C_LOGD("PKG_TYPE_WRT_PARTNER");
			return PERM_APP_TYPE_WRT_PARTNER; /* good */
		} else if (!strcmp(type, "wgt_platform")) {
			C_LOGD("PKG_TYPE_WRT_PLATFORM");
			return PERM_APP_TYPE_WRT_PLATFORM; /* good */
		}

	} else {
		if (type == NULL || (strcmp(type, "wgt")
				&& strcmp(type, "wgt_partner")
				&& strcmp(type, "wgt_platform"))){
			C_LOGD("PKG_TYPE_OTHER");
			return PERM_APP_TYPE_OTHER; /* good */
		}
	}

	/* bad */
	C_LOGE("EXIT_FAILURE");
	exit(EXIT_FAILURE);
}

#ifdef SECCOMP_ENABLED
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <stddef.h>	    		// offsetof
#include <asm/unistd.h>			// syscall numbers (__NR_#name)

#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

#define regoffset(_reg) (offsetof(struct user_regs_struct, _reg))

static int prctl_error(int option) {
	if(EINVAL == errno) {
		C_LOGW("prctl(%d,...) didn't accept arguments. Seccomp is probably disabled in kernel. Ignoring.", option);
		return PC_OPERATION_SUCCESS;
	}
	C_LOGE("prctl(%d,...) failed: %s", option, strerror(errno));
	return PC_ERR_NOT_PERMITTED;
}

static int apply_seccomp_filter() {
	struct sock_filter filter[] = {
		/* Grab the system call number. */
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),

		/* Block ptrace */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_ptrace, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
	};
	struct sock_fprog prog = {
			(unsigned short) (sizeof(filter) / sizeof(filter[0])), filter };

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		return prctl_error(PR_SET_NO_NEW_PRIVS);
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
		return prctl_error(PR_SET_SECCOMP);
	return PC_OPERATION_SUCCESS;
}
#endif //SECCOMP_ENABLED

API int set_app_privilege(const char* name, const char* type, const char* path)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: name=%s, type=%s, path=%s",
				__func__, name, type, path);

	return perm_app_set_privilege(name, type, path);
}

API int perm_app_set_privilege(const char* name, const char* type, const char* path)
{
	SECURE_C_LOGD("Entering function: %s. Params: name=%s, type=%s, path=%s",
				__func__, name, type, path);

	//SECURE_C_LOGD("Function params: name = %s, type = %s, path = %s", name, type, path);
	int ret = PC_OPERATION_SUCCESS;
	char *smack_label AUTO_FREE;

	if (name == NULL) {
		C_LOGE("Error invalid parameter");
		return PC_ERR_INVALID_PARAM;
	}

	if (path != NULL && have_smack()) {
		ret = get_smack_from_binary(&smack_label, path, verify_app_type(type, path));
		if (ret != PC_OPERATION_SUCCESS)
			return ret;

		ret = set_smack_for_self(smack_label);
		if (ret != PC_OPERATION_SUCCESS)
			return ret;
	}

	if (path != NULL && !have_smack()) {
		ret = get_smack_from_binary(&smack_label, path, verify_app_type(type, path));
		if (ret != PC_OPERATION_SUCCESS)
			return ret;
	}

	ret = set_dac(smack_label, name);
	if (ret != PC_OPERATION_SUCCESS)
		return ret;

#ifdef SECCOMP_ENABLED
	ret = apply_seccomp_filter();
#endif
	return ret;
}


API int perm_app_set_privilege_debug(const char* name, const char* type, const char* path)
{
	SECURE_C_LOGD("Entering function: %s. Params: name=%s, type=%s, path=%s",
				__func__, name, type, path);

	return perm_app_set_privilege(name, type, path);
}

API int set_privilege(const char* pkg_name)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_name=%s",
				__func__, pkg_name);

	return perm_app_set_privilege(pkg_name, NULL, NULL);
}

static int perm_file_path(char** path, app_type_t app_type, const char* perm, const char *suffix, bool is_early)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d, perm=%s, suffix=%s, is_early=%d",
				__func__, app_type, perm, suffix, is_early);

	const char* app_type_prefix = NULL;
	char* perm_basename = NULL;
	int ret = 0;

	if (perm == NULL || strlen(perm) == 0) {
		C_LOGE("Empty permission name.");
		return PC_ERR_INVALID_PARAM;
	}

	app_type_prefix = app_type_group_name(app_type);

	ret = base_name_from_perm(perm, &perm_basename);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Couldn't get permission basename.");
		return ret;
	}

	if (is_early) {
		ret = asprintf(path, TOSTRING(SHAREDIR) "/%s%s%s%s%s",
		app_type_prefix ? app_type_prefix : "", app_type_prefix ? "_" : "",
		perm_basename, "_early", suffix);
	}
	else {
		ret = asprintf(path, TOSTRING(SHAREDIR) "/%s%s%s%s",
		app_type_prefix ? app_type_prefix : "", app_type_prefix ? "_" : "",
		perm_basename, suffix);
	}
	if (ret == -1) {
		C_LOGE("asprintf failed.");
		return PC_ERR_MEM_OPERATION;
	}

	C_LOGD("Path=%s", *path);

	return PC_OPERATION_SUCCESS;
}

static int perm_to_dac(const char* app_label, app_type_t app_type, const char* perm)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_label=%s, app_type=%d, perm=%s",
				__func__, app_label, app_type, perm);

	int ret;
	char* path AUTO_FREE;
	FILE* file AUTO_FCLOSE;
	int gid;

	ret = perm_file_path(&path, app_type, perm, ".dac", 0);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGD("No dac config file for permission %s", perm);
		return ret;
	}

	SECURE_C_LOGD("Opening file %s.", path);
	file = fopen(path, "r");
	if (file == NULL) {
		C_LOGW("fopen failed.");
		return PC_OPERATION_SUCCESS;
	}

	while (fscanf(file, "%d\n", &gid) == 1) {
		SECURE_C_LOGD("Adding app_id %s to group %d", app_label, gid);
		ret = add_app_gid(app_label, gid);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("add_app_gid failed");
			return ret;
		}
	}

	return PC_OPERATION_SUCCESS;
}

static int label_all(const FTSENT* ftsent UNUSED)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	return DECISION_LABEL;
}

static int label_execs(const FTSENT* ftsent)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	C_LOGD("Mode = %d", ftsent->fts_statp->st_mode);
	// label only regular executable files
	if (S_ISREG(ftsent->fts_statp->st_mode) && (ftsent->fts_statp->st_mode & S_IXUSR))
		return DECISION_LABEL;
	return DECISION_SKIP;
}

static int label_dirs(const FTSENT* ftsent)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	// label only directories
	if (S_ISDIR(ftsent->fts_statp->st_mode))
		return DECISION_LABEL;
	return DECISION_SKIP;
}

static int label_links_to_execs(const FTSENT* ftsent)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	struct stat buf;
	char* target AUTO_FREE;

	// check if it's a link
	if ( !S_ISLNK(ftsent->fts_statp->st_mode))
		return DECISION_SKIP;

	target = realpath(ftsent->fts_path, NULL);
	if (!target) {
		SECURE_C_LOGE("Getting link target for %s failed (Error = %s)", ftsent->fts_path, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}
	if (-1 == stat(target, &buf)) {
		SECURE_C_LOGE("stat failed for %s (Error = %s", target, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}
	// skip if link target is not a regular executable file
	if (buf.st_mode != (buf.st_mode | S_IXUSR | S_IFREG)) {
		SECURE_C_LOGD("%s is not a regular executable file. Skipping.", target);
		return DECISION_SKIP;
	}

	return DECISION_LABEL;
}

static int dir_set_smack_r(const char *path, const char* label,
		enum smack_label_type type, label_decision_fn fn)
{
	SECURE_C_LOGD("Entering function: %s. Params: path=%s, label=%s, type=%d",
				__func__, path, label, type);

	const char* path_argv[] = {path, NULL};
	FTS *fts AUTO_FTS_CLOSE;
	FTSENT *ftsent;
	int ret;

	fts = fts_open((char * const *) path_argv, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL) {
		C_LOGE("fts_open failed.");
		return PC_ERR_FILE_OPERATION;
	}

	while ((ftsent = fts_read(fts)) != NULL) {
		/* Check for error (FTS_ERR) or failed stat(2) (FTS_NS) */
		if (ftsent->fts_info == FTS_ERR || ftsent->fts_info == FTS_NS) {
			C_LOGE("FTS_ERR error or failed stat(2) (FTS_NS)");
			return PC_ERR_FILE_OPERATION;
		}

		ret = fn(ftsent);
		if (ret < 0) {
			C_LOGE("fn(ftsent) failed.");
			return ret;
		}

		if (ret == DECISION_LABEL) {
			C_LOGD("smack_lsetlabel (label: %s (type: %d), path: %s)", label, type, ftsent->fts_path);
			if (smack_lsetlabel(ftsent->fts_path, label, type) != 0) {
				C_LOGE("smack_lsetlabel failed.");
				return PC_ERR_FILE_OPERATION;
			}
		}
	}

	/* If last call to fts_read() set errno, we need to return error. */
	if (errno != 0) {
		C_LOGE("Last errno from fts_read: %s", strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}
	return PC_OPERATION_SUCCESS;
}
API char* app_id_from_socket(int sockfd)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: sockfd=%d",
				__func__, sockfd);

    return perm_app_id_from_socket(sockfd);
}

API char* perm_app_id_from_socket(int sockfd)
{
	SECURE_C_LOGD("Entering function: %s. Params: sockfd=%d",
				__func__, sockfd);

	if (!have_smack()) {
		C_LOGD("No SMACK. Returning NULL.");
		return NULL;
	}

	char* app_id;
	int ret;

	ret = smack_new_label_from_socket(sockfd, &app_id);
	if (ret < 0) {
		C_LOGE("smack_new_label_from_socket failed");
		return NULL;
	}

	SECURE_C_LOGD("app_id = %s", app_id);

	return app_id;
}


API int app_add_permissions(const char* app_id, const char** perm_list)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
				__func__, app_id);

	return perm_app_enable_permissions(app_id, APP_TYPE_OTHER, perm_list, true);
}

API int app_add_volatile_permissions(const char* app_id, const char** perm_list)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
				__func__, app_id);

	return perm_app_enable_permissions(app_id, APP_TYPE_OTHER, perm_list, false);
}

API int perm_app_setup_permissions(const char* pkg_id, app_type_t app_type,
				   const char** perm_list)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d",
				__func__, pkg_id, app_type);
	return perm_app_enable_permissions(pkg_id, app_type, perm_list, true);
}

API int app_enable_permissions(const char* pkg_id, app_type_t app_type, const char** perm_list, bool persistent)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d, persistent=%d",
				__func__, pkg_id, app_type, persistent);

	return perm_app_enable_permissions(pkg_id, app_type, perm_list, persistent);
}

API int perm_app_enable_permissions(const char* pkg_id, app_type_t app_type,
				    const char** perm_list, bool persistent)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d, persistent=%d",
				__func__, pkg_id, app_type, persistent);

	int i, ret;

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid param app_id.");
		return PC_ERR_INVALID_PARAM;
	}

	if (perm_list == NULL) {
		C_LOGE("Invalid perm_list (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	if (app_type_group_name(app_type) == NULL) {
		C_LOGE("Unknown app type.");
		return PC_ERR_INVALID_PARAM;
	}

	/* Add permission to DAC */
	for (i = 0; perm_list[i] != NULL; ++i) {
		ret = perm_to_dac(pkg_id, app_type, perm_list[i]);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("perm_to_dac failed");
			return ret;
		}
	}

	/* Enable the permissions: */
	ret = rdb_enable_app_permissions(pkg_id, app_type, perm_list,
					 !((bool)persistent));
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_enable_app_permissions failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_disable_permissions(const char* pkg_id, app_type_t app_type, const char** perm_list)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d",
				__func__, pkg_id, app_type);

	return perm_app_disable_permissions(pkg_id, app_type, perm_list);
}

API int perm_app_disable_permissions(const char* pkg_id, app_type_t app_type, const char** perm_list)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d",
				__func__, pkg_id, app_type);

	int ret;
	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid param app_id.");
		return PC_ERR_INVALID_PARAM;
	}

	if (perm_list == NULL) {
		C_LOGE("Invalid perm_list (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	if (app_type_group_name(app_type) == NULL) {
		C_LOGE("Unknown app type.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_disable_app_permissions(pkg_id, app_type, perm_list);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_disable_app_permissions failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_revoke_permissions(const char* pkg_id)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s", __func__, pkg_id);
	return perm_app_revoke_permissions(pkg_id);
}

API int perm_app_revoke_permissions(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s", __func__, pkg_id);
	int ret;

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid param app_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_revoke_app_permissions(pkg_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_disable_app_permissions failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_reset_permissions(const char* pkg_id)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s",
				__func__, pkg_id);

	return perm_app_reset_permissions(pkg_id);
}

API int perm_app_reset_permissions(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s",
				__func__, pkg_id);
	int ret;

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid param pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_reset_app_permissions(pkg_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_disable_app_permissions failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int perm_app_has_permission(const char *pkg_id,
				app_type_t app_type,
				const char *permission_name,
				bool *is_enabled)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d, permission_name=%s",
				__func__, pkg_id, app_type, permission_name);

	const char *app_group = app_type_group_name(app_type);

	if (app_group == NULL) {
		C_LOGE("Unknown param app type.");
		return PC_ERR_INVALID_PARAM;
	}

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid param app_id.");
		return PC_ERR_INVALID_PARAM;
	}

	if (permission_name == NULL) {
		C_LOGE("Invalid param permission_name (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	if (is_enabled == NULL) {
		C_LOGE("Invalid param is_enabled (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	return rdb_app_has_permission(pkg_id, app_group, permission_name, is_enabled);
}

API int perm_app_get_permissions(const char *pkg_id, app_type_t app_type, char ***ppp_perm_list)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d", __func__, pkg_id,
		      app_type);

	const char *app_group = app_type_group_name(app_type);
	int ret;

	if (ppp_perm_list == NULL) {
		C_LOGE("Invalid param ppp_perm_list (NULL).");
		return PC_ERR_INVALID_PARAM;
	}
	// Set the given pointer to NULL in case of future failure.
	*ppp_perm_list = NULL;

	if (app_group == NULL) {
		C_LOGE("Unknown param app type.");
		return PC_ERR_INVALID_PARAM;
	}

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid param app_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_app_get_permissions(pkg_id, app_group, ppp_perm_list);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_app_get_permissions failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_label_dir(const char* label, const char* path)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: label=%s, path=%s",
				__func__, label, path);

	int ret = PC_OPERATION_SUCCESS;

	if(path == NULL) {
		C_LOGE("Invalid argument path (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	if (!smack_label_is_valid(label)) {
		C_LOGE("Invalid param label.");
		return PC_ERR_INVALID_PARAM;
	}

	//setting access label on everything in given directory and below
	ret = dir_set_smack_r(path, label, SMACK_LABEL_ACCESS, &label_all);
	if (PC_OPERATION_SUCCESS != ret)
	{
		C_LOGE("dir_set_smack_r failed.");
		return ret;
	}

	//setting execute label for everything with permission to execute
	ret = dir_set_smack_r(path, label, SMACK_LABEL_EXEC, &label_execs);
	if (PC_OPERATION_SUCCESS != ret)
	{
		C_LOGE("dir_set_smack_r failed.");
		return ret;
	}

	//setting execute label for everything with permission to execute
	ret = dir_set_smack_r(path, label, SMACK_LABEL_EXEC, &label_links_to_execs);
	return ret;
}


API int app_label_shared_dir(const char* app_label, const char* shared_label, const char* path)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: app_label=%s, shared_label=%s, path=%s",
				__func__, app_label, shared_label, path);
	int ret;

	if(path == NULL) {
		C_LOGE("Invalid param path.");
		return PC_ERR_INVALID_PARAM;
	}

	if(!smack_label_is_valid(app_label)) {
		C_LOGE("Invalid param app_label");
		return PC_ERR_INVALID_PARAM;
	}

	if(!smack_label_is_valid(shared_label)) {
		C_LOGE("Invalid param shared_label");
		return PC_ERR_INVALID_PARAM;
	}

	if (strcmp(app_label, shared_label) == 0) {
		C_LOGE("app_label equals shared_label");
		return PC_ERR_INVALID_PARAM;
	}

	//setting label on everything in given directory and below
	ret = dir_set_smack_r(path, shared_label, SMACK_LABEL_ACCESS, label_all);
	if(ret != PC_OPERATION_SUCCESS){
		C_LOGE("dir_set_smack_r failed.");
		return ret;
	}

	//setting transmute on dir
	ret = dir_set_smack_r(path, "1", SMACK_LABEL_TRANSMUTE, label_dirs);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("dir_set_smack_r failed");
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int add_shared_dir_readers(const char* shared_label UNUSED, const char** app_list UNUSED)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: shared_label=%s",
				__func__, shared_label);

	C_LOGE("add_shared_dir_readers is deprecated and unimplemented!");

	// TODO: This function is not implemented with RDB.
	return PC_ERR_INVALID_OPERATION;
}

static char* smack_label_for_path(const char *app_id, const char *path)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s, path=%s",
				__func__, app_id, path);

	char *salt AUTO_FREE;
	char *label;
	char *x;

	/* Prefix $1$ causes crypt() to use MD5 function */
	if (-1 == asprintf(&salt, "$1$%s", app_id)) {
		C_LOGE("asprintf failed");
		return NULL;
	}

	label = crypt(path, salt);
	if (label == NULL) {
		C_LOGE("crypt failed");
		return NULL;
	}

	/* crypt() output may contain slash character,
	 * which is not legal in Smack labels */
	for (x = label; *x; ++x) {
		if (*x == '/')
			*x = '%';
	}

	return label;
}

/* FIXME: remove this pragma once deprecated API is deleted */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static int perm_app_setup_path_internal(const char* pkg_id, const char* path, app_path_type_t app_path_type, va_list ap)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, path=%s, app_path_type=%d",
				__func__, pkg_id, path, app_path_type);

	if(path == NULL) {
		C_LOGE("Invalid argument path.");
		return PC_ERR_INVALID_PARAM;
	}

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid pkg_id.");
		SECURE_C_LOGE("Invalid pkg_id %s", pkg_id);
		return PC_ERR_INVALID_PARAM;
	}

	switch (app_path_type) {
	case APP_PATH_PRIVATE:
		C_LOGD("app_path_type is APP_PATH_PRIVATE.");
		return app_label_dir(pkg_id, path);

	case APP_PATH_GROUP: {
		C_LOGD("app_path_type is APP_PATH_GROUP.");
		int ret;
		const char *shared_label;

		shared_label = va_arg(ap, const char *);

		if (!smack_label_is_valid(shared_label)) {
			C_LOGE("Invalid shared_label.");
			return PC_ERR_INVALID_PARAM;
		}

		if (strcmp(pkg_id, shared_label) == 0) {
			C_LOGE("pkg_id equals shared_label.");
			return PC_ERR_INVALID_PARAM;
		}

		ret = app_label_shared_dir(pkg_id, shared_label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("app_label_shared_dir failed: %d", ret);
			return ret;
		}

		// Add the path to the database:
		ret = rdb_add_path(pkg_id, shared_label, path, "rwxatl", "-", "GROUP_PATH");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("RDB rdb_add_path failed with: %d", ret);
			return ret;
		}

		return PC_OPERATION_SUCCESS;
	}

	case APP_PATH_PUBLIC: {
		C_LOGD("app_path_type is APP_PATH_PUBLIC.");
		char **app_ids AUTO_FREE;
		const char *label;
		int ret;

		C_LOGD("New public RO path %s", path);

		// Generate label:
		label = smack_label_for_path(pkg_id, path);
		if (label == NULL) {
			C_LOGE("smack_label_for_path failed.");
			return PC_ERR_INVALID_OPERATION;
		}
		C_LOGD("Generated label '%s' for public RO path %s", label, path);

		ret = app_label_shared_dir(pkg_id, label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("app_label_shared_dir failed.");
			return ret;
		}

		// Add the path to the database:
		ret = rdb_add_path(pkg_id, label, path, "rwxatl", "-", "PUBLIC_PATH");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("RDB rdb_add_path failed with: %d", ret);
			return ret;
		}

		return PC_OPERATION_SUCCESS;
	}

	case APP_PATH_SETTINGS: {
		C_LOGD("app_path_type is APP_PATH_SETTINGS.");
		char **app_ids AUTO_FREE;
		const char *label;
		int ret;

		// Generate label:
		label = smack_label_for_path(pkg_id, path);
		if (label == NULL) {
			C_LOGE("smack_label_for_path failed.");
			return PC_ERR_INVALID_OPERATION;
		}
		C_LOGD("Appsetting: generated label '%s' for setting path %s", label, path);

		/*set id for path and all subfolders*/
		ret = app_label_shared_dir(pkg_id, label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("Appsetting: app_label_shared_dir failed (%d)", ret);
			return ret;
		}

		// Add the path to the database:
		ret = rdb_add_path(pkg_id, label, path, "rwxatl", "-", "SETTINGS_PATH");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("RDB rdb_add_path failed with: %d", ret);
			return ret;
		}

		return PC_OPERATION_SUCCESS;
	}

	case PERM_APP_PATH_NPRUNTIME: {
		C_LOGD("app_path_type is PERM_APP_PATH_NPRUNTIME.");
		char label[SMACK_LABEL_LEN + 1];
		int ret;

		// Create label:
		if ((strlen(pkg_id) + strlen(".npruntime")) > SMACK_LABEL_LEN) {
			C_LOGE("cannot create npruntime label, pkg_id is too long.");
			return PC_ERR_INVALID_PARAM;
		}
		ret = sprintf(label, "%s.npruntime", pkg_id);
		if (ret <= 0) {
			C_LOGE("creating npruntime label failed.");
			return PC_ERR_INVALID_OPERATION;
		}
		C_LOGD("Generated npruntime label '%s' for path %s", label, path);

		// Label executable/symlink
		ret = set_exec_label(label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("cannot set executable label '%s' for path %s.", label, path);
			return ret;
		}

		// Add the path to the database:
		ret = rdb_add_path(pkg_id, label, path, "rw", "rxat", "NPRUNTIME_PATH");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("RDB rdb_add_path failed with: %d", ret);
			return ret;
		}

		return PC_OPERATION_SUCCESS;
	}

	case APP_PATH_ANY_LABEL: {
		C_LOGD("app_path_type is APP_PATH_ANY_LABEL.");
		const char *label = NULL;
		label = va_arg(ap, const char *);
		return app_label_dir(label, path);
	}

	default:
		C_LOGE("app_path_type is invalid.");
		return PC_ERR_INVALID_PARAM;
	}

	return PC_OPERATION_SUCCESS;
}
/* FIXME: remove this pragma once deprecated API is deleted */
#pragma GCC diagnostic warning "-Wdeprecated-declarations"

API int app_setup_path(const char* pkg_id, const char* path, app_path_type_t app_path_type, ...)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, path=%s, app_path_type=%d",
				__func__, pkg_id, path, app_path_type);

	va_list ap;
	int ret;
	va_start( ap, app_path_type );
	ret = perm_app_setup_path_internal( pkg_id, path, app_path_type, ap );
	va_end( ap );
	return ret;
}


API int perm_app_setup_path(const char* pkg_id, const char* path, app_path_type_t app_path_type, ...)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, path=%s, app_path_type=%d",
				__func__, pkg_id, path, app_path_type);

	va_list ap;
	int ret;
	va_start( ap, app_path_type );
	ret = perm_app_setup_path_internal( pkg_id, path, app_path_type, ap );
	va_end( ap );
	return ret;
}

API int perm_app_get_paths(const char* pkg_id, app_path_type_t app_path_type, char*** ppp_paths)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_path_type=%d", __func__,
		      pkg_id, app_path_type);

	const char *path_type_name = app_path_type_name(app_path_type);
	int ret;

	if (ppp_paths == NULL) {
		C_LOGE("Invalid param ppp_paths (NULL).");
		return PC_ERR_INVALID_PARAM;
	}
	// Set the given pointer to NULL in case of future failure.
	*ppp_paths = NULL;

	if (path_type_name == NULL) {
		C_LOGE("Unknown or invalid param app_path_type.");
		return PC_ERR_INVALID_PARAM;
	}

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid param app_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_get_app_paths(pkg_id, path_type_name, ppp_paths);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_app_get_paths failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_add_friend(const char* pkg_id1, const char* pkg_id2)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id1=%s, pkg_id2=%s",
				__func__, pkg_id1, pkg_id2);

	return perm_app_add_friend(pkg_id1, pkg_id2);
}

API int perm_app_add_friend(const char* pkg_id1 UNUSED, const char* pkg_id2 UNUSED)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id1=%s, pkg_id2=%s",
				__func__, pkg_id1, pkg_id2);

	C_LOGE("app_register_av is deprecated and unimplemented!");

	// TODO: This function is not implemented with RDB.
	return PC_ERR_INVALID_OPERATION;
}

API int app_install(const char* pkg_id)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s",
				__func__, pkg_id);

	return perm_app_install(pkg_id);
}

API int perm_app_install(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s",
				__func__, pkg_id);
	int ret;
	int fd AUTO_CLOSE;
	char* smack_path AUTO_FREE;
	struct smack_accesses *smack AUTO_SMACK_FREE;

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid param pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	// Add application to the database:
	ret = rdb_add_application(pkg_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_add_application failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_uninstall(const char* pkg_id)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s",
				__func__, pkg_id);

	return perm_app_uninstall(pkg_id);
}

API int perm_app_uninstall(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s", __func__, pkg_id);
	char* smack_path AUTO_FREE;
	int ret;

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid param pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	// Remove application from the database
	ret = rdb_remove_application(pkg_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_remove_application failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

static int save_gids(FILE* file, const gid_t* list_of_db_gids, size_t list_size) {

	SECURE_C_LOGD("Entering function: %s.", __func__);
	int ret = PC_OPERATION_SUCCESS;
	int written = 0;
	size_t i = 0;

	if (file == NULL) {
		C_LOGE("Unable to create file. Error: %s", strerror(errno));
		return PC_ERR_FILE_OPERATION;	// TODO remove smack accesses?
	}

	if(-1 == fchmod(fileno(file), 0644)) {
		C_LOGE("Unable to chmod file. Error: %s", strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	for (i = 0; i < list_size ; ++i) {
		written = fprintf(file, "%u\n", list_of_db_gids[i]);
		if (written <= 0) {
			C_LOGE("fprintf failed for file. Error: %s", strerror(errno));
			ret = PC_ERR_FILE_OPERATION;
			break;
		}
	}
	return ret;
}

API int add_api_feature(app_type_t app_type,
                        const char* api_feature_name,
                        const char** smack_rules,
                        const gid_t* list_of_db_gids,
                        size_t list_size)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d, api_feature_name=%s",
				__func__, app_type, api_feature_name);

    return perm_add_api_feature(app_type, api_feature_name, smack_rules, list_of_db_gids, list_size);
}

API int perm_add_api_feature(app_type_t app_type,
						const char* api_feature_name,
						const char** smack_rules,
						const gid_t* list_of_db_gids,
						size_t list_size) {
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d, api_feature_name=%s",
				__func__, app_type, api_feature_name);

	int ret = PC_OPERATION_SUCCESS;
	char* smack_file AUTO_FREE;
	char* dac_file AUTO_FREE;
	char * base_api_feature_name AUTO_FREE;
	FILE* file = NULL;
	// struct smack_accesses* accesses = NULL;
	const char *s_type_name = app_type_name(app_type);

	// Check input values
	if (s_type_name == NULL || !strcmp(s_type_name, "")) {
		C_LOGE("Unknown api type");
		return PC_ERR_INVALID_PARAM;
	}

	if (api_feature_name == NULL || strlen(api_feature_name) == 0) {
		C_LOGE("Api feature name is empty.");
		return PC_ERR_INVALID_PARAM;
	}

	if (smack_rules && ((ret = validate_all_rules(smack_rules) ) != PC_OPERATION_SUCCESS) ) {
		C_LOGE("Error in rules list.");
		return ret;
	}

	// check .dac existence only if gids are supported
	if (list_of_db_gids && list_size > 0) {
		// get feature DAC file name
		ret = perm_file_path(&dac_file, app_type, api_feature_name, ".dac", 0);
		if (ret != PC_OPERATION_SUCCESS || !dac_file ) {
			C_LOGE("perm_file_path failed.");
			return ret;
		}

		unlink(dac_file);
	}

	// go through gid list
	if (ret == PC_OPERATION_SUCCESS && list_of_db_gids && list_size > 0) {
		// save to file
		SECURE_C_LOGD("Opening file %s.", dac_file);
		file = fopen(dac_file, "w+");
		ret = save_gids(file, list_of_db_gids, list_size);
		if(file) fclose(file);
	}

	// remove file in case of failure
	if (ret != PC_OPERATION_SUCCESS && dac_file) {
		unlink(dac_file);
	}

	ret = base_name_from_perm(api_feature_name, &base_api_feature_name);
	if (ret != PC_OPERATION_SUCCESS){
		C_LOGE("Error during creating base name: ", ret);
		return ret;
	}

	// Save api feature to the database.
	ret = rdb_add_permission_rules(base_api_feature_name, s_type_name, smack_rules);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_add_permission_rules failed with: %d", ret);
		return ret;
	}

	return ret;
}

/**
 * This function is marked as deprecated and will be removed
 */
API int app_register_av(const char* app_av_id UNUSED)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: app_av_id=%s",
				__func__, app_av_id);

	C_LOGE("app_register_av is deprecated and unimplemented!");

	// TODO: This function is not implemented with RDB.
	return PC_ERR_INVALID_OPERATION;
}

API int perm_add_additional_rules(const char** smack_rules){
	SECURE_C_LOGD("Entering function: %s.", __func__);
	int ret;
	if (!smack_rules){
		C_LOGE("smack_rules is NULL");
		return PC_ERR_INVALID_PARAM;
	}

	ret = rdb_add_additional_rules(smack_rules);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("RDB rdb_add_additional_rules failed with: %d", ret);
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API const char* perm_strerror(int errnum)
{
	switch (errnum) {
	case PC_OPERATION_SUCCESS:
		return "Success";
	case PC_ERR_FILE_OPERATION:
		return "File operation error";
	case PC_ERR_MEM_OPERATION:
		return "Memory operation error";
	case PC_ERR_NOT_PERMITTED:
		return "Operation not permitted";
	case PC_ERR_INVALID_PARAM:
		return "Invalid parameter";
	case PC_ERR_INVALID_OPERATION:
		return "Invalid operation";
	case PC_ERR_DB_OPERATION:
		return "Database operation error";
	case PC_ERR_DB_LABEL_TAKEN:
		return "Label taken by another application";
	case PC_ERR_DB_QUERY_PREP:
		return "Query failure during preparation";
	case PC_ERR_DB_QUERY_BIND:
		return "Query failure during binding";
	case PC_ERR_DB_QUERY_STEP:
		return "Query failure during stepping";
	case PC_ERR_DB_CONNECTION:
		return "Cannot establish a connection";
	case PC_ERR_DB_NO_SUCH_APP:
		return "No such application";
	case PC_ERR_DB_PERM_FORBIDDEN:
		return "Duplicate permission";
	default:
		return "Unknown error";
	}
}
