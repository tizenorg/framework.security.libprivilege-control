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
#include <errno.h>
#include <fcntl.h>
#include <sys/smack.h>
#include <linux/limits.h>
#include <sys/capability.h>
#include <stdbool.h>
#include <security-server-perm.h>

#include "privilege-control.h"
#include "common.h"

#define APP_GID	5000
#define APP_UID	5000
#define ADMIN_GROUP	6504
#define DEVELOPER_GID	5100
#define DEVELOPER_UID	5100
#define SYSTEM_UID	200
#define SYSTEM_GID	200

#define APP_USER_NAME	"app"
#define DEV_USER_NAME	"developer"
#define SYS_USER_NAME	"system"

#define APP_HOME_DIR	TOSTRING(HOMEDIR) "/app"
#define DEV_HOME_DIR	TOSTRING(HOMEDIR) "/developer"
#define SYS_HOME_DIR	TOSTRING(HOMEDIR) "/system"

#define APP_GROUP_PATH	"app_group_list"
#define DEV_GROUP_PATH	"dev_group_list"

#define SMACK_SRC_FILE_SUFFIX   "_src_file"
#define SMACK_SRC_DIR_SUFFIX    "_src_dir"
#define SMACK_DATA_SUFFIX       "_data"
#define WRT_BASE_DEVCAP         "WRT"

#ifdef PROFILE_TYPE_MOBILE
#define WRT_CLIENT_PATH1        "/usr/bin/wrt-client"
#define WRT_CLIENT_PATH2        "/usr/bin/WebProcess"

#elif PROFILE_TYPE_WEARABLE
#define WRT_CLIENT_PATH         "/usr/bin/wrt-client"
#define WRT_SERVICE_PATH        "/usr/bin/wrt-service"
#endif

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

/* security-server transaction */
ss_transaction *g_transaction;

int ss_error(int error)
{
	switch(error) {
	case SECURITY_SERVER_API_SUCCESS:				return PC_OPERATION_SUCCESS;
	case SECURITY_SERVER_API_ERROR_OUT_OF_MEMORY:			return PC_ERR_MEM_OPERATION;
	case SECURITY_SERVER_API_ERROR_ACCESS_DENIED:			return PC_ERR_NOT_PERMITTED;
	case SECURITY_SERVER_API_ERROR_INPUT_PARAM:			return PC_ERR_INVALID_PARAM;
	case SECURITY_SERVER_API_ERROR_FILE_OPEN_FAILED:		return PC_ERR_FILE_OPERATION;
	case SECURITY_SERVER_API_ERROR_OPERATION_NOT_PERMITTED:		return PC_ERR_INVALID_OPERATION;
	case SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_OPERATION:		return PC_ERR_DB_OPERATION;
	case SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_LABEL_TAKEN:	return PC_ERR_DB_LABEL_TAKEN;
	case SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_QUERY_PREP:		return PC_ERR_DB_QUERY_PREP;
	case SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_QUERY_BIND:		return PC_ERR_DB_QUERY_BIND;
	case SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_QUERY_STEP:		return PC_ERR_DB_QUERY_STEP;
	case SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_CONNECTION:		return PC_ERR_DB_CONNECTION;
	case SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_NO_SUCH_APP:	return PC_ERR_DB_NO_SUCH_APP;
	case SECURITY_SERVER_API_ERROR_PRIVILEGE_DB_PERM_FORBIDDEN:	return PC_ERR_DB_PERM_FORBIDDEN;

	case SECURITY_SERVER_API_ERROR_CONFIGURATION:
	case SECURITY_SERVER_API_ERROR_SOCKET:
	case SECURITY_SERVER_API_ERROR_UNKNOWN:
	default:
		return PC_ERR_INVALID_OPERATION;
	}
}

#define CALL_SS(METHOD, ...) ({							\
	int ss_ret = METHOD(__VA_ARGS__);					\
	int ret = ss_error(ss_ret);						\
	if (ret != PC_OPERATION_SUCCESS)					\
		C_LOGE(#METHOD "() failed with: %d => %s",			\
			ss_ret, perm_strerror(ret));				\
	ret;									\
})


__attribute__ ((destructor))
static void libprivilege_destructor()
{
	SECURE_C_LOGD("Entering function: %s.", __func__);
	perm_end();
}

API int perm_begin(void)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);
	if (g_transaction) {
		C_LOGW("perm_end() was not called!");
		(void) perm_end();
	}
	return ss_error(security_server_perm_begin(&g_transaction));
}

API int perm_end(void)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);
	if (!g_transaction)
		return PC_OPERATION_SUCCESS;
	return ss_error(security_server_perm_commit(&g_transaction));
}

API int perm_rollback(void)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);
	if (!g_transaction) {
		SECURE_C_LOGE("Calling perm_rollback() without former successful perm_begin().");
		return PC_ERR_INVALID_OPERATION;
	}
	return ss_error(security_server_perm_rollback(&g_transaction));
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

static int set_dac(const char *pkg_name)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_name=%s",
				__func__, pkg_name);

	FILE* fp_group = NULL;	// /etc/group
	uid_t t_uid = -1;		// uid of current process
	gid_t *glist = NULL;	// group list
	gid_t temp_gid = -1;	// for group list
	char buf[10] = {0, };		// contents in group_list file
	int glist_cnt = 0;		// for group list
	int result;
	int i;
	new_user usr;

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
			snprintf(usr.group_list, 64, TOSTRING(SHAREDIR) "/%s", DEV_GROUP_PATH);
		}
		else if(!strncmp(pkg_name, "system", 6))
		{
			strncpy(usr.user_name, SYS_USER_NAME, sizeof(usr.user_name));
			usr.uid = SYSTEM_UID;
			usr.gid = SYSTEM_GID;
			strncpy(usr.home_dir, SYS_HOME_DIR, sizeof(usr.home_dir));
			snprintf(usr.group_list, 64, TOSTRING(SHAREDIR) "/%s", APP_GROUP_PATH);
		}
		else
		{
			strncpy(usr.user_name, APP_USER_NAME, sizeof(usr.user_name));
			usr.uid = APP_UID;
			usr.gid = APP_GID;
			strncpy(usr.home_dir, APP_HOME_DIR, sizeof(usr.home_dir));
			snprintf(usr.group_list, 64, TOSTRING(SHAREDIR) "/%s", APP_GROUP_PATH);
		}

		/*
		 * get group information
		 */
		C_LOGD("Get group information");
		SECURE_C_LOGD("Opening file %s.", usr.group_list);
		if(!(fp_group = fopen(usr.group_list, "r")))
		{
			C_LOGE("fopen failed: %s", usr.group_list);
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
		/* if pkg_name == system, add system user into app group(APP_GID) */
		if(!strncmp(pkg_name, "system", 6))
		{
			glist = (gid_t*)realloc(glist, sizeof(gid_t) * (glist_cnt + 1));
			if(!glist)
			{
				result = PC_ERR_MEM_OPERATION;  // return -2
				C_LOGE("Cannot allocate memory");
				goto error;
			}
			glist[glist_cnt] = APP_GID;
			glist_cnt++;
		}

		fclose(fp_group);
		fp_group = NULL;

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

#ifdef PROFILE_TYPE_MOBILE
static int is_widget(const char* path)
{
	SECURE_C_LOGD("Entering function: %s. Params: path=%s",
				__func__, path);
	const char *wrt_client_paths[] = {WRT_CLIENT_PATH1, WRT_CLIENT_PATH2, NULL};
	char **wrt_client_path = (char **) wrt_client_paths;
	char buf[PATH_MAX];
	int ret;

	ret = readlink(path, buf, PATH_MAX-1);
	if (ret == -1) {
		C_LOGD("readlink(%s) returned error: %s. Assuming that app is not a widget", path, strerror(errno));
		return 0;
	};

	buf[ret] = '\0';
	C_LOGD("buf=%s", buf);
	while (*wrt_client_path != NULL) {
		ret = !strcmp(buf, *wrt_client_path);
		if (ret)
			break;
		wrt_client_path++;
	};

	C_LOGD("%s is %s widget", path, ret ? "a" : "not a");
	return (ret);
}
#elif PROFILE_TYPE_WEARABLE
static int is_widget(const char* path)
{
	SECURE_C_LOGD("Entering function: %s. Params: path=%s",
                                __func__, path);
        char buf[sizeof(WRT_SERVICE_PATH)+1];
        int ret;

        ret = readlink(path, buf, sizeof(WRT_SERVICE_PATH));
        if (ret == -1) {
                C_LOGD("readlink(%s) returned error: %s. Assuming that app is not a widget", path, strerror(errno));
                return 0;
        };

        buf[ret] = '\0';
        C_LOGD("buf=%s", buf);

        if(!strncmp(WRT_CLIENT_PATH, buf, strlen(WRT_CLIENT_PATH)) ||
           !strncmp(WRT_SERVICE_PATH, buf, strlen(WRT_SERVICE_PATH)))
                ret = 1;
        else
                ret = 0;

        C_LOGD("%s is %s widget", path, ret ? "a" : "not a");
        return (ret);
}
#endif

/**
 * Partially verify, that the type given for app is correct.
 * This function will use some heuristics to check whether the app type is right.
 * It is intended for security hardening to catch privilege setting for the
 * app type not corresponding to the actual binary.
 * Beware - when it detects an anomaly, the whole process will be terminated.
 *
 * @param type claimed application type
 * @param path file path to executable
 * @return return recognized type enum on success, terminate the process on error
 */
static app_type_t verify_app_type(const char* type, const char* path)
{
	SECURE_C_LOGD("Entering function: %s. Params: type=%s, path=%s",
				__func__, type, path);

	/* TODO: this should actually be treated as error, but until the old
	 * set_privilege API is removed, it must be ignored */
        /* And it will be removed very soon */
	if (path == NULL || type == NULL) {
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
		if (!strcmp(type, "osp") || !strcmp(type, "tpk")) {
			C_LOGD("PKG_TYPE_OSP");
			return PERM_APP_TYPE_OSP; /* good */
		} else if (!strcmp(type, "osp_partner")) {
			C_LOGD("PKG_TYPE_OSP_PARTNER");
			return PERM_APP_TYPE_OSP_PARTNER; /* good */
		} else if (!strcmp(type, "osp_platform")) {
			C_LOGD("PKG_TYPE_OSP_PLATFORM");
			return PERM_APP_TYPE_OSP_PLATFORM; /* good */
		} else if (!strcmp(type, "efl") || !strcmp(type, "rpm")) {
			C_LOGD("PKG_TYPE_EFL");
			return PERM_APP_TYPE_EFL; /* good */
		} else if (!strcmp(type, "efl_partner") || !strcmp(type, "rpm")) {
			C_LOGD("PKG_TYPE_EFL_PARTNER");
			return PERM_APP_TYPE_EFL_PARTNER; /* good */
		} else if (!strcmp(type, "efl_platform") || !strcmp(type, "rpm")) {
			C_LOGD("PKG_TYPE_EFL_PLATFORM");
			return PERM_APP_TYPE_EFL_PLATFORM; /* good */
		}
	}

	/* bad */
	C_LOGE("EXIT_FAILURE, app_type = \"%s\" unrecognized", type);
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

const char* app_exceptions[] = {
		"org.tizen.pwlock",
		"org.tizen.phone"
};

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

static bool is_app_exception(const char* name) {
	unsigned i;
	for(i = 0; i < (sizeof app_exceptions / sizeof *app_exceptions); ++i) {
		if (strcmp(name, app_exceptions[i]) == 0) {
			return true;
		}
	}
	return false;
}
#endif //SECCOMP_ENABLED

static int perm_app_set_privilege_internal(const char* name, const char* type,
		const char* path, bool is_debug)
{
	SECURE_C_LOGD("Entering function: %s. Params: name=%s, type=%s, path=%s is_debug=%d",
				__func__, name, type, path, is_debug);

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

		ret = set_smack_for_self(smack_label); // does nothing when there is no smack
		if (ret != PC_OPERATION_SUCCESS)
			return ret;
	}

	ret = set_dac(name);
	if (ret != PC_OPERATION_SUCCESS)
		return ret;

#ifdef SECCOMP_ENABLED
	if(!is_debug && !is_app_exception(name)) {
		SECURE_C_LOGD("Enabling seccomp for %s", name);
		ret = apply_seccomp_filter();
	}
#else
	(void) is_debug;
#endif
	return ret;
}

API int perm_app_set_privilege(const char* name, const char* type, const char* path)
{
	SECURE_C_LOGD("Entering function: %s. Params: name=%s, type=%s, path=%s",
					__func__, name, type, path);
	return perm_app_set_privilege_internal(name, type, path, false);
}

API int perm_app_set_privilege_debug(const char* name, const char* type, const char* path)
{
	SECURE_C_LOGD("Entering function: %s. Params: name=%s, type=%s, path=%s",
				__func__, name, type, path);

	return perm_app_set_privilege_internal(name, type, path, true);
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

API int perm_app_setup_permissions(const char* pkg_id, app_type_t app_type,
				   const char** perm_list)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d",
				__func__, pkg_id, app_type);
	return perm_app_enable_permissions(pkg_id, app_type, perm_list, true);
}

API int perm_app_enable_permissions(const char* pkg_id, app_type_t app_type,
				    const char** perm_list, bool persistent)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d, persistent=%d",
				__func__, pkg_id, app_type, persistent);

	if (perm_list == NULL) {
		C_LOGE("Invalid perm_list (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	const char **tmp = perm_list;
	while (*tmp != NULL) {
		C_LOGD("\tpermission: %s\n", *tmp);
		tmp++;
	}

	if (app_type_group_name(app_type) == NULL) {
		C_LOGE("Unknown app type.");
		return PC_ERR_INVALID_PARAM;
	}

	return CALL_SS(security_server_perm_app_enable_permissions, g_transaction, pkg_id, app_type, perm_list,
			persistent);
}

API int perm_app_disable_permissions(const char* pkg_id, app_type_t app_type, const char** perm_list)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d",
				__func__, pkg_id, app_type);

	if (perm_list == NULL) {
		C_LOGE("Invalid perm_list (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	if (app_type_group_name(app_type) == NULL) {
		C_LOGE("Unknown app type.");
		return PC_ERR_INVALID_PARAM;
	}

	return CALL_SS(security_server_perm_app_disable_permissions, g_transaction, pkg_id, app_type, perm_list);
}

API int perm_app_revoke_permissions(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s", __func__, pkg_id);

	return CALL_SS(security_server_perm_app_revoke_permissions, g_transaction, pkg_id);
}

API int perm_app_reset_permissions(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s",
				__func__, pkg_id);

	return CALL_SS(security_server_perm_app_reset_permissions, g_transaction, pkg_id);
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

	if (permission_name == NULL) {
		C_LOGE("Invalid param permission_name (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	if (is_enabled == NULL) {
		C_LOGE("Invalid param is_enabled (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	return CALL_SS(security_server_perm_app_has_permission, g_transaction, pkg_id, app_type, permission_name,
			is_enabled);
}

API int perm_app_get_permissions(const char *pkg_id, app_type_t app_type, char ***ppp_perm_list)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d", __func__, pkg_id,
		      app_type);

	const char *app_group = app_type_group_name(app_type);

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

	return CALL_SS(security_server_perm_app_get_permissions, g_transaction, pkg_id, app_type, ppp_perm_list);
}

API int perm_get_permissions(char ***ppp_permissions, app_type_t app_type)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d",
		      __func__, app_type);

	if(ppp_permissions == NULL) {
		C_LOGE("Invalid ppp_permissions (NULL).");
		return PC_ERR_INVALID_PARAM;
	}
	// Set the given pointer to NULL in case of future failure
	*ppp_permissions = NULL;

	const char *s_permission_type_name = app_type_group_name(app_type);

	if(s_permission_type_name == NULL) {
		C_LOGE("Unknown param app type.");
		return PC_ERR_INVALID_PARAM;
	}

	return CALL_SS(security_server_perm_get_permissions, g_transaction, ppp_permissions, app_type);
}

API int perm_get_apps_with_permission(perm_app_status_t **pp_apps,
				      size_t *pi_apps_number,
				      app_type_t app_type,
				      const char *s_permission_name)
{
	SECURE_C_LOGD("Entering function: %s. Params: \
		       app_type=%d, s_permission_name=%s",
		       __func__, app_type, s_permission_name);

	if(pp_apps == NULL) {
		C_LOGE("Invalid pp_apps (NULL).");
		return PC_ERR_INVALID_PARAM;
	}
	// Set the given pointer to NULL in case of future failure
	*pp_apps = NULL;

	if(pi_apps_number == NULL) {
		C_LOGE("Invalid pi_apps_number (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	if(s_permission_name == NULL) {
		C_LOGE("Invalid s_permission_name (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	const char *s_permission_type_name = app_type_group_name(app_type);

	if(s_permission_type_name == NULL) {
		C_LOGE("Unknown param app type.");
		return PC_ERR_INVALID_PARAM;
	}

	return CALL_SS(security_server_perm_get_apps_with_permission, g_transaction, pp_apps, pi_apps_number,
			app_type, s_permission_name);
}

API void perm_free_apps_list(perm_app_status_t *pp_apps,
			     size_t i_apps_number)
{
	SECURE_C_LOGD("Entering function: %s. Params: i_apps_number=%d",
		      __func__, i_apps_number);

	security_server_perm_free_apps_list(pp_apps, i_apps_number);
}

static int perm_app_setup_path_internal(const char* pkg_id, const char* path, app_path_type_t app_path_type, va_list ap)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, path=%s, app_path_type=%d",
				__func__, pkg_id, path, app_path_type);

	if(path == NULL) {
		C_LOGE("Invalid argument path.");
		return PC_ERR_INVALID_PARAM;
	}

	switch (app_path_type) {
	case APP_PATH_PRIVATE:
	case APP_PATH_GROUP:
	case APP_PATH_PUBLIC:
	case APP_PATH_SETTINGS:
	case PERM_APP_PATH_NPRUNTIME:
	case APP_PATH_ANY_LABEL:
		return CALL_SS(security_server_perm_app_setup_path_v, g_transaction, pkg_id, path, app_path_type, ap);
	default:
		C_LOGE("app_path_type is invalid.");
		return PC_ERR_INVALID_PARAM;
	}
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

	return CALL_SS(security_server_perm_app_get_paths, g_transaction, pkg_id, app_path_type, ppp_paths);
}

API int perm_app_remove_path(const char* pkg_id, const char *path)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, path=%s", __func__, pkg_id, path);

	if (path == NULL) {
		C_LOGE("Invalid param path (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	return CALL_SS(security_server_perm_app_remove_path, g_transaction, pkg_id, path);
}

API int perm_app_add_friend(const char* pkg_id1, const char* pkg_id2)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id1=%s, pkg_id2=%s",
				__func__, pkg_id1, pkg_id2);

	if ((pkg_id1 == NULL) || (pkg_id2 == NULL)) {
		C_LOGE("Invalid pkg_id - cannot be NULL");
		return PC_ERR_INVALID_PARAM;
	}

	return CALL_SS(security_server_perm_app_add_friend, g_transaction, pkg_id1, pkg_id2);
}

API int perm_app_install(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s",
				__func__, pkg_id);

	return CALL_SS(security_server_perm_app_install, g_transaction, pkg_id);
}

API int perm_app_uninstall(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s", __func__, pkg_id);

	return CALL_SS(security_server_perm_app_uninstall, g_transaction, pkg_id);
}

/**
 * This function uses deprecated arguments
 */
API int perm_add_api_feature(app_type_t app_type,
			     const char* api_feature_name,
			     const char** smack_rules,
			     const gid_t* list_of_db_gids,
			     size_t list_size) {
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d, api_feature_name=%s",
				__func__, app_type, api_feature_name);

	// DAC files are not supported anymore!
	if (list_of_db_gids || list_size != 0) {
		C_LOGE("Parameters list_of_db_gids and list_size are deprecated and should not be used.");
		return PC_ERR_INVALID_PARAM;
	}

	return perm_define_permission(app_type, api_feature_name, smack_rules);
}

API int perm_define_permission(app_type_t app_type,
			       const char* api_feature_name,
			       const char** smack_rules) {
	const char *s_tizen_ver = get_current_tizen_ver();
	return perm_define_permission_5(app_type, api_feature_name, s_tizen_ver, smack_rules, false);
}

API int perm_define_permission_5(app_type_t app_type,
			       const char* api_feature_name,
			       const char* tizen_version,
			       const char** smack_rules,
			       bool fast) {
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d, api_feature_name=%s, tizen_version=%s",
				__func__, app_type, api_feature_name, tizen_version);

	int ret = PC_OPERATION_SUCCESS;
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

	return CALL_SS(security_server_perm_define_permission, g_transaction, app_type, api_feature_name,
			tizen_version, smack_rules, fast);
}

API int perm_define_permission_for_tizen_version(app_type_t app_type,
                               const char* api_feature_name,
                               const char* tizen_version,
                               const char** smack_rules) {
       return perm_define_permission_5(app_type, api_feature_name, tizen_version, smack_rules, false);
}

API int perm_add_additional_rules(const char** smack_rules){
	SECURE_C_LOGD("Entering function: %s.", __func__);
	if (!smack_rules){
		C_LOGE("smack_rules is NULL");
		return PC_ERR_INVALID_PARAM;
	}

	return CALL_SS(security_server_perm_add_additional_rules, g_transaction, smack_rules);
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

API int perm_app_set_privilege_version(const char* const s_app_label_name,
		const char * const s_version)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);
	if (s_app_label_name == NULL)
	{
		C_LOGE("Error invalid parameter - application name cannot be null");
		return PC_ERR_INVALID_PARAM;
	};

	return CALL_SS(security_server_perm_app_set_privilege_version, g_transaction, s_app_label_name, s_version);
}

API int perm_app_get_privilege_version(const char* const s_app_label_name,
		char **p_version)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);
	if (s_app_label_name == NULL)
	{
		C_LOGE("Error invalid parameter - application name cannot be null");
		return PC_ERR_INVALID_PARAM;
	};
	if (p_version == NULL)
	{
		C_LOGE("Error invalid parameter - pointer to version cannot be null");
		return PC_ERR_INVALID_PARAM;
	};
	*p_version = NULL;

	return CALL_SS(security_server_perm_app_get_privilege_version, g_transaction, s_app_label_name, p_version);
};

int perm_db_configuration_refresh(const char *const dir, int clear_not_found_permissions)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	return CALL_SS(security_server_perm_db_configuration_refresh, dir, clear_not_found_permissions);
}

static bool check_app_type(app_type_t perm_type) {
	return (perm_type <= PERM_APP_TYPE_LAST);
}

API int perm_app_enable_blacklist_permissions(const char* const s_app_label_name,
                                              app_type_t perm_type,
                                              const char** pp_perm_list)
{
	if (!s_app_label_name || !check_app_type(perm_type) || !pp_perm_list || !(*pp_perm_list))
		return PC_ERR_INVALID_PARAM;

	return CALL_SS(security_server_perm_app_enable_blacklist_permissions, g_transaction, s_app_label_name,
			perm_type, pp_perm_list);
}

API int perm_app_disable_blacklist_permissions(const char* const s_app_label_name,
                                               app_type_t perm_type,
                                               const char** pp_perm_list)
{
	if (!s_app_label_name || !check_app_type(perm_type) || !pp_perm_list || !(*pp_perm_list))
		return PC_ERR_INVALID_PARAM;

	return CALL_SS(security_server_perm_app_disable_blacklist_permissions, g_transaction, s_app_label_name,
			perm_type, pp_perm_list);
}

API int perm_app_get_blacklist_statuses(const char* const s_app_label_name,
                                        perm_blacklist_status_t** pp_perm_list,
                                        size_t* p_perm_number)
{
	if (!s_app_label_name || !pp_perm_list || !p_perm_number)
		return PC_ERR_INVALID_PARAM;

	return CALL_SS(security_server_perm_app_get_blacklist_statuses, g_transaction, s_app_label_name,
			pp_perm_list, p_perm_number);
}

API void perm_free_blacklist_statuses(perm_blacklist_status_t* p_perm_list,
                                      size_t i_perm_number)
{
	if (!p_perm_list || i_perm_number == 0)
		return;

	security_server_perm_free_blacklist_statuses(p_perm_list, i_perm_number);
}
