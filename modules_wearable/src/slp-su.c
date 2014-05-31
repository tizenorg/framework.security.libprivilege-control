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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dlog.h>

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

// conditional log macro for dlogutil (error)
#ifdef DLOG_ERROR_ENABLED
#define C_LOGE(...) SLOGE(__VA_ARGS__)
#define SECURE_C_LOGE(...) SECURE_SLOGE(__VA_ARGS__)
#else
#define C_LOGE(...) do { } while(0)
#define SECURE_C_LOGE(...) do { } while(0)
#endif //DLOG_ERROR_ENABLED

void print_usage(void)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);
	printf("%s", "Usage: slp-su [PKG_NAME]\n\n");
	printf("%s", "Execute new shell which be belonged to user related with PKG_NAME\n\n");
}

int main(int argc, char* argv[])
{
	SECURE_C_LOGD("Entering function: %s.", __func__);
	pid_t pid = -1;
	char* buf = NULL;

	if(argc != 2)
	{
		fprintf(stderr, "%s", "[ERR] Check your argument.\n\n");
		C_LOGE("");
		print_usage();
		return 0;
	}

	pid = fork();
	switch(pid)
	{
		case 0:		// child
			{
				if(perm_app_set_privilege(argv[1], NULL, NULL) == 0)	// success
				{
					fprintf(stderr, "%s", "[LOG] Successfully executed set_privilege()\n");
					C_LOGD("[LOG] Successfully executed set_privilege()");
				}
				else
				{
					fprintf(stderr, "%s", "[ERR] Failed to execute set_privilege()\n");
					C_LOGE("[ERR] Failed to execute set_privilege()");
					exit(1);
				}

				buf = getenv("HOME");
				if(buf == NULL)	// fail
				{
					fprintf(stderr, "%s", "[ERR] Failed to execute getenv()\n");
					C_LOGE("[ERR] Failed to execute getenv()");
					exit(0);
				}
				else
				{
					fprintf(stderr, "%s: [%s]%s", "[LOG] HOME", buf, "\n");
					C_LOGD("[LOG] HOME [%s]", buf);
				}
				
				if(chdir(buf) == 0)	// success
				{
					fprintf(stderr, "%s", "[LOG] Successfully changed working directory\n");
					C_LOGD("[LOG] Successfully changed working directory");
				}
				else
				{
					fprintf(stderr, "%s", "[ERR] Failed to execute chdir()\n");
					C_LOGE("[ERR] Failed to execute chdir()");
					exit(0);
				}
				
				C_LOGD("execl \"/bin/sh\"");
				execl("/bin/sh", "/bin/sh", NULL);
				break;
			}
		case -1:	// error
			{
				fprintf(stderr, "%s", "[ERR] Failed to execute fork()\n");
				C_LOGE("[ERR] Failed to execute fork()");
				exit(1);
				break;
			}
		default:	// parent
			{
				wait((int*)0);
				fprintf(stderr, "%s", "[LOG] Parent end\n");
				C_LOGE("[LOG] Parent end");
				exit(0);
			}
	}

	return 1;
}
