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

/**
* @file        api_feature_loader.c
* @author      Jan Olszak (j.olszak@samsung.com)
* @version     1.0
* @brief       Binary file for loading predefined API features to the database.
*/

#define _GNU_SOURCE
#include <getopt.h>             // For getopt
#include <privilege-control.h>  // For app_type
#include <stdio.h>              // For file manipulation
#include <stdlib.h>             // For malloc and free
#include <sys/smack.h>          // For SMACK_LABEL_LEN
#include <unistd.h>             // For basename
#include <stdio.h>              // For sscanf
#include <common.h>


#define API_FEATURE_LOADER_VERSION "1.0"
#define API_FEATURES_DIR "/usr/share/privilege-control/"
#define API_FEATURE_LOADER_LOG(format, ...) if(i_verbose_flag__) printf(format, ##__VA_ARGS__)

static int i_verbose_flag__ = 0;
static int i_clear_permissions_flag__ = 0;

int main(int argc, char *argv[])
{
	int c;
	int i_option_index = 0;

	bool b_load_from_file = false;
	const char *s_file_name = NULL;
	const char *s_tizen_version = NULL;

	bool b_load_from_dir = false;
	const char *s_dir_name = NULL;

	bool b_load_additional_rules = false;
	const char *s_additional_rules_file_name = NULL;

	bool b_verify_rules = false;
	const char *s_rules_dir = NULL;

	static struct option long_options[] = {
		{"verbose", no_argument,       &i_verbose_flag__,  1},
		{"clear-permissions", no_argument, &i_clear_permissions_flag__, true},
		{"file",    required_argument, 0, 'f'},
		{"dir",     required_argument, 0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{"version", no_argument,       0, 'v'},
		{"rules",   required_argument, 0, 'r'},
		{"tizen-version", required_argument, 0, 't'},
		{"verify-rules", required_argument, 0, 'w'},
		{0, 0, 0, 0}
	};

	while((c = getopt_long(argc, argv,
			       "cf:d:hvrt:w:",
			       long_options,
			       &i_option_index)) != -1) {
		switch(c) {
		case 0:
			// If this option set a flag, do nothing.
			break;
		case '?':
			// No such command.
			// getopt_long already printed an error message.
			return 0;
		case 'f':
			b_load_from_file = true;
			s_file_name = optarg;
			break;
		case 't':
			s_tizen_version = optarg;
			break;

		case 'd':
			b_load_from_dir = true;
			s_dir_name = optarg;
			break;

		case 'r':
			b_load_additional_rules = true;
			s_additional_rules_file_name = optarg;
			break;

		case 'c':
			i_clear_permissions_flag__ = true;
			break;

                case 'w':
                        b_verify_rules = true;
                        s_rules_dir = optarg;
                        break;

		case 'h':
			printf("Api feature loader v." API_FEATURE_LOADER_VERSION "\n\n"
                               "If called without arguments, looks for privileges in subdirectories of /usr/share/privilege-control\n"
                               "and treats subdirectories names as Tizen versions to which load .smack files.\n\n");
			printf("    Options:\n");
			printf("        -d,--dir=path        Load privileges from specified directory.\n"
                               "                             This option does not look for recursive directories.\n"
                               "                             To specify Tizen version for which privileges should be loaded, use -t option.\n"
                               "                             Default tizen version is \"" TIZEN_VERSION "\".\n");
			printf("        -f,--file=file_name  Load api-feature from the file.\n"
                               "                             To secify tizen version for privilege loaded, use -t option.\n"
                               "                             Default tizen version is \"" TIZEN_VERSION "\".\n");
			printf("        -h,--help            Print this help.\n");
			printf("        -r,--rules           Load additional rules from the file.\n");
			printf("        --verbose            Verbose output.\n");
			printf("        -v,--version         Show applcation version.\n");
			printf("        -t,--tizen-version   Apply privileges from files and directories as if\n"
			       "                             they were for tizen version given as parameter.\n"
			       "                             default tizen version is \"" TIZEN_VERSION "\".\n");
			printf("        -c,--clear-permissions Clear old permissions before loading new ones\n"
			       "                               (clear all permissions rules), this option\n"
			       "                               can be combined only with --verbose, other\n"
			       "                               combinations discard its effects.\n");
			printf("        -w,--verify-rules=path It does not load any rules. Only validate rules in .smack files.\n");

			return 0;

		case 'v':
			printf("Api feature loader v." API_FEATURE_LOADER_VERSION "\n");
			return 0;

		default:
			break;
		}
	}

	// Print unknown remaining command line arguments
	if(optind < argc) {
		printf("Unknown options: ");
		while(optind < argc)
			printf("%s ", argv[optind++]);
		putchar('\n');
		return 0;
	}

	// Run task
        if(b_verify_rules) {
                return validate_rules_for_all_versions(s_rules_dir);
        }

	if(b_load_additional_rules) {
		API_FEATURE_LOADER_LOG("Loading additional rules from file '%s'\n",s_additional_rules_file_name);
		load_additional_rules(s_additional_rules_file_name);
		API_FEATURE_LOADER_LOG("Done.\n");
	}
	if(b_load_from_dir) {
		API_FEATURE_LOADER_LOG("Loading rules from directory '%s' for tizen version %s.\n",
				s_dir_name, (s_tizen_version ? s_tizen_version : "(null)"));
		load_from_dir(s_dir_name, s_tizen_version, false);
		API_FEATURE_LOADER_LOG("Done.\n");
	}
	if(b_load_from_file) {
		API_FEATURE_LOADER_LOG("Loading rules from directory '%s' for tizen version %s.\n",
				s_dir_name, (s_tizen_version ? s_tizen_version : "(null)"));
		load_from_file(s_file_name, s_tizen_version, false);
		API_FEATURE_LOADER_LOG("Done.\n");
	}
	if(!b_load_additional_rules &&
		!b_load_from_dir &&
		!b_load_from_file) {
		API_FEATURE_LOADER_LOG("Loading permissions for all versions from '%s'\n", API_FEATURES_DIR);
		perm_db_configuration_refresh(API_FEATURES_DIR, i_clear_permissions_flag__);
		API_FEATURE_LOADER_LOG("Done.\n");
	}

	return 0;
}
