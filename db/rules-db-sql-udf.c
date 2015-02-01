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
* @file        rules-db-sql-udf.c
* @author      Jan Olszak (j.olszak@samsung.com)
* @version     1.0
* @brief       This file contains implementation of a SQLite module used in rules-db.
*/

/*
 * WARNING FOR DEVELOPER:
 * Changing this file has to keep backward compatibility.
 * While you need to make a change that breaks backward compatibility,
 * you have to build all older versions of librules-db-sql-udf.so library
 * and pack them in libprivilege-control package, so that old update
 * sql scripts could use older versions of this library.
 * Alternatively if you need changes that are not backward compatible,
 * you can make a separate library built from a separate .c file.
 */

#include <sqlite3ext.h>

#define UNUSED __attribute__((unused))

// Access rights:
#define RDB_ACCESS_READ       1
#define RDB_ACCESS_WRITE      2
#define RDB_ACCESS_EXEC       4
#define RDB_ACCESS_APPEND     8
#define RDB_ACCESS_TRANSMUTE  16
#define RDB_ACCESS_LOCK       32
#define RDB_ACCESS_FULL (RDB_ACCESS_READ      |  \
			 RDB_ACCESS_WRITE     |  \
			 RDB_ACCESS_EXEC      |  \
			 RDB_ACCESS_APPEND    |  \
			 RDB_ACCESS_TRANSMUTE |  \
			 RDB_ACCESS_LOCK)


SQLITE_EXTENSION_INIT1

/**
* Convert access to a string representation.
*
* @ingroup SQLite User Defined Functions
*
*/
static void access_to_str(sqlite3_context *context,
			  int argc UNUSED,
			  sqlite3_value **argv)
{
	int access = sqlite3_value_int(argv[0]);
	int i = 0;
	char string[7];
	if (access & RDB_ACCESS_READ)
		string[i++] = 'r';
	if (access & RDB_ACCESS_WRITE)
		string[i++] = 'w';
	if (access & RDB_ACCESS_EXEC)
		string[i++] = 'x';
	if (access & RDB_ACCESS_APPEND)
		string[i++] = 'a';
	if (access & RDB_ACCESS_TRANSMUTE)
		string[i++] = 't';
	if (access & RDB_ACCESS_LOCK)
		string[i++] = 'l';
	string[i] = '\0';
	sqlite3_result_text(context, string, -1, SQLITE_TRANSIENT);
}


/**
* Convert a string to access representation.
* Takes ONE input string like "rwxat" and converts it into access representation.
* The order of rwxat letters does not matter.
*
* @ingroup SQLite User Defined Functions
*
*/
static void str_to_access(sqlite3_context *context,
			  int argc UNUSED,
			  sqlite3_value **argv)
{
	const unsigned char *string = sqlite3_value_text(argv[0]);
	int access = 0;
	int i;

	if (!string) {
		sqlite3_result_null(context);
		return;
	}

	for (i = 0; string[i] != '\0'; ++i) {
		switch (string[i]) {
		case 'R':
		case 'r': access |= RDB_ACCESS_READ; break;

		case 'W':
		case 'w': access |= RDB_ACCESS_WRITE; break;

		case 'X':
		case 'x': access |= RDB_ACCESS_EXEC; break;

		case 'A':
		case 'a': access |= RDB_ACCESS_APPEND; break;

		case 'T':
		case 't': access |= RDB_ACCESS_TRANSMUTE; break;

		case 'L':
		case 'l': access |= RDB_ACCESS_LOCK; break;

		case '-': break;

		default: // He got an unknown permission
			sqlite3_result_null(context);
			return;
		}
	}
	sqlite3_result_int(context, access);
}


/**
* An bitwise or aggregating function. We assume, that all arguments are ints.
*
* @ingroup SQLite User Defined Functions
*
* @return bitwise or of all given values.
*/
static void bitwise_or_step(sqlite3_context *context,
			    int argc UNUSED,
			    sqlite3_value **argv)
{
	int *result_buffer = (int *)sqlite3_aggregate_context(context, sizeof(int));
	*result_buffer |= sqlite3_value_int(argv[0]);
}


static void bitwise_or_final(sqlite3_context *context)
{
	int *result_buffer = (int *)sqlite3_aggregate_context(context, sizeof(int));
	sqlite3_result_int(context, *result_buffer );
}

/**
* Entry point for SQLite.
*/
__attribute__((visibility("default")))
int sqlite3_extension_init( sqlite3 *p_db,
			    char **ps_err_msg UNUSED,
			    const sqlite3_api_routines *p_api)
{
	SQLITE_EXTENSION_INIT2(p_api)
	sqlite3_create_function(p_db, "access_to_str", 1, SQLITE_ANY, 0, access_to_str, 0, 0);
	sqlite3_create_function(p_db, "str_to_access", 1, SQLITE_ANY, 0, str_to_access, 0, 0);
	sqlite3_create_function(p_db, "bitwise_or", 1, SQLITE_ANY, 0, 0,
				bitwise_or_step, bitwise_or_final);

	return 0;
}
