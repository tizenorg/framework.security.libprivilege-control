/*
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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

/**
* @file        smack_rules_buffer.c
* @author      Rafal Krypa (r.krypa@samsung.com)
* @version     1.0
* @brief       Binary file for loading smack rules using one big buffer - without fragmentation
*              To be used in the smack-rules.service
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <err.h>

size_t buf_size = 1 << 20; /* 1 MB */

int main(int argc, char *argv[])
{
	char *buf;
	char *endptr = NULL;
	size_t read_pos = 0, write_pos = 0, write_bytes = 0;
	int eof = 0;
	int ret;

	if (argc == 2) {
		unsigned long temp = strtoul(argv[1], &endptr, 10);
		if (*endptr != '\0' || (temp == ULONG_MAX && errno) || temp == 0)
			errx(EXIT_FAILURE, "Wrong buffer size argument: %s", argv[1]);
/*
 * The comparison below is not applicable on some architectures,
 * in which sizes of int and long are equal (i.e. arm)
 */
#if ULONG_MAX > UINT_MAX
		if (temp > UINT_MAX)
			errx(EXIT_FAILURE, "Buffer size cannot be bigger than: %u", UINT_MAX);
#endif
		buf_size = (unsigned int)temp;
	} else if (argc > 2) {
		errx(EXIT_FAILURE, "Too many arguments, one optional buf size arg is acceptable");
	}

	buf = malloc(buf_size);
	if (buf == NULL)
		errx(EXIT_FAILURE, "Unable to allocate %zu bytes of memory", buf_size);

	for (eof = 0; !eof; ) {
		for (; read_pos < buf_size && !eof; ) {
			ret = read(STDIN_FILENO, buf + read_pos, buf_size - read_pos);
			switch (ret) {
			case -1:
				err(EXIT_FAILURE, "Read failed");
				break;
			case  0:
				eof = 1;
				break;
			default:
				read_pos += ret;
			}
		}
		if (read_pos == 0)
			continue;

		write_bytes = read_pos;
		if (!eof)
			while (buf[write_bytes - 1] != '\n')
				if (--write_bytes == 0)
					errx(EXIT_FAILURE, "Line too long");

		for (write_pos = 0; write_pos < write_bytes; ) {
			ret = write(STDOUT_FILENO, buf + write_pos, write_bytes - write_pos);
			if (ret == -1)
				err(EXIT_FAILURE, "Write failed");
			else
				write_pos += ret;
		}

		read_pos = read_pos - write_bytes;
		if (read_pos > 0)
			memcpy(buf, buf + write_pos, read_pos);
	}

	free(buf);
	return 0;
}
