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

#ifndef _ACCESS_DB_H_
#define _ACCESS_DB_H_


/**
 * This function adds an app to a supplementary group identified by gid
 */
int add_app_gid(const char *app_id, unsigned gid);


/**
 * This function returns (in params) supplementary group ids that an app
 * has been assigned to.
 * gids should be freed by caller.
 */
int get_app_gids(const char *app_id, unsigned **gids, int *len);

#endif // _ACCESS_DB_H_
