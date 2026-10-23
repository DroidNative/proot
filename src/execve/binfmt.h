/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

#ifndef BINFMT_H
#define BINFMT_H

#include <linux/limits.h>
#include "tracee/tracee.h"

extern int binfmt_lookup(Tracee *tracee, const char *host_path, const char *user_path,
			char interp_user[PATH_MAX], char interp_host[PATH_MAX]);

#endif /* BINFMT_H */
