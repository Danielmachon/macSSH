/*
    This file is part of SSH
    
    Copyright 2016 Daniel Machon

    SSH program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "misc.h"


void ssh_print(const char *msg)
{
	printf("%s\n", msg);
}

void ssh_print_file(FILE *file, const char *msg)
{
	fprintf(file, "%s\n", msg);
}

void ssh_print_array(void *data, int len)
{
	int x;
	for(x = 0; x < len; x++)  {
		fprintf(stderr, "[%u]", ((unsigned char *)data)[x]);
		if(x % 15 == 0)
			fprintf(stderr, "\n");
	}
}

void ssh_debug(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
}

void ssh_err(const char *msg, int err)
{
	fprintf(stderr, "%s: %s", msg, strerror(err));
}

void ssh_exit(const char *msg, int err)
{
	ssh_err(msg, err);
	exit(EXIT_FAILURE);
}
