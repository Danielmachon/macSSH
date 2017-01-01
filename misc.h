/*
    This file is part of macSSH
    
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

#ifndef MISC_H
#define MISC_H

#define FREE_SAFE(p) do { void ** __p = (void **) &(p);	if(*__p) free(*(__p)); \
	*(__p) = NULL; } while (0)

/* Print functions */
void macssh_print(const char *msg);
void macssh_print_file(FILE *file, const char *msg);
void macssh_print_array(void *data, int len);
void macssh_print_embedded_string(void *data, int len);

void macssh_debug(const char *msg);
void macssh_err(const char *msg, int err);
void macssh_exit(const char *msg, int err);

#endif /* MISC_H */

