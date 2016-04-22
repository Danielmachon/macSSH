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
#include "ssh-options.h"

void macssh_exit(const char *msg, int err)
{
	
}

void macssh_err(const char *msg, int err)
{
	
}

void macssh_debug(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
}

void macssh_print(const char *msg)
{
	printf("%s\n", msg);
}

void macssh_print_file(FILE *file, const char *msg)
{
	fprintf(file, "%s\n", msg);
}

void macssh_print_array(void *data, int len)
{
	int x;
	for(x = 0; x < len; x++)  {
		fprintf(stderr, "[%u]", ((unsigned char *)data)[x]);
		if(x % 15 == 0)
			fprintf(stderr, "\n");
	}
}

/* Attempt to print any embedded string in byte array */
void macssh_print_embedded_string(void *data, int len)
{
	unsigned char *ptr = (unsigned char * )data;
	
	int x;
	int start = 0;
	int end = 0;
	for(x = 0; x < len; x++) {
		if(ptr[x] >= ' ') {
			/* Printable. Mark start. */
			if(!start)
				start = x;
		}
		else {
			/* Zero termination. Mark end if previous byte
			 * was a printable */
			if(start && ptr[x] == '\0') 
				end = x;
			/* Non-printable and not zero. 
			 * This is definitely not a string */
			else
				start = 0;
		}
		
		/* Check if we have something to print */
		if(start && end) {
			fprintf(stderr, "This looks stringy: %s\n", 
				ptr + start, end - start);
			start = end = 0;
		}
	}
}
