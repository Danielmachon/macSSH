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

#ifndef SSH_OPTIONS_H
#define SSH_OPTIONS_H

#define MACSSH_SUCCESS	0
#define MACSSH_FAILURE	-1

/*
 * Move this elsewhere !!!
 */
#define MACSSH_3DES
#define SHA1_HASH_SIZE		20
#define MD5_HASH_SIZE		16
#define MAX_HASH_SIZE		64 /* sha512 */

#define MACSSH_URANDOM_DEV	"/dev/urandom"
#define MACSSH_CONF_DIR		"/etc/macssh/"

struct options {
	
	/* SSH options */
	int server_port;
	char server_addr[32];
	
	/* Internal options */
	int verbose;
	int more_verbose;
	int debug;
	
} argv_options;

#endif /* SSH_OPTIONS_H */

