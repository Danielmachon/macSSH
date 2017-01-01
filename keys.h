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

#ifndef KEYS_H
#define KEYS_H

#include "tommath.h"

#define MIN_RSA_KEYLEN		512

#define MIN_DSS_KEYLEN		512

#define LINE_MAX_LEN		72 * 8

#define PUB_KEY_BEGIN		"---- BEGIN SSH2 PUBLIC KEY ----"
#define PUB_KEY_END		"---- END SSH2 PUBLIC KEY ----"
#define HOSTKEY_HEADER_SUBJECT	"Subject"
#define HOSTKEY_HEADER_COMMENT	"Comment"
#define HOSTKEY_HEADER_PRIVATE	"x-"

struct ssh_rsa_key {
	char *blob;
	mp_int *e;
	mp_int *n;
};

struct ssh_dss_key {
	char *blob;
	mp_int *p;
	mp_int *q;
	mp_int *g;
	mp_int *y;
};

char *ssh_key_get_fingerprint(char *key, int len, int type);
int ssh_generate_rsa_key();
int ssh_generate_dss_key();

#endif /* KEYS_H */

