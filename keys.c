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

#include "includes.h"

/*
 * Convert 'len' bytes from 'bin' to hex
 */
static unsigned char* bin_to_hex_str(unsigned char *bin, int len)
{
	char *str = malloc(len);

	memset(str, 'Z', len);
	strcpy(str, "md5 ");

	unsigned char *pin = bin;
	const char *hex = "0123456789ABCDEF";
	char *pout = str;

	for (; pin < bin + sizeof(bin); pout += 3, pin++) {
		pout[0] = hex[(*pin >> 4) & 0xF];
		pout[1] = hex[ *pin & 0xF];
		pout[2] = ':';
	}
	pout[-1] = 0;

	printf("%s\n", str);
}

/*
 * Compute the hash of 'key' and return a fingerprint of size,
 * 'MD5_HASH_SIZE'
 */
static char* get_md5_fingerprint(char *key, int len)
{
	unsigned char *fp;

	char *ret;
	hash_state hs;
	unsigned char hash[MD5_HASH_SIZE];
	unsigned int i;
	unsigned int buflen;

	md5_init(&hs);

	/* skip the size int of the string - this is a bit messy */
	md5_process(&hs, key, len);

	md5_done(&hs, hash);

	/* "md5 hexfingerprinthere\0", each hex digit is "AB:" etc */
	buflen = 4 + 3 * MD5_HASH_SIZE;

	ret = bin_to_hex_str(hash, buflen);

	return ret;
}

/*
 * Get the fingerprint of 'key'
 */
unsigned char *ssh_key_get_fingerprint(char *key, int len, int type)
{
	return get_md5_fingerprint(key, len);
}



