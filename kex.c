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
#include "kex.h"

/* List of supported kex algorithms */
struct exchange_list kex_list = {

	.algos =
	{
		{"diffie-hellman-group14-sha256", NULL},
		{"diffie-hellman-group14-sha1", NULL},
		{"diffie-hellman-group1-sha1", NULL}
	},

	.num = 3

};

/* List of supported host keys */
struct exchange_list host_list = {

	.algos =
	{
		{"ssh-rsa", NULL},
		{"ssh-dss", NULL},
	},

	.num = 2

};

/* List of supported ciphers.
 * The first cipher on this list, that is also supported,
 * by the server, will be chosen */
struct exchange_list cipher_list = {

	.algos =
	{
		{"aes128-ctr", NULL},
		{"aes256-ctr", NULL},
		{"twofish256-ctr", NULL},
		{"twofish128-ctr", NULL},
		{"aes128-cbc", NULL},
		{"aes256-cbc", NULL},
		{"twofish256-cbc", NULL},
		{"twofish-cbc", NULL},
		{"twofish128-cbc", 0NULL},
		{"3des-ctr", NULL},
		{"3des-cbc", NULL},
		{"blowfish-cbc", NULL},
		{"none", NULL},
		{NULL, NULL}
	},

	.num = 14

};

/* List of supported hashes */
struct exchange_list hash_list = {

	.algos =
	{
		{"hmac-sha1-96", NULL},
		{"hmac-sha1", NULL},
		{"hmac-sha2-256", NULL},
		{"hmac-sha2-512", NULL},
		{"hmac-md5", NULL},
		{"none",},
		{NULL, NULL}
	},

	.num = 7

};

/* List of supported compression algortihms */
struct exchange_list compress_list = {

	.algos =
	{
		{"zlib@openssh.com", NULL},
		{"zlib", NULL},
		{"none", NULL},
		{NULL, NULL}
	},

	.num = 4

};

void kex_init()
{

}

void kex_guess()
{

}