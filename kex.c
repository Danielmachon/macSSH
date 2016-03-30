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

#include <unistd.h>

#include "includes.h"
#include "kex.h"
#include "ssh-packet.h"
#include "ssh-numbers.h"
#include "misc.h"
#include "ssh-session.h"

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
		{"twofish128-cbc", NULL},
		{"3des-ctr", NULL},
		{"3des-cbc", NULL},
		{"blowfish-cbc", NULL},
		{"none", NULL},
	},

	.num = 13

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
	},

	.num = 6

};

/* List of supported compression algortihms */
struct exchange_list compress_list = {

	.algos =
	{
		{"zlib@openssh.com", NULL},
		{"zlib", NULL},
		{"none", NULL},
	},

	.num = 3

};

void kex_init()
{
	struct packet *pck = packet_new(1024);
	char cookie[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	
	pck->put_byte(pck, SSH_MSG_KEXINIT);
	pck->put_bytes(pck, cookie, 16);
	pck->put_exch_list(pck, &kex_list);
	pck->put_exch_list(pck, &cipher_list);
	pck->put_exch_list(pck, &hash_list);
	pck->put_exch_list(pck, &host_list);
	pck->put_exch_list(pck, &compress_list);
	
	/* No preferred languages */
	pck->put_str(pck, "");
	
	pck->put_byte(pck, 0); //No guess
	pck->put_int(pck, 0); //Reserved
	
	//ssh_print_array(pck->data, pck->len);
	
	if(session.write_packet(pck) == pck->len)
		fprintf(stderr, "All bytes were transmitted\n");
	
	struct packet *kex_resp = packet_new(4096);
	kex_resp = session.read_packet();
	
	ssh_print_array(kex_resp->data, kex_resp->len);
	fprintf(stderr, "%s\n", ((unsigned char *)kex_resp->data+25));
	
}

void kex_guess()
{

}