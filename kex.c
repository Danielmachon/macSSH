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

/* List of supported language */
struct exchange_list lang_list = {

	.algos =
	{
		{"", NULL},
	},

	.num = 1
};

void kex_init()
{
	/*	
	byte         SSH_MSG_KEXINIT
	byte[16]     cookie (random bytes)
	name-list    kex_algorithms
	name-list    server_host_key_algorithms
	name-list    encryption_algorithms_client_to_server
	name-list    encryption_algorithms_server_to_client
	name-list    mac_algorithms_client_to_server
	name-list    mac_algorithms_server_to_client
	name-list    compression_algorithms_client_to_server
	name-list    compression_algorithms_server_to_client
	name-list    languages_client_to_server
	name-list    languages_server_to_client
	boolean      first_kex_packet_follows
	uint32       0 (reserved for future extension) */

	struct packet *pck = packet_new(1024);
	pck->len = 5; //Make room for size and pad size
	char cookie[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	char pads[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	pck->put_byte(pck, SSH_MSG_KEXINIT);
	pck->put_bytes(pck, cookie, 16);
	pck->put_exch_list(pck, &kex_list);
	pck->put_exch_list(pck, &host_list);
	pck->put_exch_list(pck, &cipher_list);
	pck->put_exch_list(pck, &cipher_list);
	pck->put_exch_list(pck, &hash_list);
	pck->put_exch_list(pck, &hash_list);
	pck->put_exch_list(pck, &compress_list);
	pck->put_exch_list(pck, &compress_list);

	/* No preferred languages both ways */
	pck->put_exch_list(pck, &lang_list);
	pck->put_exch_list(pck, &lang_list);

	pck->put_byte(pck, 1); //No guess
	pck->put_int(pck, 0); //Reserved
	
	/* Stamp with metadata */
	put_stamp(pck);
	
	//ssh_print_array(pck->data, pck->len);
	//ssh_print_embedded_string(pck->data, pck->len);
	
	if (session.write_packet(pck) == pck->len)
		fprintf(stderr, "All bytes were transmitted\n");

	struct packet *kex_resp;
	kex_resp = session.read_packet();
	kex_resp->rd_pos = 5;
	
	if(kex_resp->get_int(kex_resp) == SSH_MSG_KEXINIT)
		kex_negotiate(kex_resp);
	else
		ssh_err("Expected remote KEX_INIT. Found something else\n", -1);
	
	struct packet *kex_resp_2;
	kex_resp_2 = session.read_packet();

	//ssh_print_embedded_string(kex_resp_2->data, kex_resp_2->len);


}

/* Negotiate algorithms by mathing remote and local versions */
static void kex_negotiate(struct packet *pck)
{
	/* Skip the 16 byte cookie */
	pck->rd_pos += 16;
	
	kex_try_match(pck->get_exch_list(pck), kex_list);
	kex_try_match(pck->get_exch_list(pck), host_list);
	kex_try_match(pck->get_exch_list(pck), cipher_list);
	kex_try_match(pck->get_exch_list(pck), hash_list);
	kex_try_match(pck->get_exch_list(pck), compress_list);
	kex_try_match(pck->get_exch_list(pck), lang_list);
}

/* Try to match remote and local version of single algorithm */
static void kex_try_match(struct exchange_list rem, struct exchange_list loc)
{
	
}

/* Send a KEX guess */
void kex_guess()
{

}