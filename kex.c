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

#include "kex.h"
#include "includes.h"
#include "misc.h"
#include "random.h"
#include "ssh-packet.h"
#include "ssh-numbers.h"
#include "ssh-session.h"

int kex_status = 0;
const int DH_G_VAL = 2;

/* Forward declarations */
static void kex_negotiate(struct packet *pck);
static struct algorithm* kex_try_match(struct exchange_list_remote* rem,
	struct exchange_list_local* loc);
struct diffie_hellman* kex_dh_compute();
struct packet* kex_dh_init();
struct packet* kex_dh_reply();

/* List of supported kex algorithms */
struct exchange_list_local kex_list = {

	.algos =
	{
		{"diffie-hellman-group14-sha256", NULL},
		{"diffie-hellman-group14-sha1", NULL},
		{"diffie-hellman-group1-sha1", NULL}
	},

	.num = 3

};

/* List of supported host keys */
struct exchange_list_local host_list = {

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
struct exchange_list_local cipher_list = {

	.algos =
	{
		{"aes128-ctr", &aes_desc},
		{"aes256-ctr", NULL},
		{"twofish256-ctr", &twofish_desc},
		{"twofish128-ctr", NULL},
		{"aes128-cbc", NULL},
		{"aes256-cbc", NULL},
		{"twofish256-cbc", NULL},
		{"twofish-cbc", NULL},
		{"twofish128-cbc", NULL},
		{"3des-ctr", &des3_desc},
		{"3des-cbc", NULL},
		{"blowfish-cbc", &blowfish_desc},
		{"none", NULL},
	},

	.num = 13

};

/* List of supported hashes */
struct exchange_list_local hash_list = {

	.algos =
	{
		{"hmac-sha1", &sha1_desc},
		{"hmac-sha2-256", &sha256_desc},
		{"hmac-sha2-512", &sha512_desc},
		{"hmac-md5", &md5_desc},
		{"none", NULL},
	},

	.num = 5

};

/* List of supported compression algortihms */
struct exchange_list_local compress_list = {

	.algos =
	{
		{"zlib@openssh.com", NULL},
		{"zlib", NULL},
		{"none", NULL},
	},

	.num = 3

};

/* List of supported language */
struct exchange_list_local lang_list = {

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

	struct packet *kex_dh_pck;
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

	if(session.write_packet(pck) == pck->len)
		fprintf(stderr, "All bytes were transmitted\n");

	struct packet *kex_resp;

	if(session.state == HAVE_KEX_INIT)
		kex_resp = session.packet_part;
	else
		kex_resp = session.read_packet();


	kex_resp->rd_pos += 5;

	if(kex_resp->get_byte(kex_resp) == SSH_MSG_KEXINIT)
		kex_negotiate(kex_resp);
	else
		macssh_err("Expected remote KEX_INIT. Found something else", -1);

	if(kex_status & KEX_FAIL)
		macssh_err("KEX failed", -1);
	
	if(session.state == HAVE_KEX_INIT)
		session.packet_part = NULL;
	
	free(kex_resp);

	/* Send our part of the diffie-hellman kex */
	kex_dh_pck = kex_dh_init();
	session.write_packet(kex_dh_pck);

	struct packet *kex_resp_2;
	kex_resp_2 = session.read_packet();
	macssh_print_array(kex_resp_2->data, kex_resp_2->len);
}

/* Initialize the diffie-hellman part of the key-exchange.
 * This will be done initially after connection has been,
 * established, but can also occur anytime during a session. */
struct packet* kex_dh_init()
{
	struct packet *pck = packet_new(1024);

	pck->len = 5; //Make room for size and pad size
	char cookie[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	char pads[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	pck->put_byte(pck, SSH_MSG_KEXDH_INIT);
	pck->put_bytes(pck, cookie, 16);

	struct diffie_hellman *dh;
	dh = kex_dh_compute();

	pck->put_mpint(pck, &dh->pub_key);

	//pck->put_byte(pck, 1); //No guess
	//pck->put_int(pck, 0); //Reserved

	/* Stamp with metadata */
	put_stamp(pck);

	return pck;
}

/* Server response to a client kex_dh_init */
struct packet* kex_dh_reply()
{

}

/* Negotiate algorithms by mathing remote and local versions */
static void kex_negotiate(struct packet *pck)
{
	/* Skip the 16 byte cookie */
	pck->rd_pos += 16;

	session.crypto->keys.kex =
		kex_try_match(pck->get_exch_list(pck), &kex_list);

	session.crypto->keys.host =
		kex_try_match(pck->get_exch_list(pck), &host_list);

	session.crypto->keys.ciper =
		kex_try_match(pck->get_exch_list(pck), &cipher_list);

	session.crypto->keys.hash =
		kex_try_match(pck->get_exch_list(pck), &hash_list);

	session.crypto->keys.compress =
		kex_try_match(pck->get_exch_list(pck), &compress_list);

	session.crypto->keys.lang =
		kex_try_match(pck->get_exch_list(pck), &lang_list);
}

/* Try to match remote and local version of single algorithm */
static struct algorithm* kex_try_match(struct exchange_list_remote *rem,
	struct exchange_list_local *loc)
{
	int x, y;
	for(x = 0; x < loc->num; x++) {
		for(y = 0; y < rem->end; y++) {
			if(strcmp(loc->algos[x].name, rem->algos[y]->name) == 0)
				return &loc->algos[x];
		}
	}

	kex_status |= KEX_FAIL;
}

/* Send a KEX guess */
void kex_guess()
{

}

/* Diffie-Hellman computation */
struct diffie_hellman* kex_dh_compute()
{
	struct diffie_hellman *dh_vals = NULL;

	mp_int dh_p = {0, 0, 0, NULL};
	mp_int dh_q = {0, 0, 0, NULL};
	mp_int dh_g = {0, 0, 0, NULL};

	/* Initialize dh struct and mp_int's */
	dh_vals = malloc(sizeof(struct diffie_hellman));
	mp_init_multi(&dh_vals->pub_key, &dh_vals->priv_key, &dh_g, &dh_p, &dh_q, NULL);

	/* read the prime and generator*/
	/* Where should I read the prime from ? */
	unsigned char dh_p_bytes[26] = {255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};
	unsigned int dh_p_len = 26;
	mp_read_unsigned_bin(&dh_p, dh_p_bytes, dh_p_len);

	/* Set the dh g value */
	if(mp_set_int(&dh_g, DH_G_VAL) != MP_OKAY)
		macssh_err("Diffie-Hellman error", errno);

	/* calculate q = (p-1)/2 */
	/* dh_priv is just a temp var here */
	if(mp_sub_d(&dh_p, 1, &dh_vals->priv_key) != MP_OKAY)
		macssh_err("Diffie-Hellman error", errno);

	if(mp_div_2(&dh_vals->priv_key, &dh_q) != MP_OKAY)
		macssh_err("Diffie-Hellman error", errno);

	/* Generate a private portion 0 < dh_priv < dh_q */
	gen_random_mpint(&dh_q, &dh_vals->priv_key);

	/* f = g^y mod p 
	 * public key portion */
	if(mp_exptmod(&dh_g, &dh_vals->priv_key, &dh_p, &dh_vals->pub_key) != MP_OKAY)
		macssh_err("Diffie-Hellman error", errno);

	mp_clear_multi(&dh_g, &dh_p, &dh_q, NULL);

	return dh_vals;
}