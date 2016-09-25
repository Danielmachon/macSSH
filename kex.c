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
#include "dbg.h"
#include "keys.h"

int kex_status = 0;

/* Used to force mp_ints to be initialised */
#define DEF_MP_INT(X) mp_int X = {0, 0, 0, NULL}

/* Forward declarations */
static void kex_negotiate(struct packet *pck);
static struct algorithm* kex_try_match(struct exchange_list_remote* rem,
        struct exchange_list_local* loc);
struct diffie_hellman* kex_dh_compute();
struct packet* kex_dh_init();
struct packet* kex_dh_reply();

/* Common generator for diffie-hellman-group14 */
const int DH_G_VAL = 2;

/* diffie-hellman-group14-sha1 value for p */
const unsigned char dh_p_14[256] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
        0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
        0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
        0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
        0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
        0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
        0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
        0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
        0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
        0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF
};

/* List of supported kex algorithms */
struct exchange_list_local kex_list = {

        .algos =
        {
                {"diffie-hellman-group14-sha1", NULL},
                {"diffie-hellman-group1-sha1", NULL},
                {"diffie-hellman-group14-sha256", NULL}
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
                {"none", NULL},
                {"zlib@openssh.com", NULL},
        },

        .num = 2

};

/* List of supported languages */
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
        char *cookie = (char *) get_random_bytes(16);

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
        pck->put_int(pck, 0); //Empty language list
        pck->put_int(pck, 0); //Empty language list

        pck->put_byte(pck, 0); //No guess
        pck->put_int(pck, 0); //Reserved

        /* Stamp with metadata */
        put_stamp(pck);

        struct packet *kex_resp;

        if (session.state == HAVE_KEX_INIT)
                kex_resp = session.packet_part;
        else
                kex_resp = session.read_packet();

        if (kex_resp->get_byte(kex_resp) == SSH_MSG_KEXINIT)
                kex_negotiate(kex_resp);
        else
                macssh_err("Expected remote KEX_INIT. Found something else", -1);

        if (session.state == HAVE_KEX_INIT)
                session.packet_part = NULL;

        free(kex_resp);

        /* Send our KEX packet */
        macssh_print_array(pck->data, pck->len);
        macssh_print_embedded_string(pck->data, pck->len);

        if (session.write_packet(pck) == pck->len)
                fprintf(stderr, "All bytes were transmitted\n");

        /* Send our part of the diffie-hellman kex */
        kex_dh_pck = kex_dh_init();

        log_info("Sending KEX_DH_INIT packet");

        macssh_print_array(kex_dh_pck->data, kex_dh_pck->len);

        session.write_packet(kex_dh_pck);

        struct packet *dh_pck = packet_new(1024);

        log_info("Reading KEX_DH_REPLY packet");

        kex_dh_reply();


}

/* Initialize the diffie-hellman part of the key-exchange.
 * This will be done initially after connection has been,
 * established, but can also occur anytime during a session. */
struct packet* kex_dh_init()
{
        struct packet *pck = packet_new(1024);

        pck->len = 5; //Make room for size and pad size
        char *cookie = (char *) get_random_bytes(16);

        pck->put_byte(pck, SSH_MSG_KEXDH_INIT);
        //pck->put_bytes(pck, cookie, 16);

        struct diffie_hellman *dh;

        dh = kex_dh_compute();

        log_info("Before put_mpint");

        macssh_print_array(pck->data, pck->len);

        pck->put_mpint(pck, &dh->pub_key);

        log_info("After put_mpint");

        macssh_print_array(pck->data, pck->len);

        //pck->put_byte(pck, 1); //No guess
        //pck->put_int(pck, 0); //Reserved

        /* Stamp with metadata */
        put_stamp_2(pck);

        return pck;
}

/* Server response to a client kex_dh_init */
struct packet* kex_dh_reply()
{
        struct packet *dh_pck;

        dh_pck = session.read_packet();

        macssh_print_array(dh_pck->data, dh_pck->len);
        macssh_print_embedded_string(dh_pck->data, dh_pck->len);

        dh_pck->rd_pos += 1; //Skip type
        int key_len = dh_pck->get_int(dh_pck);
        int id_len = dh_pck->get_int(dh_pck);

        //char *k_s = dh_pck->get_bytes(dh_pck, key_len - 4);
        //char *k_s_id = strncpy(k_s_id, k_s, id_len);

        struct ssh_rsa_key *rsa_key = malloc(sizeof (struct ssh_rsa_key));

        mp_init(rsa_key->e);
        mp_init(rsa_key->n);

        /* Get the RSA host key from the packet */
        rsa_key->string = dh_pck->get_bytes(dh_pck, id_len);
        rsa_key->e = dh_pck->get_mpint(dh_pck);
        rsa_key->n = dh_pck->get_mpint(dh_pck);

        if (mp_count_bits(rsa_key->n) < MIN_RSA_KEYLEN)
                log_warn("RSA key too short");

        mp_int *dh_f;

        dh_f = dh_pck->get_mpint(dh_pck);

        DEF_MP_INT(dh_p);
        DEF_MP_INT(dh_p_min1);
        mp_int *dh_e = NULL;

        unsigned int dh_p_len = 256;

        mp_init(&dh_p);
        mp_init(&dh_p_min1);

        mp_read_unsigned_bin(&dh_p, dh_p_14, dh_p_len);

        if (mp_sub_d(&dh_p, 1, &dh_p_min1) != MP_OKAY) {
                log_warn("Diffie-Hellman error");
                exit(EXIT_FAILURE);
        }

        /* Check that dh_pub_them (dh_e or dh_f) is in the range [2, p-2] */
        if (mp_cmp(dh_f, &dh_p_min1) != MP_LT
                || mp_cmp_d(dh_f, 1) != MP_GT) {
                log_warn("Diffie-Hellman error");
                exit(EXIT_FAILURE);
        }

        /* K = e^y mod p = f^x mod p */
        //m_mp_alloc_init_multi(&ses.dh_K, NULL);
        //if (mp_exptmod(dh_pub_them, &param->priv, &dh_p, ses.dh_K) != MP_OKAY) {
        //        dropbear_exit("Diffie-Hellman error");
        //}

        mp_init(&session.dh->dh_k);
        if (mp_exptmod(dh_f, &session.dh->priv_key, &dh_p,
                &session.dh->dh_k) != MP_OKAY) {
                log_warn("Diffie-Hellman error");
                exit(EXIT_FAILURE);
        }

        /* clear no longer needed vars */
        mp_clear_multi(&dh_p, &dh_p_min1, NULL);

        /* Create the remainder of the hash buffer, to generate the exchange hash */
        /* K_S, the host key */

        struct packet *pck = packet_new(2048);

        pck->put_mpint(pck, &session.dh->pub_key);
        pck->put_mpint(pck, dh_f);
        pck->put_mpint(pck, &session.dh->dh_k);

        //buf_put_pub_key(ses.kexhashbuf, hostkey, ses.newkeys->algo_hostkey);
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
        for (x = 0; x < loc->num; x++) {
                for (y = 0; y < rem->end; y++) {
                        if (strcmp(loc->algos[x].name, rem->algos[y]->name) == 0)
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
        struct diffie_hellman *dh_vals = &session.dh;

        DEF_MP_INT(dh_p);
        DEF_MP_INT(dh_q);
        DEF_MP_INT(dh_g);

        /* Initialize dh struct and mp_int's */
        dh_vals = malloc(sizeof (struct diffie_hellman));
        mp_init_multi(&dh_vals->pub_key, &dh_vals->priv_key, &dh_g, &dh_p, &dh_q, NULL);

        unsigned int dh_p_len = 256;

        mp_read_unsigned_bin(&dh_p, dh_p_14, dh_p_len);

        /* Set the dh g value */
        if (mp_set_int(&dh_g, DH_G_VAL) != MP_OKAY)
                log_warn("Diffie-Hellman error");

        /* calculate q = (p-1)/2 */
        /* dh_priv is just a temp var here */
        if (mp_sub_d(&dh_p, 1, &dh_vals->priv_key) != MP_OKAY)
                log_warn("Diffie-Hellman error");

        if (mp_div_2(&dh_vals->priv_key, &dh_q) != MP_OKAY)
                log_warn("Diffie-Hellman error");

        /* Generate a private portion 0 < dh_priv < dh_q */
        gen_random_mpint(&dh_q, &dh_vals->priv_key);

        /* f = g^y mod p 
         * public key portion */
        if (mp_exptmod(&dh_g, &dh_vals->priv_key, &dh_p, &dh_vals->pub_key) != MP_OKAY)
                log_warn("Diffie-Hellman error");

        mp_clear_multi(&dh_g, &dh_p, &dh_q, NULL);

        return dh_vals;
}

FILE* pub_keys_open(char* path)
{

}

int pub_key_check(FILE *pub_key)
{
        char *blob = malloc(1024);
        char *line;
        int line_len;
        int cont = 0;

        char *ptr;
        char *head_subj = NULL;
        char *head_comm = NULL;
        char *head_priv = NULL;

        while (getline(&line, &line_len, pub_key) > 0) {

                if (cont)
                        strncat(ptr, line, line_len);

                else if (!strchr(line, '\\') && !strchr(line, ':')) {
                        strncat(blob, line, line_len);
                }
                
                else if (strchr(line, '\\')) {
                        cont = 1;
                }
                
                else if(!strchr(line, '\\')) {
                        cont = 0;
                }
                
                else if (strchr(line, ':')) {
                        if (strstr(line, PUB_KEY_HEADER_SUBJECT)) {
                                if (!head_subj)
                                        head_subj = calloc(line_len, 1);
                                else
                                        head_subj = realloc(head_subj,
                                        strlen(head_subj) + line_len);

                                ptr = head_subj;
                        }
                        if (strstr(line, PUB_KEY_HEADER_COMMENT)) {
                                if (!head_comm)
                                        head_comm = calloc(line_len, 1);
                                else
                                        head_comm = realloc(head_comm,
                                        strlen(head_comm) + line_len);

                                ptr = head_comm;
                        }
                        if (strstr(line, PUB_KEY_HEADER_PRIVATE)) {
                                if (!head_priv)
                                        head_priv = calloc(line_len, 1);
                                else
                                        head_priv = realloc(head_priv,
                                        strlen(head_priv) + line_len);

                                ptr = head_priv;
                        }

                }
        }

        if (head_subj)
                log_info("Found subject header: %s", head_subj);
        if (head_comm)
                log_info("Found comment header: %s", head_comm);
        if (head_priv)
                log_info("Found private header: %s", head_priv);

        log_info("Found pub_key: %s", blob);
}