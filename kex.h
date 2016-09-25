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
/* 
 * File:   kex.h
 * Author: dmachon
 *
 * Created on March 25, 2016, 10:16 PM
 */

#ifndef KEX_H
#define KEX_H

#include "libtommath/tommath.h"

enum {
	KEX_OK = 0b00000001,
	KEX_FAIL = 0b00000010
};

struct diffie_hellman {
	mp_int pub_key;
	mp_int priv_key;
	mp_int dh_k;
};

struct algorithm {
	char *name;
	const void *algorithm;
};

struct exchange_list_local {
	int num;
	struct algorithm algos[];
};

struct exchange_list_remote {
	int num;
	int end;
	struct algorithm **algos;
};

extern int kex_status;

extern struct exchange_list_local kex_list;
extern struct exchange_list_local host_list;
extern struct exchange_list_local cipher_list;
extern struct exchange_list_local hash_list;
extern struct exchange_list_local compress_list;
extern struct exchange_list_local lang_list;

void kex_init();
void kex_guess();

struct packet* kex_dh_init();
struct packet* kex_dh_reply();

#endif /* KEX_H */

