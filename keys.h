/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   keys.h
 * Author: dmachon
 *
 * Created on 24. september 2016, 23:29
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

unsigned char *ssh_key_get_fingerprint(char *key, int len, int type);

#endif /* KEYS_H */

