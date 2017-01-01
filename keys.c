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
#include "ssh-packet.h"

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

///* 
// * Compare a binary hostkey against a base64 hostkey from ~.ssh/known_hosts.
// */ 
//static int hostkey_compare(const unsigned char* keyblob, unsigned int keybloblen,
//	const unsigned char* algoname, unsigned int algolen,
//	buffer * line, char **fingerprint)
//{
//
//	buffer *decodekey = NULL;
//	int ret = DROPBEAR_FAILURE;
//	unsigned int len, filealgolen;
//	unsigned long decodekeylen;
//	unsigned char* filealgo = NULL;
//
//	/* now we have the actual data */
//	len = line->len - line->pos;
//	decodekeylen = len * 2; /* big to be safe */
//	decodekey = buf_new(decodekeylen);
//
//	if (base64_decode(buf_getptr(line, len), len,
//		buf_getwriteptr(decodekey, decodekey->size),
//		&decodekeylen) != CRYPT_OK) {
//		TRACE(("checkpubkey: base64 decode failed"))
//			goto out;
//	}
//	TRACE(("checkpubkey: base64_decode success"))
//	buf_incrlen(decodekey, decodekeylen);
//
//	if (fingerprint) {
//		*fingerprint = sign_key_fingerprint(buf_getptr(decodekey, decodekeylen),
//			decodekeylen);
//	}
//
//	/* compare the keys */
//	if ((decodekeylen != keybloblen)
//		|| memcmp(buf_getptr(decodekey, decodekey->len),
//		keyblob, decodekey->len) != 0) {
//		TRACE(("checkpubkey: compare failed"))
//			goto out;
//	}
//
//	/* ... and also check that the algo specified and the algo in the key
//	 * itself match */
//	filealgolen = buf_getint(decodekey);
//	filealgo = buf_getptr(decodekey, filealgolen);
//	if (filealgolen != algolen || memcmp(filealgo, algoname, algolen) != 0) {
//		TRACE(("checkpubkey: algo match failed"))
//			goto out;
//	}
//
//	/* All checks passed */
//	ret = DROPBEAR_SUCCESS;
//
//out:
//	buf_free(decodekey);
//	decodekey = NULL;
//	return ret;
//}

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
char *ssh_key_get_fingerprint(char *key, int len, int type)
{
	return get_md5_fingerprint(key, len);
}

int ssh_generate_rsa_key()
{
	prng_state st;
	rsa_key k;
	FILE *f;
	char path[strlen(MACSSH_CONF_DIR) + strlen("macssh_rsa_key")];
	sprintf(path, "%s%s", MACSSH_CONF_DIR, "macssh_rsa_key");
	
	/* Open key file */
	f = fopen(path, "w+");
	
	if(!f)
		return -1;
	
	/* Create rsa key */
	if(rsa_make_key(&st, 1, 256, 65537, &k) != CRYPT_OK)
		return -1;
	
	/*
	 * We store the key in the format:
	 * string    certificate or public key format identifier
         * byte[n]   key/certificate data
	 */
	int pck_len = 256 + strlen("ssh-rsa") + 4; //4 + for str length
	struct packet *pck = packet_new(pck_len);
	pck->put_int(pck, strlen("ssh-rsa"));
	pck->put_str(pck, "ssh-rsa");
	pck->put_mpint(pck, k.e);
	pck->put_mpint(pck, k.N);
	
	fwrite((void *) pck->data, pck->len, 1, f);
}

char* ssh_generate_dss_key()
{
	
}



