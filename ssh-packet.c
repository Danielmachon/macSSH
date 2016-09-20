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
#include "ssh-packet.h"
#include "kex.h"
#include "misc.h"
#include "dbg.h"

void put_size(struct packet *pck, int data)
{
	STORE32H(data, pck->data);
}

void put_pad_size(struct packet *pck, int data)
{
	((unsigned char *) pck->data)[4] = data;
}

/* Fill our the meta-data of the packet */
void put_stamp(struct packet* pck)
{

	int pad;
	if ((pad = (pck->len % 8)) > 4) {
		put_pad_size(pck, (8 - pad));
	} else {
		pad = 4;
		put_pad_size(pck, pad);
	}

	int x;
	for (x = 0; x < pad; x++)
		pck->put_byte(pck, 0);

	put_size(pck, pck->len);
}

void put_byte(struct packet *pck, unsigned char data)
{
	*(pck->data + pck->len) = data;
	
	pck->len++;
}

/* This function does NOT increment the write offset */
void put_byte_at(struct packet *pck, unsigned char data, int index)
{
	*(pck->data + index) = data;
}

void put_bytes(struct packet *pck, void *data, int len)
{
	memcpy(pck->data + pck->len, (unsigned char*) data, len);
	
	pck->len += len;
}

void put_char(struct packet *pck, unsigned char data)
{
	put_byte(pck, data);
	
	pck->len++;
}

void put_int(struct packet *pck, int data)
{
	/* Macro from tomcrypt */
	STORE32H(data, pck->data + pck->len);
	
	pck->len += 4;
}

void put_str(struct packet *pck, const char *data)
{
	memmove(((char*) pck->data) + pck->len, data, strlen(data));
	pck->len += strlen(data);
}

/* If the most significant bit would be set for
 * a positive number, the number MUST be preceded by a zero byte.
 * Unnecessary leading bytes with the value 0 or 255 MUST NOT be
 * included.  The value zero MUST be stored as a string with zero
 * bytes of data. */
void put_mpint(struct packet *pck, mp_int *mpi)
{
	/* Determine length */
	unsigned int len = (mp_count_bits(mpi) / 8 + 1);

	pck->put_int(pck, len);

	/* Check if we should pad with a preceding zero byte */
	if (len % 8 == 0)
		pck->put_byte(pck, 0x00);

	if (mp_to_unsigned_bin(mpi, (unsigned char *) pck->data) != MP_OKAY)
		macssh_exit("error in put_mpint", errno);
}

void put_exch_list(struct packet* pck, struct exchange_list_local* data)
{
	struct packet *tmp = packet_new(1024);

	int x;
	for (x = 0; x < data->num; x++) {

		tmp->put_str(tmp, data->algos[x].name);

		if (x != (data->num - 1))
			tmp->put_char(tmp, ',');

	}

	pck->put_int(pck, tmp->len);
	pck->put_str(pck, (const char *) tmp->data);

}

int get_int(struct packet * pck)
{
	int ret;
	LOAD32H(ret, pck->data + pck->rd_pos);
	pck->rd_pos += 4;
	return ret;
}

mp_int* get_mpint(struct packet *pck)
{
	mp_int *mpi;
	mp_init(mpi);

	unsigned int len = pck->get_int(pck);

	if (len < 0)
		macssh_exit("error in get_mpint", errno);

	/* Check if ms bit is set */
	if (*(unsigned char *) (pck->data + pck->rd_pos) & (1 << (CHAR_BIT - 1)))
		macssh_exit("error in get_mpint", errno);

	if (mp_read_unsigned_bin(mpi, pck->data + pck->rd_pos, len) != MP_OKAY)
		macssh_exit("error in get_mpint", errno);

	/* Increment read position */
	pck->data += len;

	/* Remember to free */
	return mpi;

}

unsigned char get_char(struct packet * pck)
{
	return get_byte(pck);
}

char* get_str(struct packet * pck)
{
	/* We are assuming a str i zero terminated
	 * Undefined behaviour if it is not */
	
	char *str;
	int len;
	
	len = strlen(pck->data + pck->rd_pos);
	
	str = calloc(len, 1);
	strcpy(str, (pck->data + pck->rd_pos));
	
	return str;
	
}

unsigned char get_byte(struct packet * pck)
{
	unsigned char ret;
	
	ret = ((unsigned char *) pck->data)[pck->rd_pos];
	
	pck->rd_pos++;
	
	return ret;
}

unsigned char* get_bytes(struct packet *pck, int num)
{
	unsigned char *ret;
	ret = malloc(num);
	memcpy(ret, pck->data + pck->rd_pos, num);
	pck->rd_pos += num;
	return ret;
}

/* Iterate through remote KEX_INIT packet */
struct exchange_list_remote* get_exch_list(struct packet * pck)
{
	struct exchange_list_remote *ret;
	int len;
	int pos;

	/* Initialize exchange list and make room for 10 initial
	 * algorithms - realloc if necessaray */
	ret = malloc(sizeof(struct exchange_list_remote));
	ret->algos = malloc(sizeof(struct algorithm *) * 10);
	ret->num = 10;
	ret->end = 0;

	len = get_int(pck);
	pos = pck->rd_pos;

	int x;
	for (x = pos; x <= pos + len; x++) {
		
		if (((unsigned char *) pck->data)[x] == ',' || 	
			x == (len + pos)) {

			if (ret->end >= ret->num) {
				ret->algos = realloc(ret->algos,
					sizeof(struct algorithm) * ret->num + 5);
				ret->num += 5;
			}

			ret->algos[ret->end] =
				malloc(sizeof(struct algorithm));

			unsigned char *name;
			name = pck->get_bytes(pck, (x - pck->rd_pos));
			
			if(x != (len + pos))
				pck->rd_pos++;

			ret->algos[ret->end]->name = name;

			log_info(stderr, "%s\n", ret->algos[ret->end]->name);

			ret->end++;

		}
	}

	return ret;
}

void packet_init(struct packet * pck)
{
	pck->len = 0;
	pck->wr_pos = 0;

	/* Puts */
	pck->put_byte = &put_byte;
	pck->put_char = &put_char;
	pck->put_int = &put_int;
	pck->put_str = &put_str;
	pck->put_bytes = &put_bytes;
	pck->put_exch_list = &put_exch_list;
	pck->put_mpint = &put_mpint;

	/* Gets */
	pck->get_int = &get_int;
	pck->get_byte = &get_byte;
	pck->get_bytes = &get_bytes;
	pck->get_exch_list = &get_exch_list;
}

struct packet * packet_new(unsigned int size)
{
	struct packet *pck;

	if ((pck = malloc(sizeof(struct packet))) == NULL)
		return NULL;

	if ((pck->data = malloc(size)) == NULL)
		return NULL;

	packet_init(pck);

	pck->size = size;

	return pck;
}

int packet_encrypt(struct packet * pck)
{

}

/* The minimum size of a packet is 16 (or the cipher block size,
whichever is larger) bytes (plus 'mac').  Implementations SHOULD
decrypt the length after receiving the first 8 (or cipher block size,
whichever is larger) bytes of a packet. */
int packet_descrypt(struct packet * pck)
{

}

void packet_free(struct packet * pck)
{
	free(pck->data);
	free(pck);
}
