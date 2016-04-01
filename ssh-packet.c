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

void put_size(struct packet *pck, int data)
{
	STORE32H(data, pck->data);
}

void put_pad_size(struct packet *pck, int data)
{
	((unsigned char *) pck->data)[4] = data;
}

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
	((unsigned char *) pck->data)[pck->len] = data;
	pck->len++;
}

void put_bytes(struct packet *pck, void *data, int len)
{
	memcpy(pck->data + pck->len, (unsigned char*) data, len);
	pck->len += len;
}

void put_char(struct packet *pck, unsigned char data)
{
	((char *) pck->data)[pck->len] = data;
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

void put_exch_list(struct packet* pck, struct exchange_list* data)
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
	LOAD32H(ret, pck->data);
	pck->rd_pos += 4;
	return ret;
}

unsigned char get_char(struct packet * pck)
{

}

char* get_str(struct packet * pck)
{
	/* Probably not safe to assume a string is zero terminated */
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
	memcpy(ret, pck->data, num);
	pck->rd_pos += num;
}

struct exchange_list * get_exch_list(struct packet * pck)
{
	struct exchange_list *ret;
	int len;
	int pos;
	
	ret = malloc(sizeof(struct exchange_list));
	
	len = get_int(pck);
	
	int x;
	for(x = 0; x < len; x++) {
		if(((unsigned char *)pck->data)[x] == ',' || x == len) {
			//ret.algos[ret.num] = malloc(sizeof(struct exchange_list));
			//ret.algos[ret.num] = calloc(x + 1, 1);
			memcpy((void *)ret->algos[ret->num].name, get_bytes(pck->data, 
				(pck->rd_pos - x)), pck->rd_pos - x); 
		}
	}
	
	return ret;
}

void packet_init(struct packet * pck)
{
	pck->len = 0;
	pck->wr_pos = 0;

	pck->put_byte = &put_byte;
	pck->put_char = &put_char;
	pck->put_int = &put_int;
	pck->put_str = &put_str;
	pck->put_bytes = &put_bytes;
	pck->put_exch_list = &put_exch_list;
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
