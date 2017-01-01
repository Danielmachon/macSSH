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

#ifndef SSH_PACKET_H
#define SSH_PACKET_H

#include "includes.h"

#define PACKET_MAX_SIZE  35000

#define SET_WR_POS(a, b) { a->wr_pos = b; }
#define SET_RD_POS(a, b) { a->rd_pos = b; }
#define INCREMENT_WR_POS(a, b) { a->wr_pos += b; }
#define INCREMENT_RD_POS(a, b) { a->rd_pos += b; }

/* All implementations MUST be able to process packets with an
uncompressed payload length of 32768 bytes or less and a total packet
size of 35000 bytes or less (including 'packet_length',
'padding_length', 'payload', 'random padding', and 'mac'). */

struct exchange_list_local;

/* Single packet buffer */
struct packet {
	
	char *data; /* Actual data */

	unsigned int len; /* Used size */
	unsigned int wr_pos; /* Write position */
	unsigned int rd_pos; /* Read position */
	unsigned int size; /* Memory size */

	/*
	 * Put operations
	 */
	void (*put_int)(struct packet *pck, int data);
	void (*put_char)(struct packet *pck, unsigned char data);
	void (*put_str)(struct packet *pck, const char *data);
	void (*put_byte)(struct packet *pck, unsigned char);
	void (*put_bytes)(struct packet *pck, void *data, int len);
	void (*put_exch_list)(struct packet *pck, struct exchange_list_local *data);
	void (*put_mpint)(struct packet *pck, mp_int *mpi);

	/*
	 * Get operations
	 */
	mp_int* (*get_mpint)(struct packet *pck, mp_int *mp);
	int (*get_int)(struct packet *pck);
	char* (*get_str)(struct packet *pck);
	unsigned char (*get_char)(struct packet *pck);
	unsigned char (*get_byte)(struct packet *pck);
	unsigned char (*get_byte_at)(struct packet *pck, int index);
	unsigned char (*get_byte_at_offset)(struct packet *pck, int offset);
	unsigned char* (*get_bytes)(struct packet *pck, int num);
	struct exchange_list_remote* (*get_exch_list)(struct packet *pck);
	
	/*
	 * Other operations
	 */
	int (*resize)(struct packet *pck, int size);
	
	/*
	 * Crypto operations
	 */
	int (*encrypt) (struct packet *pck);
	int (*decrypt) (struct packet *pck);
	
	/*
	 * Linked-list head
	 */	
	struct list_head list;
	
};

/* Create new packet */
struct packet* packet_new(unsigned int size);

/* Wrap 'data' in a new packet */
struct packet* packet_wrap(char *data, int size);

/* Initialize packet */
void packet_init(struct packet *pck);

/* Free packet */
void packet_free(struct packet *pck);

/* Crypto stuff */
int packet_encrypt(struct packet *pck);
int packet_descrypt(struct packet *pck);

/* Manipulate meta-data in packet */
void put_size(struct packet *pck, int data);
void put_pad_size(struct packet *pck, int data);
void put_stamp(struct packet *pck);

#endif /* SSH_PACKET_H */

