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
 * File:   ssh-packet.h
 * Author: dmachon
 *
 * Created on March 22, 2016, 9:09 PM
 */

#ifndef SSH_PACKET_H
#define SSH_PACKET_H

typedef char byte_t;

/* All implementations MUST be able to process packets with an
uncompressed payload length of 32768 bytes or less and a total packet
size of 35000 bytes or less (including 'packet_length',
'padding_length', 'payload', 'random padding', and 'mac'). */

/* Single packet buffer */
struct packet {
	
	void *data;
	unsigned int len; /* the used size */
	unsigned int pos;
	unsigned int size; /* the memory size */
	
	void (*put_int)(struct packet *pck, int data);
	void (*put_char)(struct packet *pck, char data[1]);
	void (*put_str)(struct packet *pck, char *data);
	void (*put_byte)(struct packet *pck, char[1]);
	
};

/* Initialize/Manipulate packet */
struct packet* packet_new(unsigned int size);
void packet_init();
void packet_resize(struct packet *pck);

/* Manipulate data in packet */
void put_int(struct packet *pck, int data);
void put_char(struct packet *pck, char data[1]);
void put_str(struct packet *pck, char *data);
void put_byte(struct packet *pck, char[1]);

#endif /* SSH_PACKET_H */

