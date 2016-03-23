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

#ifndef BUFFER_H
#define BUFFER_H

#include "ssh-packet.h"
#include "includes.h"


typedef struct buffer buffer_t;
typedef struct buf_node buf_node_t;

/* Single buffer node */
struct buf_node {
	
	packet_t *data;
	buf_node_t *next;

};

/* Buffer to hold in- and outgoing data */
struct buffer {
	
	buf_node_t *head;
	buf_node_t *tail;
	
	void (*buf_add)(buffer_t *, packet_t *);
	packet_t* (*buf_remove)(buffer_t *);
	int (*buf_isempty)(buffer_t *);
	int (*buf_len)(buffer_t *);

};

buffer_t* buf_new();
void buf_free(buffer_t *);

#endif /* BUFFER_H */

