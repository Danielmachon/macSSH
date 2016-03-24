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

/* Single buffer node */
struct buf_node {
	
	struct packet *data;
	struct buf_node *next;

};

/* Buffer to hold in- and outgoing data */
struct buffer {
	
	struct buf_node *head;
	struct buf_node *tail;
	
	void (*buf_add)(struct buffer *, struct packet *);
	struct packet* (*buf_remove)(struct buffer *);
	int (*buf_isempty)(struct buffer *);
	int (*buf_len)(struct buffer *);

};

struct buffer* buf_new();
void buf_free(struct buffer *);

#endif /* BUFFER_H */

