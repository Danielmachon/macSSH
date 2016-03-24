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

void put_byte(struct packet *pck, char data[1])
{
	
}

void put_char(struct packet *pck, char data[1])
{
	
}

void put_int(struct packet *pck, int data)
{
	
}

void put_str(struct packet *pck, char *data)
{
	memmove(((char*)pck->data) + pck->len, data, strlen(data));
	pck->len += strlen(data);
}


void packet_init(struct packet *pck)
{
	pck->len = 0;
	pck->pos = 0;
	
	pck->put_byte = &put_byte;
	pck->put_char = &put_char;
	pck->put_int = &put_int;
	pck->put_str = &put_str;
}

struct packet* packet_new(unsigned int size)
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
