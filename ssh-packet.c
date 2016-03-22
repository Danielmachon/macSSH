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

packet_t* packet_new(unsigned int size)
{
	packet_t *pck;

	if ((pck = malloc(sizeof(packet_t))) == NULL)
		return NULL;

	if ((pck->data = malloc(size)) == NULL)
		return NULL;

	pck->size = size;
	pck->pos = 0;
	pck->len = size;

	return pck;
}

void packet_init()
{

}
