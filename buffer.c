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

#include "buffer.h"

void buf_add(buffer_t *buf, packet_t *data)
{
	buf_node_t *node = malloc(sizeof(buf_node_t));

	node->data = data;
	node->next = NULL;

	if (buf->tail == NULL)
		buf->head = buf->tail = node;
	else {
		buf->tail->next = node;
		buf->head = node;
	}
}

packet_t* buf_remove(buffer_t *buf)
{
	buf_node_t *node;
	packet_t *data;

	if ((node = buf->head) == NULL)
		return NULL;

	data = node->data;
	if ((buf->head = node->next) == NULL)
		buf->tail = NULL;

	free(node);

	return data;
}

int buf_isempty(buffer_t *buf)
{
	return(buf->head == NULL) ? 0 : 1;
}

int buf_len(buffer_t *buf)
{
	int count = 0;
	buf_node_t *node;
	for (node = buf->head; node; node = node->next)
		count++;

	return count;
}

void buf_free(buffer_t *buf)
{
	buf_node_t *node;
	for (node = buf->head; node; node = node->next) {
		free(node->data);
		free(node);
	}
	free(buf);
}

static void buf_init(buffer_t *buf)
{
	buf->head = NULL;
	buf->tail = NULL;

	buf->buf_add = &buf_add;
	buf->buf_remove = &buf_remove;
	buf->buf_isempty = &buf_isempty;
	buf->buf_len = &buf_len;
}

buffer_t* buf_new(void)
{
	buffer_t *buf = malloc(sizeof(buffer_t));
	buf_init(buf);

	return buf;
}