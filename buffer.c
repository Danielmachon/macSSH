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
#include "list.h"

void buf_add(struct buffer *buf, struct packet *data)
{
        list_add(&data->list, &buf->packets->list);
}

struct packet* buf_get(struct buffer *buf)
{
        struct packet *pck;

        pck = list_entry(buf->packets->list.next, struct packet, list);

        list_del(&pck->list);

        return pck;
}

struct packet* buf_peak(struct buffer *buf)
{
        struct packet *pck;

        pck = list_entry(buf->packets->list.next, struct packet, list);

        return pck;
}

int buf_isempty(struct buffer *buf)
{
        return (list_empty(&buf->packets->list));
}

int buf_len(struct buffer *buf)
{
        int count = 0;

        while (!list_empty(&buf->packets->list))
                count++;

        return count;
}

void buf_free(struct buffer *buf)
{
        struct packet *pck;
        struct list_head *pos;
        struct list_head *safe;

        list_for_each_safe(pos, safe, &buf->packets->list)
        {
                pck = list_entry(pos, struct packet, list);
                list_del(pos);
                free(pck);
        }

        free(buf);
}

static void buf_init(struct buffer *buf)
{

        buf->packets = packet_new(1514);
        
        INIT_LIST_HEAD(&buf->packets->list);

        buf->buf_add = &buf_add;
        buf->buf_get = &buf_get;
        buf->buf_peak = &buf_peak;
        buf->buf_isempty = &buf_isempty;
        buf->buf_len = &buf_len;
}

struct buffer* buf_new(void)
{
        struct buffer *buf = malloc(sizeof (struct buffer));

        buf_init(buf);

        return buf;
}