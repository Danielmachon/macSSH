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

#include <unistd.h>

#include "buffer.h"
#include "ssh-packet.h"
#include "ssh-session.h"

void client_session_loop()
{

}

void server_session_loop()
{

}

void write_packet(struct packet *pck)
{

}

struct packet* read_packet(void)
{
	int len = 0;
	struct packet *pck = packet_new(1514);

	len = read(session.sock_out, pck->data, 1514);

	pck->len = len;

	if (((char*) pck->data)[0] == pck->len)
		return pck;
	else
		return pck;

}

void send_identification_string()
{
	struct packet *pck;
	pck = packet_new(1514);

	pck->put_str(pck, "SSH-2.0-DMA-SSH-alpha \r\n");

	session.buf_out->buf_add(session.buf_out, pck);

}

void read_identification_string()
{

}

void session_init(struct session *ses)
{
	ses->buf_in = buf_new();
	ses->buf_out = buf_new();

	ses->read_packet = &read_packet;
	ses->write_packet = &write_packet;
}