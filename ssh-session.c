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
#include <bits/errno.h>

#include "buffer.h"
#include "ssh-packet.h"
#include "ssh-session.h"
#include "misc.h"

void client_session_loop()
{
	for (;;) {

	}
loop_out:
;
}

void server_session_loop()
{

}

int write_packet(struct packet *pck)
{
	int len = 0;

	len = send(session.sock_out, pck->data + pck->wr_pos,
		pck->len - pck->wr_pos, 0);

	return len;
}

/* Read whatever is on the socket descriptor and return it,
 * as a packet */
struct packet* read_packet(void)
{
	int len = 0;
	struct packet *pck = packet_new(1514);

	len = read(session.sock_out, pck->data, 1514);

	pck->len = len;
}

/* Read binary packet. If the whole packet cant be read,
 * the read content is placed in a temporary packet. */
struct packet* read_bin_packet(void)
{
	int len = 0;
	struct packet *pck;
	(session.packet_part == NULL) ? 
		pck = packet_new(1514) : pck = session.packet_part;

	len = read(session.sock_out, pck->data + pck->len, 1514);

	pck->len = len;

	/* Check if we have the whole packet */
	if (((char*) pck->data)[0] == pck->len) {
		session.buf_in->buf_add(session.buf_in, pck);
	} else {
		session.packet_part = pck;
		return NULL;
	}

	return pck;
}

/* Identify with remote host. 
 * ID packets are read and send directly on the socket
 * descriptor. */
void identify()
{
	struct packet *rem_id_pck = session.read_packet();

	if (errno == EWOULDBLOCK || errno == EAGAIN)
		ssh_exit("failed in identify()", errno);

	fprintf(stderr, "%s\n", rem_id_pck->data);

	if (memcmp(rem_id_pck->data, "SSH-2.0", 7) == 0)
		ssh_print("Found supported remote SSH version\n");
	else
		ssh_print("Found unsupported SSH version\n");

	if (memcmp(rem_id_pck->data + 7, "DMA-SSH", 7) == 0)
		ssh_print("Seems like remote host is using DMA-SSH");

	struct packet *loc_id_pck = packet_new(64);

	loc_id_pck->put_str(loc_id_pck, IDENTIFICATION_STRING);

	loc_id_pck->wr_pos = session.write_packet(loc_id_pck);

	/* Check if entire packet has been transmitted */
	if (loc_id_pck->wr_pos != loc_id_pck->len) {
		/* Enqueue the packet for retransmission */
		session.buf_out->buf_add(session.buf_out, loc_id_pck);

		fprintf(stderr, "%u out of %u was transmitted\n",
			loc_id_pck->wr_pos, loc_id_pck->len);
	}

	free(rem_id_pck);
	free(loc_id_pck);

	session.state = IDENTIFIED;
}

void session_init(struct session *ses)
{
	ses->session_id = 1;

	ses->rx = 0;
	ses->tx = 0;

	ses->buf_in = buf_new();
	ses->buf_out = buf_new();

	ses->packet_part = packet_new(PACKET_MAX_SIZE);

	ses->read_packet = &read_packet;
	ses->read_bin_packet = &read_bin_packet;
	ses->write_packet = &write_packet;
}

void session_free()
{
	buf_free(session.buf_in);
	buf_free(session.buf_out);

	packet_free(session.packet_part);

	close(session.sock_in);
	close(session.sock_out);
}
