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

/* Read the first 16 bytes, or cipher block-size, whichever is larger,
 * of a pending packet */
static int try_read_packet(struct packet *pck)
{
	int len = 0;

	len = read(session.sock_in, pck->data, 16);

	if (len == 16)
		return len;
	else
		return -1;
}

/* Read packet. If the whole packet cant be read,
 * the read content is placed in a temporary packet. */
struct packet* read_packet(void)
{
	int rd_len = 0;
	struct packet *pck;

	(session.packet_part == NULL) ?
		(pck = packet_new(1514)) : (pck = session.packet_part);

	rd_len = try_read_packet(pck);

	if (rd_len < 16) {
		(session.packet_part == NULL) ? (session.packet_part = pck) :
			macssh_exit("Could not read packet in 2 tries", -1);
		return NULL;
	}

	/* We have enough info to determine the length of the packet */
	int pck_len;
	pck_len = pck->get_int(pck);

	rd_len = read(session.sock_out, pck->data + pck->len, (pck_len - 16));

	if (rd_len != (pck_len - 16)) {
		session.packet_part = pck;
		return NULL;
	}

	/* We have the whole packet. Place it in ingoing buffer*/
	session.buf_in->buf_add(session.buf_in, pck);

	return pck;
}

void process_packet()
{
	struct packet *pck;

	pck = session.buf_in->buf_get(session.buf_in);
}

/* Identify with remote host. 
 * ID packets are read and send directly on the socket
 * descriptor. */
void identify()
{
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


	read_identification_string();

	if (errno == EWOULDBLOCK || errno == EAGAIN)
		macssh_exit("failed in identify()", errno);

	free(loc_id_pck);
}

void read_identification_string()
{
	struct packet *pck;
	pck = packet_new(1514);
	int len = 0;

	pck->len = read(session.sock_in, pck->data, 1514);

	/* Some implementations will send the KEXINIT immediately after
	 * the identification string. Check for that and increment the read,
	 * position accordingly. */
	int x;
	for (x = 0; x < pck->len; x++) {
		if (((unsigned char *) pck->data)[x] == '\r' &&
			((unsigned char *) pck->data)[x + 1] == '\n') {
			strncpy(session.remote_id,
				(unsigned char *) pck->data, x);
			pck->rd_pos += (x + 2);
			break;
		}

	}

	if (x + 2 == pck->len) {
		free(pck);
		session.state = IDENTIFIED;
	} else {
		macssh_debug("Seems like serverside has sent id string,"
			" and kexinit immediately after each other\n");

		session.state = HAVE_KEX_INIT;
		session.packet_part = pck;
	}

	fprintf(stderr, "Found identification string: %s\n",
		session.remote_id);
}

void session_init(struct session *ses)
{
	ses->session_id = 1;

	ses->rx = 0;
	ses->tx = 0;

	ses->buf_in = buf_new();
	ses->buf_out = buf_new();

	ses->packet_part = packet_new(PACKET_MAX_SIZE);

	ses->crypto = malloc(sizeof(struct crypto));
	memset(ses->crypto, 0, sizeof(struct crypto));

	ses->read_packet = &read_packet;
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
