/*
    This file is part of macSSH
    
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
#include "dbg.h"

static int session_read_user_inp()
{
	
}

static int session_flush_buf()
{
	
}

void client_session_loop()
{
	fd_set readfds;

	struct buffer *buf_in = ses.buf_in;
	struct buffer *buf_out = ses.buf_out;

	if (connect_to_remote_host() > -1)
		identify();
	else
		macssh_err("connect");

	if (ses.state >= IDENTIFIED) {
		
		/*
		 * Send the exchange lists.
		 */
		kex_init();
		
		/*
		 * Compute our DH values and send them to server.
		 */
		kex_dh_init();
		
		/*
		 * Get their DH values, compute shared secret.
		 */
		kex_dh_reply();
		
		/*
		 * Create the exchange hash and send it to server.
		 */
		kex_dh_exchange_hash();
	}

	if (ses.state != KEXED)
		exit(EXIT_FAILURE);

	for (;;) {

		struct packet *pck_in;
		struct packet *pck_out;

		/* Check for activity on sockets */
		struct timeval tv;
		tv.tv_sec = 5;
		tv.tv_usec = 5;

		/*
		 * Zero out the set
		 */
		FD_ZERO(&readfds);

		/*
		 * Add stdin to fd_set
		 */
		FD_SET(STDIN_FILENO, &readfds);

		int num;
		if ((num = select(FD_SETSIZE,
			&readfds, NULL, NULL, &tv)) == 0)
			goto out;
		
		/*
		 * Read user input from STDIN.
		 * Encapsulate in packet and place in outgoing,
		 * buffer.
		 */
		if(FD_ISSET(STDIN_FILENO, &readfds))
			session_read_user_inp();
		
		/*
		 * Flush outgoing packet buffer
		 */
		session_flush_buf();
			

out:
		;
	}
}

void server_session_loop()
{
	fd_set readfds;
	int sock;
	int client;
	struct sockaddr_in addr;
	int addr_len = sizeof(struct sockaddr_in);

	sock = init_tcp_listen_socket(6677);

	struct packet *pck;

	for (;;) {

		struct packet *pck_in;
		struct packet *pck_out;

		FD_ZERO(&readfds);

		FD_SET(sock, &readfds);

		/* Check for activity on sockets */
		struct timeval tv;
		tv.tv_sec = 5;
		tv.tv_usec = 5;

		int num;
		if ((num = select(FD_SETSIZE,
			&readfds, NULL, NULL, &tv)) < 1)
			goto out;

		if (FD_ISSET(sock, &readfds)) {
			ses.sock_out = accept(sock, (struct sockaddr *) &addr,
				&addr_len);
			ses.sock_in = ses.sock_out;
			identify();
			kex_init();
		}

		pck_in = packet_new(1500);

		ses.write_packet(pck_in);
out:
		;
	}

}

int write_packet(struct packet *pck)
{
	int len = 0;

	len = send(ses.sock_out, pck->data + pck->wr_pos,
		pck->len - pck->wr_pos, 0);

	return len;
}

/* Read the first 8 bytes, or cipher block-size, whichever is larger,
 * of a pending packet */
static int read_packet_init(struct packet *pck)
{
	pck->len += read(ses.sock_in, pck->data + pck->len, 8);

	macssh_info("%u", pck->len);

	if (pck->len == 8)
		macssh_info("Successfully read first 8 bytes");
	else if (pck->len == 0)
		macssh_warn("Connection closed by remote host");
	else
		macssh_err("try_read_packet");
}

/* Read packet. If the whole packet cant be read,
 * the read content is placed in a temporary packet. */
struct packet* read_packet(void)
{
	struct packet *pck;

	(ses.pck_tmp == NULL) ?
		(pck = packet_new(2048)) : (pck = ses.pck_tmp);

	read_packet_init(pck);

	if (pck->len < 8) {
		(ses.pck_tmp == NULL) ? (ses.pck_tmp = pck) :
			macssh_exit("Could not read packet in 2 tries", -1);
		return NULL;
	}

	macssh_print_array(pck->data, pck->len);

	/* We have enough info to determine the length of the packet */
	int pck_len, pck_pad, pck_pay_len;
	pck_len = pck->get_int(pck);
	pck_pad = pck->get_byte(pck);
	pck_pay_len = (pck_len - pck_pad - 1);
	pck_len += 4; // -uint32 and mac length

	pck->len += read(ses.sock_out, pck->data + pck->len, (pck_len - 8));

	if (pck->len != pck_len) {
		ses.pck_tmp = pck;
		return NULL;
	}

	/* We have the whole packet. Place it in ingoing buffer*/
	//ses.buf_in->buf_add(ses.buf_in, pck);

	macssh_print_embedded_string(pck->data, pck->len);

	return pck;
}

void process_packet()
{
	struct packet *pck;

	pck = ses.buf_in->buf_get(ses.buf_in);
}

/* 
 * Identify with remote host. 
 * ID packets are read and send directly on the socket descriptor. 
 */
void identify()
{
	struct packet *loc_id_pck = packet_new(64);

	loc_id_pck->put_str(loc_id_pck, IDENTIFICATION_STRING);

	loc_id_pck->wr_pos = ses.write_packet(loc_id_pck);

	/* Check if entire packet has been transmitted */
	if (loc_id_pck->wr_pos != loc_id_pck->len) {
		/* Enqueue the packet for retransmission */
		ses.buf_out->buf_add(ses.buf_out, loc_id_pck);

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
	pck = packet_new(2048);

	pck->len = read(ses.sock_in, pck->data, 2048);

	macssh_print_array(pck->data, pck->len);
	macssh_print_embedded_string(pck->data, pck->len);

	/* 
	 * We might receive the KEX_INIT immediatelly after the,
	 * identification (eg. debugging).
	 */
	int x;
	for (x = 0; x < pck->len; x++) {
		if ((*(pck->data + x) == '\r') &&
			(*(pck->data + x + 1) == '\n')) {
			strncpy(ses.remote_id, pck->data, x);
			pck->rd_pos += (x + 2);
			break;
		}

	}

	if (x + 2 == pck->len) {
		free(pck);
		ses.state = IDENTIFIED;
	} else {
		macssh_info("Seems like serverside has sent id string,"
			" and kexinit immediately after each other");

		ses.state = HAVE_KEX_INIT;
		ses.pck_tmp = pck;
	}

	macssh_info("Found identification string: %s\n",
		ses.remote_id);
}

void session_init(struct session *ses)
{
	ses->session_id = 1;

	ses->rx = 0;
	ses->tx = 0;

	ses->buf_in = buf_new();
	ses->buf_out = buf_new();

	ses->pck_tmp = NULL;

	ses->crypto = calloc(1, sizeof(struct crypto));

	ses->read_packet = &read_packet;
	ses->write_packet = &write_packet;

	/*
	 * Allocated memory for the channels list head
	 */
	ses->channels = calloc(1, sizeof(struct channel));
	
	/*
	 * Initialize the diffie hellman struct
	 */
	ses->dh = calloc(1, sizeof(struct diffie_hellman));

	/*
	 * Initialize the channels list head
	 */
	INIT_LIST_HEAD(&ses->channels->list);
}

void session_free(struct session *ses)
{
	buf_free(ses->buf_in);
	buf_free(ses->buf_out);

	packet_free(ses->pck_tmp);

	close(ses->sock_in);
	close(ses->sock_out);
}
