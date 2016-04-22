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

#ifndef SSH_SESSION_H
#define SSH_SESSION_H

#include "buffer.h"
#include "build.h"
#include "crypto.h"
#include "ssh-channel.h"
#include "ssh-packet.h"

#define IDENTIFICATION_STRING "SSH-2.0-" SSH_VERSION_STR "\r\n"

struct session;

void session_free();
void session_init(struct session *ses);
void client_session_loop();
void server_session_loop();
void identify();
void read_identification_string();

enum {
	NONE = 0,
	IDENTIFIED = 1,
	HAVE_KEX_INIT = 2,
	KEXED = 3,
	SETUP = 4,
};

struct session {
	
	int session_id;

	int state;

	int sock_in;
	int sock_out;

	int rx;
	int tx;
	
	char remote_id[256];
	
	/* Number of kex'es (initial + renegotiation) */
	int kex_num;
	
	struct crypto *crypto;
	
	struct diffie_hellman *dh;

	struct channel **channels;

	/* Partial read packet. Might be incomplete
	 * after a read. Is put in ingoing buffer if
	 * complete. */
	struct packet *packet_part;
	int packet_flag;

	struct buffer *buf_in;
	struct buffer *buf_out;

	int (*write_packet)(struct packet *pck);
	struct packet* (*read_packet)();
	void (*process_packet)();
	

	/* Initial identification */
	void (*identify)();

	/* KEX */
	void (*kex_init)();

} session;

#endif /* SSH_SESSION_H */

