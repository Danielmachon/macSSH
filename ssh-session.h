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
#include "ssh-channel.h"
#include "ssh-packet.h"

struct session {
	
	int session_id;
	
	int sock_in;
	int sock_out;
	
	struct channel **channels;
	
	struct buffer buf_in;
	struct buffer buf_out;
	
	(*write_packet)(struct packet *pck);
	struct packet* (*read_packet)(void);
	
};

void client_session_loop();
void server_session_loop();

#endif /* SSH_SESSION_H */

