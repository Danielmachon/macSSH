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
#include "util.h"
#include "ssh-session.h"

#define h_addr h_addr_list[0]

int init_tcp_socket(char* ip, int port, int t_out);
int init_tcp_listen_socket(int port); 

int connect_to_remote_host()
{
	int sock;
	sock = init_tcp_socket("194.255.39.141", 6666, 0);

	if(sock < 0)
		return -1;
	else
		ses.sock_out = ses.sock_in = sock;
	
	return 0;
}

int init_tcp_socket(char *ip, int port, int t_out)
{
	/* Needs to be declared outside while loop */
	int sock;

	struct hostent *host;
	struct sockaddr_in server_addr;
	struct timeval rcv_timeval;
	struct timeval snd_timeval;

	/* TextSpeak IP Address is defined as 192.168.0.23 */
	host = gethostbyname(ip);

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;


	/* Set TCP socket options */
	if (t_out) {
		rcv_timeval.tv_sec = t_out;
		rcv_timeval.tv_usec = 0;
		snd_timeval.tv_sec = t_out;
		snd_timeval.tv_usec = 0;

		int buffersize = 2;
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &rcv_timeval, sizeof(struct timeval));
		setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &snd_timeval, sizeof(struct timeval));
		setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buffersize, 4);
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr = *((struct in_addr *) host->h_addr);
	bzero(&(server_addr.sin_zero), 8);

	if (connect(sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) < 0)
		return -1;

	return sock;
}

int init_tcp_listen_socket(int port)
{
	/* Needs to be declared outside while loop */
	int sock;

	struct hostent *host;
	struct sockaddr_in si_me;
	struct timeval rcv_timeval;
	struct timeval snd_timeval;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;

	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(port);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sock, (struct sockaddr*) &si_me, sizeof(si_me)) == -1)
		return -1;
        
        listen(sock, 5);


	return sock;
}

void get_ip(struct in_addr *addr, char *ip)
{
	inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN);
}
