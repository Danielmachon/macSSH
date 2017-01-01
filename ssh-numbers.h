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

#ifndef SSH_NUMBERS_H
#define SSH_NUMBERS_H

/* Specs:
 * http://www.openssh.com/txt/rfc4250.txt		[SSH-NUMBERS]
 * https://tools.ietf.org/html/rfc4253			[SSH-TRANS]
 * https://www.ietf.org/rfc/rfc4252.txt			[SSH-USERAUTH]
 * https://www.ietf.org/rfc/rfc4254.txt			[SSH-CONNECT]
 */

#define SSH_MSG_DISCONNECT                       1	//[SSH-TRANS]
#define SSH_MSG_IGNORE                           2	//[SSH-TRANS]
#define SSH_MSG_UNIMPLEMENTED                    3	//[SSH-TRANS]
#define SSH_MSG_DEBUG                            4	//[SSH-TRANS]
#define SSH_MSG_SERVICE_REQUEST                  5	//[SSH-TRANS]
#define SSH_MSG_SERVICE_ACCEPT                   6	//[SSH-TRANS]
#define SSH_MSG_KEXINIT                         20	//[SSH-TRANS]
#define SSH_MSG_NEWKEYS                         21	//[SSH-TRANS]
#define SSH_MSG_KEXDH_INIT			30	//[SSH-TRANS]
#define SSH_MSG_KEXDH_REPLY			31	//[SSH-TRANS]
#define SSH_MSG_USERAUTH_REQUEST                50	//[SSH-USERAUTH]
#define SSH_MSG_USERAUTH_FAILURE                51	//[SSH-USERAUTH]
#define SSH_MSG_USERAUTH_SUCCESS                52	//[SSH-USERAUTH]
#define SSH_MSG_USERAUTH_BANNER                 53	//[SSH-USERAUTH]
#define SSH_MSG_GLOBAL_REQUEST                  80	//[SSH-CONNECT]
#define SSH_MSG_REQUEST_SUCCESS                 81	//[SSH-CONNECT]
#define SSH_MSG_REQUEST_FAILURE                 82	//[SSH-CONNECT]
#define SSH_MSG_CHANNEL_OPEN                    90	//[SSH-CONNECT]
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION       91	//[SSH-CONNECT]
#define SSH_MSG_CHANNEL_OPEN_FAILURE            92	//[SSH-CONNECT]
#define SSH_MSG_CHANNEL_WINDOW_ADJUST           93	//[SSH-CONNECT]
#define SSH_MSG_CHANNEL_DATA                    94	//[SSH-CONNECT]
#define SSH_MSG_CHANNEL_EXTENDED_DATA           95	//[SSH-CONNECT]
#define SSH_MSG_CHANNEL_EOF                     96	//[SSH-CONNECT]
#define SSH_MSG_CHANNEL_CLOSE                   97	//[SSH-CONNECT]
#define SSH_MSG_CHANNEL_REQUEST                 98	//[SSH-CONNECT]
#define SSH_MSG_CHANNEL_SUCCESS                 99	//[SSH-CONNECT]
#define SSH_MSG_CHANNEL_FAILURE                100	//[SSH-CONNECT]

#endif /* SSH_NUMBERS_H */

