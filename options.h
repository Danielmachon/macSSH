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
/* 
 * File:   options.h
 * Author: dmachon
 *
 * Created on March 23, 2016, 10:49 PM
 */

#ifndef OPTIONS_H
#define OPTIONS_H

struct options {
	
	/* SSH options */
	int server_port;
	char server_addr[32];
	
	/* Internal options */
	int verbose;
	int more_verbose;
	int debug;
	
} argv_options;

#endif /* SSH_OPTIONS_H */

