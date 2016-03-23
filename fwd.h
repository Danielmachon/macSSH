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
 * File:   port-fwd.h
 * Author: dmachon
 *
 * Created on March 22, 2016, 11:06 PM
 */

#ifndef FWD_H
#define FWD_H

typedef struct fwd fwd_t;

struct fwd {
	
};

struct fwds {
	fwd_t **fwds;
	int end;
};

#endif /* FWD_H */

