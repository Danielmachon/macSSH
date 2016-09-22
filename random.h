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
 * File:   random.h
 * Author: dmachon
 *
 * Created on April 5, 2016, 10:30 PM
 */

#ifndef RANDOM_H
#define RANDOM_H

#include "includes.h"

void seedrandom();
void genrandom(unsigned char* buf, unsigned int len);
void addrandom(unsigned char * buf, unsigned int len);
void gen_random_mpint(mp_int *max, mp_int *rand);

void* get_random_bytes(int size);

#endif /* RANDOM_H */

