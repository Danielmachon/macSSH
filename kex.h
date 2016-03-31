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
 * File:   kex.h
 * Author: dmachon
 *
 * Created on March 25, 2016, 10:16 PM
 */

#ifndef KEX_H
#define KEX_H

struct algorithm {
	const char *name;
	void *algorithm;
};

struct exchange_list {
	int num;
	struct algorithm algos[];
};

extern struct exchange_list kex_list;
extern struct exchange_list host_list;
extern struct exchange_list cipher_list;
extern struct exchange_list hash_list;
extern struct exchange_list compress_list;
extern struct exchange_list lang_list;

void kex_init();
void kex_guess();

#endif /* KEX_H */

