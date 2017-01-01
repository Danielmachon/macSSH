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

#ifndef CRYPTO_H
#define CRYPTO_H

#include "includes.h"
#include "kex.h"

struct keys {
	
	struct algorithm *kex;
	struct algorithm *host;
	struct algorithm *ciper;
	struct algorithm *hash;
	struct algorithm *compress;
	struct algorithm *lang;
		
};

struct crypto {
	
	struct keys keys;
	struct keys old_keys;
	
};

#endif /* CRYPTO_H */

