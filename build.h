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

#ifndef BUILD_H
#define BUILD_H

#define SSH_VERSION		0x00000001
#define SSH_VERSION_STR		"DMA-SSH-alpa_v0.0.0.1"

#define SSH_DEFS                _NO_MMU_DEF " "

#ifdef _NO_MMU	
#define _NO_MMU_DEF		"+NO_MMU"
#else
#define	_NO_MMU_DEF		"-NO_MMU"
#endif

#endif /* BUILD_H */

