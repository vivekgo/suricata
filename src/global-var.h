/* Copyright (C) 2007-2013 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 * \author Vivek Goswami <vivekgoswami10@gmail.com>
 */


#ifndef __GLOBAL_VAR_H__
#define __GLOBAL_VAR_H__


#define NUM_INT_VAR 15
#define NUM_STR_VAR 15

//Global Variable - Type int
extern int globalInt[NUM_INT_VAR];

//Global Variable - Type char*
extern char* globalStr[NUM_STR_VAR];

void GlobalVarInit();
int GlobalIntSet(int,int);
int GlobalIntGet(int);
int GlobalStrSet(int,char*);
char* GlobalStrGet(int);
void GlobalStrFree(int);
void GlobalVarFree();

#endif

