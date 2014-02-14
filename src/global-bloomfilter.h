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
 *
 * Support for Adhoc Bloomfilter - for any heuristic using blacklisted tlds as part of heurisitic
 */


#ifndef __GLOBAL_BLOOMFILTER_H__
#define __GLOBAL_BLOOMFILTER_H__


#include<string.h>
#include<stdlib.h>
#include<stdio.h>
#include<math.h>
#include "util-bloomfilter.h"
#include "hash-functions.h"

/**
 * Adhoc BloomFilter with init variable to determine initialization
 *
 *
typedef struct {
    BloomFilter* GlobalBloomFilter;
    int count;
} globalBloomFilter;
*/
/* Global BloomFilter of type globalBloomFilter */
extern BloomFilter* globalBloomFilter;
extern int globalBloomFilterCount;

/* Functions for GlobalBloomFilter */
void add_to_globalBloomFilter(char*);
int present_in_globalBloomFilter(char*);
void refresh_globalBloomFilter(double);

#endif


