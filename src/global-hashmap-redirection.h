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
 * Support for Adhoc Global Hashmaps for redirection heuristics
 */


#ifndef __GLOBAL_HASHMAP_REDIRECTION_H__
#define __GLOBAL_HASHMAP_REDIRECTION_H__

#include "uthash.h"
#include "hash-functions.h"
#include<string.h>
#include<stdlib.h>
#include<stdio.h>
#include<math.h>

/**
 * Hash Map of locations for a particular srcIp 
 * Key: Location String
 * Value: RedirectionType, DestinationIP, Count (Number of GET/POST requests from the same srcIP after this redirection)
 */
typedef struct {
    char* location_key;
    char* type_redirect;
    char* dstIp;
    int count;
    UT_hash_handle hh3;
} locationHashMap;

/**
 * Hash Map of srcIp and location information of unfollowed redirects
 * Key: SourceIP
 * Value: locationHashMap
 */
typedef struct {
    char srcip_key[8]; 
    locationHashMap* LocationMap;
    UT_hash_handle hh2;
} redirectsHashMap;

/* Global HashMap of type redirectsHashMap for redirection heuristic */
extern redirectsHashMap* RedirectsMap;

/* Functions for Global HashMap redirectsHashMap */
int find_key_redirectsHashMap(char*);
int find_location_redirectsHashMap(char*,char*);
void add_location_redirectsHashMap(char*,char*,char*,char*);
int increase_locationcount_redirectsHashMap(char*,int);
int get_redirectcount_redirectsHashMap(char*);
int get_count_location_redirectsHashMap(char*,char*);
void remove_location_redirectsHashMap(char*,char*);
void delete_record_redirectsHashMap(char*);

void TempRaiseAlertHeuristic10();
#endif


