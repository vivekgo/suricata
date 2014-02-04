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
 * Support for Adhoc Global Hashmaps and bloom-filters for repetition heuristics
 */


#ifndef __GLOBAL_HASHMAP_REPETITION_H__
#define __GLOBAL_HASHMAP_REPETITION_H__

#define MAX_NUM_IP 3

#include<string.h>
#include<stdlib.h>
#include<stdio.h>
#include<math.h>
#include "uthash.h"
#include "util-bloomfilter.h"
#include "hash-functions.h"

/**
 * Hash Map for URI_LIST
 * Key: Uri String
 * Value: Count (Number of entries), IPs[], Hosts[]
 */
typedef struct {
    char* uri_key;
    int count;
    char* ip[MAX_NUM_IP];
    char* host[MAX_NUM_IP];
    UT_hash_handle hh1;
} adhocHashMapURI;

/**
 * Hash Map of srcIP, associated bloomfilters for dstIP and uri and hashmap of uri_list
 * Key: SourceIP
 * Value: BF_DST_IP(BloomFilter for dstIPs), BF_URI(BloomFilter for URIs), BF_PAIR_DSTIP_URI(BloomFilter for dstIp concatenated with uri string), HashMap of Uri_List
 * bf_ip_count(Number of entries in BF_DST_IP), bf_uri_count(Number of entries in BF_URI), bf_pair_count(Number of entries in BF_PAIR_DSTIP_URI)
 */
typedef struct {
    char srcip_key[7];
    BloomFilter* BF_PAIR_DSTIP_URI;
    BloomFilter* BF_DST_IP;
    BloomFilter* BF_URI;
    int bf_ip_count;
    int bf_uri_count;
    int bf_pair_count;
    adhocHashMapURI* URI_LIST;
    UT_hash_handle hh;
} adhocHashMap;

/* Global HashMap of type adhocHashMap for repetition heuristic */
extern adhocHashMap* IP_BFS;

/* Functions for adhocHashMap(IP_BFS) */
int find_key(char*);
int find_dst_ip_In_BF_DSTIP(char*,char*);
int find_uri_In_BF_URI(char*,char*); 
int find_uri_In_URI_List(char*,char*,char*); 
int find_pair_In_BF_PAIR_DSTIP_URI(char*,char*,char*);
int add_to_both_BF(char*,char*,char*);
void add_to_pairBF(char*,char*,char*);
void add_to_BF_DSTIP(char*,char*);
void add_to_BF_URI(char*,char*);
int update_URI_List(char*,char*,char*,char*);
int get_ipcount_from_URI_List(char*,char*);
char* get_info_from_URI_List(char*,char*);
void log_info_from_URI_List(char*,char*);
void remove_uri_from_URI_List(char*,char*);
void refresh_bloomfilters(char*,double);
void delete_record(char*);

#endif


