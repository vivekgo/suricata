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


#ifndef __GLOBAL_HASHMAP_H__
#define __GLOBAL_HASHMAP_H__

#define MAX_NUM_IP 3

#include "uthash.h"
#include "util-bloomfilter.h"

/*Hash Table for locations for a particular srcIp */
typedef struct {
    char* location_key; //key
    char* type_redirect; //301,302,303,307,308
    int count;
    UT_hash_handle hh3;
} locationHashMap;

/*Hash Table for 302/303 redirects host+uri and srcIp */
typedef struct {
    char srcip_key[7]; //key
    locationHashMap* LocationMap;
    UT_hash_handle hh2;
} redirectsHashMap;

extern redirectsHashMap* RedirectsMap;

/* HashMap for URI_LIST alongwith IPs - restricted to 3 IP associated with a URI */
typedef struct {
    char* uri_key; //key = uri
    int count;
    char* ip[MAX_NUM_IP];
    UT_hash_handle hh1;
} adhocHashMapURI;

/* HashMap - srcIp as key and two bloomfilters to store dstip and uri, as well as another hashmap of URIs */
typedef struct {
    char srcip_key[7]; //key = srcIp
    BloomFilter* BF_DST_IP;
    BloomFilter* BF_URI;
    adhocHashMapURI* URI_LIST;
    UT_hash_handle hh;
} adhocHashMap;

//Global HashMap
extern adhocHashMap* IP_BFS;

/*
Functions for adhocHashMap(IP_BFS)
*/
int find_key(char*);
int find_dst_ip_In_BF_DSTIP(char*,char*);/*parameters: (srcIp,dstIp) */
int find_uri_In_BF_URI(char*,char*); /*parameters: (srcIp,uri) */
int find_uri_In_URI_List(char*,char*,char*); /*parameters: (srcIp,dstIp,uri) */

void add_to_both_BF(char*,char*,char*);/*parameters: (srcIp,dstIp,uri) */
void add_to_BF_DSTIP(char*,char*);/*parameters: (srcIp,dstIp) */
void add_to_BF_URI(char*,char*);/*parameters: (srcIp,uri) */

int update_URI_List(char*,char*,char*);/*parameters: (srcIp,dstIp,uri) */
int get_ipcount_from_URI_List(char*,char*);
char* get_info_from_URI_List(char*,char*);/*parameters: (srcIp,uri) */
void remove_uri_from_URI_List(char*,char*);/*parameters: (srcIp,uri) */

void delete_record(char*);/*parameter: srcIp */


/*
Functions for redirectsHashMap(RedirectsMap)
*/
int find_key_redirectsHashMap(char*);
int find_location_redirectsHashMap(char*,char*);/* parameters : (srcIp,location) */

void add_location_redirectsHashMap(char*,char*,char*);/* parameters : (srcIp,location) */

int get_redirectcount_redirectsHashMap(char*);/*parameter: srcIp */
int get_count_location_redirectsHashMap(char*,char*);/* parameters : (srcIp,location) */

void remove_location_redirectsHashMap(char*,char*);/* parameters : (srcIp,location) */
void delete_record_redirectsHashMap(char*);/* parameter : srcIp */

#endif


