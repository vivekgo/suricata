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

#endif


