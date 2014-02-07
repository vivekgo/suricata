/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 *

/**
 * \file
 *
 * \author Vivek Goswami <vivekgoswami10@gmail.com>
 *
 * Global HashMap - adhoc support for "similar requests heuristic"
 */

#include "global-hashmap-repetition.h"


adhocHashMap* IP_BFS = NULL;

/**
 * /brief Returns 1 if srcIP is present as key in adhocHashMap(IP_BFS)
 *
 */
int find_key(char* srcIp) {
    adhocHashMap* map = NULL;
    HASH_FIND_STR(IP_BFS,srcIp,map);
    return map ? 1 : 0 ;
}

/**
 * /brief Returns 1 if dstIP is present in BF_DST_IP for the given srcIP else returns 0
 * /brief Returns -1 if there is no entry for the given srcIP in IP_BFS
 * 
 */
int find_dst_ip_In_BF_DSTIP(char* srcIp, char* dstIp) {
     adhocHashMap* map = NULL;
     HASH_FIND_STR(IP_BFS,srcIp,map);
     if(!map) {
         printf("Error: global-hashmap-repetition.c - find_dst_ip_In_BF_DSTIP - Application Level should ensure that srcIP is present as key.\n");
         return -1;
     }
     else {
         if(BloomFilterTest(map->BF_DST_IP,dstIp,strlen(dstIp)))
		return 1;
         else
                return 0;
     }
}

/**
 * /brief Returns 1 if uri is present in BF_URI for the given srcIP else returns 0
 * /brief Returns -1 if there is no entry for the given srcIP in IP_BFS
 * 
 */
int find_uri_In_BF_URI(char* srcIp, char* uri) {
     adhocHashMap* map = NULL;
     HASH_FIND_STR(IP_BFS,srcIp,map);
     if(!map) {
         printf("Error: global-hashmap-repetition.c - find_uri_In_BF_URI - Application Level should ensure that srcIP is present as a key.\n");
         return -1;
     }
     else {
         if(BloomFilterTest(map->BF_URI,uri,strlen(uri)))
                return 1;
         else
                return 0;
     }
}

/**
 * /brief Returns 1 if dstIP:uri is present in BF_PAIR_DSTIP_URI for the given srcIP else returns 0
 * /brief Returns -1 if there is no entry for the given srcIP in IP_BFS
 * 
 */
int find_pair_In_BF_PAIR_DSTIP_URI(char* srcIp, char* dstIp, char* uri) {
     adhocHashMap* map = NULL;
     HASH_FIND_STR(IP_BFS,srcIp,map);
     if(!map) {
         printf("Error: global-hashmap-repetition.c - find_pair_In_BF_PAIR_DSTIP_URI - Application Level should ensure that srcIP is present as a key.\n");
         return -1;
     }
     else {
        int dstIp_len = strlen(dstIp);
        int uri_len = strlen(uri);
        int pair_str_len = dstIp_len + uri_len + 1;
        char* pair_str = (char*)malloc(pair_str_len*sizeof(char));
        if(pair_str) {
            memcpy(pair_str,dstIp,dstIp_len);
            memcpy(pair_str + dstIp_len,uri,uri_len + 1);
            if(BloomFilterTest(map->BF_PAIR_DSTIP_URI,pair_str,pair_str_len)) {
                return 1;
            }
            else
                return 0;
            free(pair_str);
        }
        else {
            printf("Error: global-hashmap-repetition.c - find_pair_In_BF_PAIR_DSTIP_URI  : malloc error\n");
            return -1;
        }
     }
}

/**
 * /brief Adds dstIP and uri to respective bloom filters for a given srcIP entry in IP_BFS (creates a new entry if srcIP is not present as key in IP_BFS)
 *
*/
int add_to_both_BF(char* srcIp, char* dstIp, char* uri) {
    adhocHashMap* map = NULL;
    HASH_FIND_STR(IP_BFS,srcIp,map);
    if(map == NULL) {
        map = (adhocHashMap*)malloc(sizeof(adhocHashMap));
        if(map) {
            strncpy(map->srcip_key,srcIp,8);
	    map->BF_DST_IP = (BloomFilter*)malloc(sizeof(BloomFilter));
            map->BF_URI = (BloomFilter*)malloc(sizeof(BloomFilter));
            map->BF_PAIR_DSTIP_URI = (BloomFilter*)malloc(sizeof(BloomFilter));
            if(map->BF_DST_IP && map->BF_URI && map->BF_PAIR_DSTIP_URI) {
	        map->BF_DST_IP = BloomFilterInit(256*1024,10,BloomFilterHashFn);
		BloomFilterAdd(map->BF_DST_IP,dstIp,strlen(dstIp));
	        map->BF_URI = BloomFilterInit(256*1024,10,BloomFilterHashFn);
		BloomFilterAdd(map->BF_URI,uri,strlen(uri));
                map->BF_PAIR_DSTIP_URI = BloomFilterInit(256*1024,10,BloomFilterHashFn);
		map->URI_LIST = NULL;
               	map->bf_ip_count = 1;
        	map->bf_uri_count = 1;
                map->bf_pair_count = 0;
		HASH_ADD_STR(IP_BFS,srcip_key,map);
                if(find_key(srcIp))
                    return 1;
                else
                    return 0;
            }
            else {
                printf("Error: global-hashmap-repetition.c - add_to_both_BF() :malloc error \n");
                return 0;
            }
        }
        else {
            printf("Error: global-hashmap-repetition.c - add_to_both_BF() : malloc error \n");
            return 0;
        }
    }
    else {
        BloomFilterAdd(map->BF_DST_IP,dstIp,strlen(dstIp));
        BloomFilterAdd(map->BF_URI,uri,strlen(uri));
        map->bf_ip_count = map->bf_ip_count + 1;
        map->bf_uri_count = map->bf_uri_count + 1;
        return 1;
    }
}

/**
 * /brief Adds dstIP:uri to BF_PAIR_DSTIP_URI bloom filter for a given srcIP entry in IP_BFS (assuming srcIP is present as key in IP_BFS)
 *
 */
void add_to_pairBF(char* srcIp, char* dstIp, char* uri) {
    adhocHashMap* map = NULL;
    HASH_FIND_STR(IP_BFS,srcIp,map);
    if(map) {
        int dstIp_len = strlen(dstIp);
        int uri_len = strlen(uri);
        int pair_str_len = dstIp_len + uri_len + 1;
        char* pair_str = (char*)malloc(pair_str_len*sizeof(char));
        if(pair_str) {
            memcpy(pair_str,dstIp,dstIp_len);
            memcpy(pair_str + dstIp_len,uri,uri_len + 1);
            BloomFilterAdd(map->BF_PAIR_DSTIP_URI,pair_str,pair_str_len);
            map->bf_pair_count = map->bf_pair_count + 1;
            free(pair_str);
        }
        else 
            printf("Error: global-hashmap-repetition.c - add_to_pairBF : malloc error \n");
    }
    else 
        printf("Error: global-hashmap-repetition.c - add_to_pairBF - Application Level should guarantee that srcIp is present as a key already. \n");
}

/**
 * /brief Adds dstIP to BF_DST_IP bloom filter for a given srcIP entry in IP_BFS (assuming srcIP is present as key in IP_BFS)
 *
 */
void add_to_BF_DSTIP(char* srcIp, char* dstIp) {
    adhocHashMap* map = NULL;
    HASH_FIND_STR(IP_BFS,srcIp,map);
    if(map) {
        BloomFilterAdd(map->BF_DST_IP,dstIp,strlen(dstIp));
        map->bf_ip_count = map->bf_ip_count + 1;
    }
    else
        printf("Error: global-hashmap-repetition.c - add_to_BF_DSTIP - Application Level should guarantee that srcIp is present as a key already. \n");
}

/**
 * /brief Adds uri to BF_DST_IP bloom filter for a given srcIP entry in IP_BFS (assuming srcIP is present as key in IP_BFS)
 *
 */
void add_to_BF_URI(char* srcIp, char* uri){
    adhocHashMap* map = NULL;
    HASH_FIND_STR(IP_BFS,srcIp,map);
    if(map) {
        BloomFilterAdd(map->BF_URI,uri,strlen(uri));
        map->bf_uri_count = map->bf_uri_count + 1;
    }
    else
        printf("Error: global-hashmaprepetition.c - add_to_BF_URI - Application Level should guarantee that srcIp is present as a key already. \n");
}

/**
 * /brief Updates uri_list with the new ip and returns the ip count for uri entry ( assuming srcIP is present as a key), returns -1 on error
 * 
*/
int update_URI_List(char* srcIp, char* dstIp, char* uri,char* host) {
    adhocHashMap* map = NULL;
    HASH_FIND_STR(IP_BFS,srcIp,map);
    if(map) {
        int host_len = strlen(host);
        adhocHashMapURI* new_item = NULL;
        HASH_FIND(hh1,map->URI_LIST,uri,strlen(uri),new_item);
        if(!new_item) {
            new_item = (adhocHashMapURI*)malloc(sizeof(adhocHashMapURI));
            if(!new_item) {
                 printf("Error: global-hashmap-repetition.c update_URI_List : malloc error \n");
                 return -1;
            }
            else {
                new_item->uri_key = (char*)malloc(strlen(uri)*sizeof(char));
                if(!new_item->uri_key) {
                    printf("Error: global-hashmap-repetition.c update_URI_List : malloc error \n");
                    return -1;
                }
                else {
                    strncpy(new_item->uri_key,uri,strlen(uri));
                    new_item->count = 1;
                    new_item->ip[0] = (char*)malloc(7*sizeof(char));
                    new_item->host[0] = (char*)malloc(host_len*sizeof(char));
                    if(new_item->ip[0] && new_item->host[0]) {
                        strncpy(new_item->ip[0],dstIp,7);
                        strncpy(new_item->host[0],host,host_len);
                    }
                    else {
                        printf("Error: global-hashmap-repetition.c update_URI_List : malloc error\n");
                        return -1;
                    }
                    HASH_ADD_KEYPTR(hh1,map->URI_LIST,new_item->uri_key,strlen(uri),new_item);
                    return 1;
                }
            }
        }
        else {
            int i = 0;
            int count = new_item->count;
            int ip_or_host_already_present = 0;
            for(i = 0; i < count; i++) {
                if((strncmp(dstIp,new_item->ip[i],7)==0) || (strncmp(host,new_item->host[i],strlen(host))==0) ) {
                    ip_or_host_already_present = 1;
                    break;
                }
            }
            if(!ip_or_host_already_present) {
                new_item->ip[count] = (char*)malloc(7*sizeof(char));
                new_item->host[count] = (char*)malloc(host_len*sizeof(char));
                if(new_item->ip[count] != NULL && new_item->host[count] != NULL) {
                    strncpy(new_item->ip[count],dstIp,7);
                    strncpy(new_item->host[count],host,host_len);
                }
                else {
                    printf("Error: global-hashmap-repetition.c update_URI_List : malloc error \n");
                    return -1;
                }
                count++;
                new_item->count = count;
            }
            return count;
        }
    }
    else {
        printf("Error:  global-hashmap-repetition.c update_URI_List : Application Level should guarantee presence of srcIP as key. \n");
        return -1;
    }
}

/**
 * /brief Returns ip count for uri entry in URI_LIST, -1 if uri entry is not present (assuming srcIP entry is present in IP_BFS) 
 * 
*/
int get_ipcount_from_URI_List(char* srcIp, char* uri) {
     adhocHashMap* map = NULL;
     HASH_FIND_STR(IP_BFS,srcIp,map);
     if(!map) {
        printf("-Error: global-hashmap-repetition.c - get_ipcount_from_URI_List : Application level should guarantee srcIP is present as a key. \n");
        return -1;
     }
     else {
         adhocHashMapURI* urimap = NULL;
         HASH_FIND(hh1,map->URI_LIST,uri,strlen(uri),urimap);
         if(!urimap) {
             printf("Error: global-hashmap-repetition.c - get_ipcount_from_URI_List : Application level should guarantee uri is present as a key. \n");
             return -1;
         }
         else
             return urimap->count;
     }
}

/**
 * /brief Returns string of all ips concatenated by uri else NULL for uri entry
 * 
 */
char* get_info_from_URI_List(char* srcIp, char* uri) {
     char* return_str = NULL;
     adhocHashMap* map = NULL;
     HASH_FIND_STR(IP_BFS,srcIp,map);
     if(!map) {
	printf("Error: global-hashmap-repetition.c - get_info_from_URI_List : Application level should guarantee srcIP is present as a key. \n");
        return NULL;
     }
     else {
         adhocHashMapURI* urimap = NULL;
         HASH_FIND(hh1,map->URI_LIST,uri,strlen(uri),urimap);
         if(!urimap) {
             printf("Error: global-hashmap-repetition.c - get_info_from_URI_List : Application level should guarantee uri is present as a key. \n");
             return NULL;
         }
         else {
             int i;
             int ip_count = urimap->count;
             int len_uri = strlen(urimap->uri_key);
             int len_str = len_uri + 7*ip_count;
             return_str = (char*)malloc(len_str*sizeof(char));
             memset(return_str,0x00,len_str);
             for(i=0; i<ip_count; i++)
                 memcpy(return_str + i*7,urimap->ip[i],7);
             memcpy(return_str + ip_count*7,urimap->uri_key,len_uri);
             return return_str;
         }
     }
}

/**
 * /brief Logs info - uri, dstIPs and hosts in case of alert
 *
 */
void log_info_from_URI_List(char* srcIp, char* uri) {
     adhocHashMap* map = NULL;
     HASH_FIND_STR(IP_BFS,srcIp,map);
     if(!map) {
        printf("Error: global-hashmap-repetition.c log_info_from_URI_List() : Application level should guarantee srcIP is present as a key. \n");
     }
     else {
         adhocHashMapURI* urimap = NULL;
         HASH_FIND(hh1,map->URI_LIST,uri,strlen(uri),urimap);
         if(!urimap) {
             printf("Error: global-hashmap-repetition.c log_info_from_URI_List() : Application level should guarantee uri is present as a key. \n");
         }
         else {
             int i;
             printf("SrcIP: %hhu.%hhu.%hhu.%hhu \n ", srcIp[0],srcIp[2],srcIp[4],srcIp[6]);
             for(i=0; i < urimap->count; i++)
                 printf("DstIP[%d]: %hhu.%hhu.%hhu.%hhu Host: %s \n ",i, (urimap->ip[i])[0],(urimap->ip[i])[2], (urimap->ip[i])[4], (urimap->ip[i])[6], urimap->host[i]);
             printf("Uri: %s \n",urimap->uri_key);
         }
     }
}


/**
 * /brief Refresh bloom filters when the false positive rate is greater than the parameter
 *
*/
void refresh_bloomfilters(char* srcIp, double threshold) {
    adhocHashMap* map = NULL;
    HASH_FIND_STR(IP_BFS,srcIp,map);
    if(map) {
        int size_bf = 262144;
        double n_by_m_bf_ip = -(map->bf_ip_count/size_bf);
        double n_by_m_bf_uri = -(map->bf_uri_count/size_bf);
        double n_by_m_bf_pair = -(map->bf_pair_count/size_bf);
        double fp_rate_bf_ip = 1 - exp(n_by_m_bf_ip);
        double fp_rate_bf_uri = 1 - exp(n_by_m_bf_uri);
        double fp_rate_bf_pair = 1 - exp(n_by_m_bf_pair);
        if(fp_rate_bf_ip >= threshold) {
            BloomFilterFree(map->BF_DST_IP);
            map->BF_DST_IP = (BloomFilter*)malloc(sizeof(BloomFilter));
            map->BF_DST_IP = BloomFilterInit(256*1024,10,BloomFilterHashFn);
        }
        if(fp_rate_bf_uri >= threshold) {
            BloomFilterFree(map->BF_URI);
            map->BF_URI = (BloomFilter*)malloc(sizeof(BloomFilter));
            map->BF_URI = BloomFilterInit(256*1024,10,BloomFilterHashFn);
            adhocHashMapURI *urimap, *tmp;
            HASH_ITER(hh1,map->URI_LIST,urimap,tmp) {
                HASH_DELETE(hh1,map->URI_LIST,urimap);
                free(urimap);
            }
            free(map->URI_LIST);
            map->URI_LIST = NULL;
        }
        if(fp_rate_bf_pair >= threshold) {
            BloomFilterFree(map->BF_PAIR_DSTIP_URI);
            map->BF_PAIR_DSTIP_URI = (BloomFilter*)malloc(sizeof(BloomFilter));
            map->BF_PAIR_DSTIP_URI = BloomFilterInit(256*1024,10,BloomFilterHashFn);
        }
    }
}

/**
 * /brief Removes uri entry from URI_LIST
 *
 */
void remove_uri_from_URI_List(char* srcIp, char* uri) {
    adhocHashMap* map = NULL;
    adhocHashMapURI* urimap = NULL;
    HASH_FIND_STR(IP_BFS,srcIp,map);
    if(map) {
        HASH_FIND(hh1,map->URI_LIST,uri,strlen(uri),urimap);
        if(urimap) {
            HASH_DELETE(hh1,map->URI_LIST,urimap);
            free(urimap);
        }
    }
}

/**
 * /brief Deletes srcIP entry from IP_BFS
 *
 */
void delete_record(char* srcIp) {
    adhocHashMap* map = NULL;
    HASH_FIND_STR(IP_BFS,srcIp,map);
    if(map) {
        BloomFilterFree(map->BF_DST_IP);
        BloomFilterFree(map->BF_URI);
        adhocHashMapURI *urimap, *tmp;
        HASH_ITER(hh1,map->URI_LIST,urimap,tmp) {
            HASH_DELETE(hh1,map->URI_LIST,urimap);
            free(urimap);
        }
        HASH_DEL(IP_BFS,map);
        free(map);
    }
}

