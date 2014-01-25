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
 */

/**
 * \file
 *
 * \author Vivek Goswami <vivekgoswami10@gmail.com>
 *
 * Global HashMap - adhoc support for "similar requests heuristic"
 */

#include "global-hashmap.h"

#include<string.h>
#include<stdlib.h>
#include<stdio.h>
#include<math.h>

adhocHashMap* IP_BFS = NULL;
redirectsHashMap* RedirectsMap = NULL;

/*Hash Function for Bloom Filter
-Jenkin one at a time hash function
FP probability = (1-e^(-n/m))
where n = number of elements inserted in Bloom Filter
m = size of bitarray
*/ 
static uint32_t BloomFilterHashFn(void *data, uint16_t datalen, uint8_t iter, uint32_t hash_size) {
    uint32_t hash, i;
    uint8_t *d = (uint8_t*)data;
    for(hash = i = 0; i < datalen; ++i)
    {
        hash += (uint32_t)*d++;
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    hash %= hash_size;
    return hash; 
}


int find_key(char* srcIp){
    adhocHashMap* map = NULL;
    HASH_FIND_STR(IP_BFS,srcIp,map);
    return map ? 1 : 0 ;
}

/*
Assumption - srcIP exists as key
returns 1 if exist else 0 error -1
*/
int find_dst_ip_In_BF_DSTIP(char* srcIp, char* dstIp){
     adhocHashMap* map = NULL;
     HASH_FIND_STR(IP_BFS,srcIp,map);
     if(!map) {
         printf("------------Error: global-hashmap.c - find_dst_ip_In_BF_DSTIP - Application Level should take care of this----------------------------\n");
         return -1;
     }
     else {
         if(BloomFilterTest(map->BF_DST_IP,dstIp,strlen(dstIp)))
		return 1;
         else
                return 0;
     }
}

/*
Assumption - srcIP exists as key
returns 1 if exist else 0 error -1
*/
int find_uri_In_BF_URI(char* srcIp, char* uri){
     adhocHashMap* map = NULL;
     HASH_FIND_STR(IP_BFS,srcIp,map);
     if(!map) {
         printf("------------Error: global-hashmap.c - find_uri_In_BF_URI - Application Level should take care of this----------------------------\n");
         return -1;
     }
     else {
         if(BloomFilterTest(map->BF_URI,uri,strlen(uri)))
                return 1;
         else
                return 0;
     }
}

/*
Assumption - srcIP exists as key
returns 1 if exist else 0 error -1
*/
/*
int find_uri_In_URI_List(char* srcIp, char*,char*){
}
*/

/*
-Create a new key with the given srcIp
-Application checks if this srcIp is present as a key or not
-If this key is not present - then only this function is called.
*/
void add_to_both_BF(char* srcIp, char* dstIp, char* uri){
        adhocHashMap* map = NULL;
        HASH_FIND_STR(IP_BFS,srcIp,map);
        if(!map) {
	   map = (adhocHashMap*)malloc(sizeof(adhocHashMap));
           if(map){
		strncpy(map->srcip_key,srcIp,7);
		map->BF_DST_IP = (BloomFilter*)malloc(sizeof(BloomFilter));
                map->BF_URI = (BloomFilter*)malloc(sizeof(BloomFilter));
                if(map->BF_DST_IP && map->BF_URI) {
		    map->BF_DST_IP = BloomFilterInit(256*1024,1,BloomFilterHashFn);
		    BloomFilterAdd(map->BF_DST_IP,dstIp,strlen(dstIp));

		    map->BF_URI = BloomFilterInit(256*1024,1,BloomFilterHashFn);
		    BloomFilterAdd(map->BF_URI,uri,strlen(uri));

		    map->URI_LIST = NULL;
        
               	    map->bf_ip_count = 1;
        	    map->bf_uri_count = 1;
		    HASH_ADD_STR(IP_BFS,srcip_key,map);
                }
                else {
                    printf("-------------Malloc Error: global-hashmap.c - add_to_both_BF() for malloc of BloomFilters-------------------------\n");
                }
           }
           else {
               printf("-------------Malloc Error: global-hashmap.c - add_to_both_BF() for malloc of adhocHashMap-------------------------\n");
           }
        }
        else {
            BloomFilterAdd(map->BF_DST_IP,dstIp,strlen(dstIp));
            BloomFilterAdd(map->BF_URI,uri,strlen(uri));
            map->bf_ip_count = map->bf_ip_count + 1;
            map->bf_uri_count = map->bf_uri_count + 1;
        }
}

/*
-srcIp already exists as a key and update the BF_DST_IP with the given dstIp
*/
void add_to_BF_DSTIP(char* srcIp, char* dstIp){
    adhocHashMap* map = NULL;
    HASH_FIND_STR(IP_BFS,srcIp,map);
    if(map) {
        BloomFilterAdd(map->BF_DST_IP,dstIp,strlen(dstIp));
        map->bf_ip_count = map->bf_ip_count + 1;
    }
    else {
        printf("-----------------Error: global-hashmap.c - add_to_BF_DSTIP - Application Level should guarantee that srcIp is present as a key already---------------- \n");
    }
}

/*
-srcIp already exists as a key and update the BF_URI with the given uri
*/
void add_to_BF_URI(char* srcIp, char* uri){
    adhocHashMap* map = NULL;
    HASH_FIND_STR(IP_BFS,srcIp,map);
    if(map) {
        BloomFilterAdd(map->BF_URI,uri,strlen(uri));
        map->bf_uri_count = map->bf_uri_count + 1;
    }
    else {
        printf("-----------------Error: global-hashmap.c - add_to_BF_URI - Application Level should guarantee that srcIp is present as a key already---------------- \n");
    }
}

/*
-Assumption: srcIp already present as a key
-Updates uri_list with the new ip and returns the count
- Returns 
value of count
-1 for error
Other Int for length of IP_List for that particular URI
*/
int update_URI_List(char* srcIp, char* dstIp, char* uri,char* host) {
    adhocHashMap* map = NULL;
    HASH_FIND_STR(IP_BFS,srcIp,map);
    if(map) {
        int host_len = strlen(host);
        adhocHashMapURI* new_item = NULL;
        HASH_FIND(hh1,map->URI_LIST,uri,strlen(uri),new_item);
        if(new_item == NULL) {
            new_item = (adhocHashMapURI*)malloc(sizeof(adhocHashMapURI));
            if(new_item == NULL) {
                 printf("------------------------Malloc Error: global-hashmap.c : update_URI_List - call for adhocHashMapURI failed \n");
                 return -1;
            }
            else {
                new_item->uri_key = (char*)malloc(strlen(uri)*sizeof(char));
                if(new_item->uri_key == NULL) {
                    printf("---------------Malloc Error: global-hashmap.c : update_URI_List - call for uri_key failed \n");
                    return -1;
                }
                else {
                    strncpy(new_item->uri_key,uri,strlen(uri));
                    new_item->count = 1;
                    new_item->ip[0] = (char*)malloc(7*sizeof(char));
                    new_item->host[0] = (char*)malloc(host_len*sizeof(char));
                    if(new_item->ip[0] != NULL && new_item->host[0] != NULL) {
                        strncpy(new_item->ip[0],dstIp,7);
                        strncpy(new_item->host[0],host,host_len);
                    }
                    else {
                        printf("------------------Malloc Error: global-hashmap.c : update_URI_List -  call for new_item->ip[0] or new_item->host[0] failed.\n");
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
            int ip_already_present = 0;
            for(i = 0; i < count; i++) {
                if(!(strncmp(dstIp,new_item->ip[i],7))) {
                    ip_already_present = 1;
                    break;
                }
            }
            if(!ip_already_present) {
                new_item->ip[count] = (char*)malloc(7*sizeof(char));
                new_item->host[count] = (char*)malloc(host_len*sizeof(char));
                if(new_item->ip[count] != NULL && new_item->host[count] != NULL) {
                        strncpy(new_item->ip[count],dstIp,7);
                        strncpy(new_item->host[count],host,host_len);
                }
                else {
                        printf("------------------Malloc Error: global-hashmap.c : update_URI_List -  call for new_item->ip[count] or new_item->host[count] failed.\n");
                        return -1;
                }
                count++;
                new_item->count = count;
            }
            return count;
        }
    }
    else {
        printf("-----------------Error:  global-hashmap.c : update_URI_List---------------- \n");
        return -1;
    }
}

/*
-Assumption srcIp is already present as a key
- Returns
-1 -in case uri is not present in URI_LIST
count - in case uri is present
*/
int get_ipcount_from_URI_List(char* srcIp, char* uri){
     adhocHashMap* map = NULL;
     HASH_FIND_STR(IP_BFS,srcIp,map);
     if(!map) {
        printf("-------Error: global-hashmap.c - get_ipcount_from_URI_List----------------\n");
        return -1;
     }
     else {
         adhocHashMapURI* urimap = NULL;
         HASH_FIND(hh1,map->URI_LIST,uri,strlen(uri),urimap);
         if(!urimap) {
             printf("-------Error: global-hashmap.c - get_ipcount_from_URI_List----------------\n");
             return -1;
         }
         else {
             return urimap->count;
         }
     }
}

/* Assumption srcIP exists as a key and uri exists in URI_LIST
returns 
- On success -a char pointer with all ips concatenated by uri
- else NULL
*/
char* get_info_from_URI_List(char* srcIp, char* uri){
     char* return_str = NULL;
     adhocHashMap* map = NULL;
     HASH_FIND_STR(IP_BFS,srcIp,map);
     if(!map) {
	printf("-------Error: global-hashmap.c - get_info_from_URI_List----------------\n");
        return NULL;
     }
     else {
         adhocHashMapURI* urimap = NULL;
         HASH_FIND(hh1,map->URI_LIST,uri,strlen(uri),urimap);
         if(!urimap) {
             printf("-------Error: global-hashmap.c - get_info_from_URI_List----------------\n");
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

/* Assumption srcIP exists as a key and uri exists in URI_LIST
- Logs Info
*/
void log_info_from_URI_List(char* srcIp, char* uri) {
     adhocHashMap* map = NULL;
     HASH_FIND_STR(IP_BFS,srcIp,map);
     if(!map) {
        printf("-------Error: global-hashmap.c : log_info_from_URI_List()----------------\n");
     }
     else {
         adhocHashMapURI* urimap = NULL;
         HASH_FIND(hh1,map->URI_LIST,uri,strlen(uri),urimap);
         if(!urimap) {
             printf("-----Error: global-hashmap.c : log_info_from_URI_List()-------------------\n");
         }
         else {
             int i;
             printf("----------------------------------------------\n");
             printf("SrcIP: %hhu.%hhu.%hhu.%hhu \n ", srcIp[0],srcIp[2],srcIp[4],srcIp[6]);

             for(i=0; i < urimap->count; i++) {
                 printf("DstIP[%d]: %hhu.%hhu.%hhu.%hhu Host: %s \n ",i, (urimap->ip[i])[0],(urimap->ip[i])[2], (urimap->ip[i])[4], (urimap->ip[i])[6], urimap->host[i]);
             }
             printf("Uri: %s \n",urimap->uri_key);
         }
     }
}


/*
empty bloom filters when the false positive rate is greater than the parameter
*/
void refresh_bloomfilters(char* srcIp,double threshold) {
    adhocHashMap* map = NULL;
    HASH_FIND_STR(IP_BFS,srcIp,map);
    if(map) {
        int size_bf = 262144;
        double n_by_m_bf_ip = -(map->bf_ip_count/size_bf);
        double n_by_m_bf_uri = -(map->bf_uri_count/size_bf);
        double fp_rate_bf_ip = 1 - exp(n_by_m_bf_ip);
        double fp_rate_bf_uri = 1 - exp(n_by_m_bf_uri);
        if(fp_rate_bf_ip >= threshold) {
            BloomFilterFree(map->BF_DST_IP);
            map->BF_DST_IP = (BloomFilter*)malloc(sizeof(BloomFilter));
            map->BF_DST_IP = BloomFilterInit(256*1024,1,BloomFilterHashFn);
        }
        if(fp_rate_bf_uri >= threshold) {
            BloomFilterFree(map->BF_URI);
            map->BF_URI = (BloomFilter*)malloc(sizeof(BloomFilter));
            map->BF_URI = BloomFilterInit(256*1024,1,BloomFilterHashFn);
        }
    }
}

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

/*
Functions for redirectsHashMap(RedirectsMap)
*/
int find_key_redirectsHashMap(char* srcIp){
    redirectsHashMap* map = NULL;
    HASH_FIND(hh2,RedirectsMap,srcIp,7,map);
    return map ? 1 : 0 ;	
}

int find_location_redirectsHashMap(char* srcIp, char* location){
    redirectsHashMap* map = NULL;
    HASH_FIND(hh2,RedirectsMap,srcIp,7,map);
    if(map) {
        locationHashMap* locationmap = NULL;
        HASH_FIND(hh3,map->LocationMap,location,strlen(location),locationmap);
        return locationmap ? 1 : 0 ;
    }
    else
        return -1;
}

void add_location_redirectsHashMap(char* srcIp, char* dstIp, char* location, char* redirectType) {
    redirectsHashMap* map = NULL;
    locationHashMap* locationmap = NULL;
    int location_len = strlen(location);
   // printf("Recieved srcIp: %s dstIp: %s location: %s redirectType: %s \n",srcIp,dstIp,location,redirectType);
    HASH_FIND(hh2,RedirectsMap,srcIp,7,map);
    if(map) {
        HASH_FIND(hh3,map->LocationMap,location,strlen(location),locationmap);
        if(!locationmap) {
     //       printf("Creating new locationmap for this location \n"); 
            locationmap = (locationHashMap*)malloc(sizeof(locationHashMap));
            if(!locationmap) {
                printf("------------------Malloc Error: global-hashmap.c - add_location_redirectsHashMap-----------------");
            }
            else {
                locationmap->location_key = (char*)malloc(location_len*sizeof(char));
                locationmap->dstIp = (char*)malloc(7*sizeof(char));
                locationmap->type_redirect = (char*)malloc(3*sizeof(char));
                if(locationmap->location_key == NULL || locationmap->type_redirect == NULL || locationmap->dstIp == NULL) {
                    printf("------------------Malloc Error: global-hashmap.c - add_location_redirectsHashMap----------------------------------");
                }
                else {
                    strncpy(locationmap->location_key,location,location_len);
                    strncpy(locationmap->dstIp,dstIp,7);
                    strncpy(locationmap->type_redirect,redirectType,3);
                    locationmap->count = 0;
                    HASH_ADD_KEYPTR(hh3,map->LocationMap,locationmap->location_key,location_len,locationmap);
                }
            }
        }

    }
    else {
        map = (redirectsHashMap*)malloc(sizeof(redirectsHashMap));
        locationmap = (locationHashMap*)malloc(sizeof(locationHashMap));
        if(map == NULL || locationmap == NULL) {
            printf("------------------Malloc Error: global-hashmap.c - add_location_redirectsHashMap----------------------------------");
        }
        else {
            locationmap->location_key = (char*)malloc(location_len*sizeof(char));
            locationmap->dstIp = (char*)malloc(7*sizeof(char));
            locationmap->type_redirect = (char*)malloc(3*sizeof(char));
            if(locationmap->location_key == NULL || locationmap->type_redirect == NULL || locationmap->dstIp == NULL) {
                    printf("------------------Malloc Error: global-hashmap.c - add_location_redirectsHashMap----------------------------------");
            }
            else {
                strncpy(locationmap->location_key,location,location_len);
                strncpy(locationmap->dstIp,dstIp,7);
                strncpy(locationmap->type_redirect,redirectType,3);
                locationmap->count = 0;
                strncpy(map->srcip_key,srcIp,7);
                map->LocationMap = NULL;

                HASH_ADD(hh2,RedirectsMap,srcip_key,7,map);
                
                HASH_ADD_KEYPTR(hh3,map->LocationMap,locationmap->location_key,location_len,locationmap);

            
            
            }
        }
    }
}

/*
Increments count for all locationmaps of the given srcIp
Returns the number of urls which crossed the threshold
returns 0 if none crossed it
returns -1 if srcIp is not present

If a url crosses threshold deletes it from the hashmap and logs information.
*/
int increase_locationcount_redirectsHashMap(char* srcIp, int threshold)
{
    redirectsHashMap* map = NULL;
    locationHashMap *locationmap, *tmp;
    int count = 0;
    HASH_FIND(hh2,RedirectsMap,srcIp,7,map);
    if(map) {
        HASH_ITER(hh3,map->LocationMap, locationmap,tmp){
            locationmap->count = locationmap->count + 1;
            if(locationmap->count > threshold) {
               printf("----------------------------------------------------------\n");
               printf("SrcIp: %hhu.%hhu.%hhu.%hhu  \n",srcIp[0],srcIp[2],srcIp[4],srcIp[6]);
               printf("Location: %s Type: %s \n",locationmap->location_key, locationmap->type_redirect);
               HASH_DELETE(hh3,map->LocationMap,locationmap);
               free(locationmap);
               count++;
            }
        }
        return count;
    }
    else
        return -1;
}

int get_redirectcount_redirectsHashMap(char* srcIp)
{
    redirectsHashMap* map = NULL;
    HASH_FIND(hh2,RedirectsMap,srcIp,7,map);
    if(map)
        return HASH_CNT(hh3,map->LocationMap);
    else
	return -1;
}

int get_count_location_redirectsHashMap(char* srcIp, char* location)
{
    redirectsHashMap* map = NULL;
    locationHashMap* locationmap = NULL;
    HASH_FIND(hh2,RedirectsMap,srcIp,7,map);
    if(map) {
    	HASH_FIND(hh3,map->LocationMap,location,strlen(location),locationmap);
        if(locationmap)
		return locationmap->count;
        else
		return -1;
    }
    else
    	return -1;
}

void remove_location_redirectsHashMap(char* srcIp, char* location)
{
    redirectsHashMap* map = NULL;
    locationHashMap* locationmap = NULL;
    HASH_FIND(hh2,RedirectsMap,srcIp,7,map);
    if(map) {
        HASH_FIND(hh3,map->LocationMap, location, strlen(location),locationmap);
        if(locationmap) {
        	HASH_DELETE(hh3,map->LocationMap,locationmap);
                free(locationmap);
        }
    }
}
void delete_record_redirectsHashMap(char* srcIp)
{
    redirectsHashMap* map = NULL;
    locationHashMap *locationmap, *tmp;
    HASH_FIND(hh2,RedirectsMap, srcIp, 7, map);
    if(map) {
        HASH_ITER(hh3,map->LocationMap, locationmap,tmp){
            HASH_DELETE(hh3,map->LocationMap,locationmap);
            free(locationmap);
        }
        HASH_DELETE(hh2,RedirectsMap,map);
        free(map);
    }
}

void TempRaiseAlertHeuristic10(){
	// iterate over redirectsHashMap go over all srcIps and print alerts
        redirectsHashMap *map, *tmp_map;
        locationHashMap *locationmap,*tmp_locationmap;
        HASH_ITER(hh2,RedirectsMap,map,tmp_map){
            if(map) {
                HASH_ITER(hh3,map->LocationMap,locationmap,tmp_locationmap){
                    printf("Alert_10: SrcIp: %s RedirectType: %s Location %s \n",map->srcip_key,locationmap->type_redirect,locationmap->location_key);
                }
            }
        }
}
