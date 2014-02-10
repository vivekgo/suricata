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
 * Support for Global Adhoc HashMap for redirection heuristic
 */

#include "global-hashmap-redirection.h"

redirectsHashMap* RedirectsMap = NULL;

/**
  * /brief Returns 1 if sourceIp is present as key in RedirectsMap else 0
  * /parameter sourceIP
  */
int find_key_redirectsHashMap(char* srcIp) {
    redirectsHashMap* map = NULL;
    HASH_FIND(hh2,RedirectsMap,srcIp,7,map);
    return map ? 1 : 0 ;	
}

/**
  * /brief Returns 1 if location is present in the LocationMap (HashMap) as key for a particular entry in RedirectsMap for a soruceIP
  * /brief Returns 0 if location is not present but sourceIP is present as a key in RedirectsMap, -1 if sourceIP is not present as key in RedirectsMap
  * /parameters sourceIP, location
  */
int find_location_redirectsHashMap(char* srcIp, char* location) {
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

/**
 * /brief Adds location entry to LocationMap(HashMap) for particular sourceIP 
 * /paramters sourceIP, destinationIP, location, redirectionType
 */
void add_location_redirectsHashMap(char* srcIp, char* dstIp, char* location, char* redirectType) {
    redirectsHashMap* map = NULL;
    locationHashMap* locationmap = NULL;
    int location_len = strlen(location);
    HASH_FIND(hh2,RedirectsMap,srcIp,7,map);
    if(map) {
        HASH_FIND(hh3,map->LocationMap,location,strlen(location),locationmap);
        if(!locationmap) {
            locationmap = (locationHashMap*)malloc(sizeof(locationHashMap));
            if(!locationmap) {
                printf("Error: global-hashmap-redirection.c add_location_redirectsHashMap : malloc error \n");
            }
            else {
                locationmap->location_key = (char*)malloc(location_len*sizeof(char));
                locationmap->dstIp = (char*)malloc(7*sizeof(char));
                locationmap->type_redirect = (char*)malloc(4*sizeof(char));
                if(locationmap->location_key == NULL || locationmap->type_redirect == NULL || locationmap->dstIp == NULL) {
                    printf("Error: global-hashmap-redirection.c add_location_redirectsHashMap : malloc error \n");
                }
                else {
                    strncpy(locationmap->location_key,location,location_len);
                    strncpy(locationmap->dstIp,dstIp,7);
                    strncpy(locationmap->type_redirect,redirectType,4);
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
            printf("Error: global-hashmap-redirection.c add_location_redirectsHashMap : malloc error \n");
        }
        else {
            locationmap->location_key = (char*)malloc(location_len*sizeof(char));
            locationmap->dstIp = (char*)malloc(7*sizeof(char));
            locationmap->type_redirect = (char*)malloc(4*sizeof(char));
            if(locationmap->location_key == NULL || locationmap->type_redirect == NULL || locationmap->dstIp == NULL) {
                    printf("Error: global-hashmap-redirection.c add_location_redirectsHashMap : malloc error \n");
            }
            else {
                strncpy(locationmap->location_key,location,location_len);
                strncpy(locationmap->dstIp,dstIp,7);
                strncpy(locationmap->type_redirect,redirectType,4);
                locationmap->count = 0;
                strncpy(map->srcip_key,srcIp,7);
                map->LocationMap = NULL;
                HASH_ADD(hh2,RedirectsMap,srcip_key,7,map);
                HASH_ADD_KEYPTR(hh3,map->LocationMap,locationmap->location_key,location_len,locationmap);
            }
        }
    }
}

/**
 * /brief Increments count for all locationmaps of the given srcIp
 * /brief Returns the number of urls which crossed the threshold, -1 if srcIp is not present 
 * /brief If a url crosses threshold deletes it from the hashmap and logs information.
*/
int increase_locationcount_redirectsHashMap(char* srcIp, int threshold) {
    redirectsHashMap* map = NULL;
    locationHashMap *locationmap, *tmp;
    int count = 0;
    HASH_FIND(hh2,RedirectsMap,srcIp,7,map);
    if(map) {
        HASH_ITER(hh3,map->LocationMap, locationmap,tmp) {
            locationmap->count = locationmap->count + 1;
            if(locationmap->count > threshold) {
               printf("Alert_13: Redirection SrcIp: %hhu.%hhu.%hhu.%hhu Location: %s Type: %s \n",srcIp[0],srcIp[2],srcIp[4],srcIp[6],locationmap->location_key, locationmap->type_redirect);
               HASH_DELETE(hh3,map->LocationMap,locationmap);
               printf("Before Free : increase_locationcount_redirectsHashMap \n");
               free(locationmap->location_key);
               free(locationmap->dstIp);
               free(locationmap->type_redirect);
               free(locationmap);
               printf("After Free : increase_locationcount_redirectsHashMap \n");
                count++;
            }
        }
        return count;
    }
    else
        return -1;
}

/**
  * /brief Returns number of redirections not followed for a particular srcIP entry in RedirectsMap, -1 if srcIP is not present in RedirectsMap
  *
  */
int get_redirectcount_redirectsHashMap(char* srcIp) {
    redirectsHashMap* map = NULL;
    HASH_FIND(hh2,RedirectsMap,srcIp,7,map);
    if(map)
        return HASH_CNT(hh3,map->LocationMap);
    else
	return -1;
}

/**
  * /brief Returns number of different requests after the redirection, -1 if location is not present as a key or srcIP is not present as a key
  *
  */
int get_count_location_redirectsHashMap(char* srcIp, char* location) {
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

/**
  * /brief Removes location key from LocationMap of the given srcIP
  *
  */
void remove_location_redirectsHashMap(char* srcIp, char* location) {
    redirectsHashMap* map = NULL;
    locationHashMap* locationmap = NULL;
    HASH_FIND(hh2,RedirectsMap,srcIp,7,map);
    if(map) {
        HASH_FIND(hh3,map->LocationMap, location, strlen(location),locationmap);
        if(locationmap) {
        	HASH_DELETE(hh3,map->LocationMap,locationmap);
                printf("Before Free : remove_location_redirectsHashMap\n");
                free(locationmap->location_key);
               free(locationmap->dstIp);
               free(locationmap->type_redirect);
                 free(locationmap);
                printf("After Free : remove_location_redirectsHashMap\n");
        }
    }
}

/**
  * /brief Removes entry for the given srcIP from RedirectsMap
  *
  */
void delete_record_redirectsHashMap(char* srcIp) {
    redirectsHashMap* map = NULL;
    locationHashMap *locationmap, *tmp;
    HASH_FIND(hh2,RedirectsMap, srcIp, 7, map);
    if(map) {
        HASH_ITER(hh3,map->LocationMap, locationmap,tmp) {
            HASH_DELETE(hh3,map->LocationMap,locationmap);
               free(locationmap->location_key);
               free(locationmap->dstIp);
               free(locationmap->type_redirect);
            free(locationmap);
        }
        HASH_DELETE(hh2,RedirectsMap,map);
        printf("Before Free : delete_record_redirectsHashMap\n");
        free(map->LocationMap);
        free(map);
        printf("After Free : delete_record_redirectsHashMap \n");
    }
}

void TempRaiseAlertHeuristic10(){
	// iterate over redirectsHashMap go over all srcIps and print alerts
        redirectsHashMap *map, *tmp_map;
        locationHashMap *locationmap,*tmp_locationmap;
        HASH_ITER(hh2,RedirectsMap,map,tmp_map){
            if(map) {
                HASH_ITER(hh3,map->LocationMap,locationmap,tmp_locationmap){
                    printf("Alert_13: Redirection SrcIp: %hhu.%hhu.%hhu.%hhu  RedirectType: %s Location %s \n",map->srcip_key[0],map->srcip_key[2],map->srcip_key[4],map->srcip_key[6],locationmap->type_redirect,locationmap->location_key);
                }
            }
        }
}
