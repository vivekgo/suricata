/*
 **************************************************************************
 *                                                                        *
 *          General Purpose Hash Function Algorithms Library              *
 *                                                                        *
 * Author: Arash Partow - 2002                                            *
 * URL: http://www.partow.net                                             *
 * URL: http://www.partow.net/programming/hashfunctions/index.html        *
 *                                                                        *
 * Copyright notice:                                                      *
 * Free use of the General Purpose Hash Function Algorithms Library is    *
 * permitted under the guidelines and in accordance with the most current *
 * version of the Common Public License.                                  *
 * http://www.opensource.org/licenses/cpl1.0.php                          *
 *                                                                        *
 **************************************************************************
*/


#ifndef __HASH_FUNCTIONS_H__
#define __HASH_FUNCTIONS_H__


#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

//typedef uint32_t (*hash_function)(uint8_t*, uint16_t len);

uint32_t BloomFilterHashFn(void *data, uint16_t datalen, uint8_t iter, uint32_t hash_size);
uint32_t JHash  (uint8_t* str, uint16_t len);
uint32_t RSHash  (uint8_t* str, uint16_t len);
uint32_t JSHash  (uint8_t* str, uint16_t len);
uint32_t PJWHash (uint8_t* str, uint16_t len);
uint32_t ELFHash (uint8_t* str, uint16_t len);
uint32_t BKDRHash(uint8_t* str, uint16_t len);
uint32_t SDBMHash(uint8_t* str, uint16_t len);
uint32_t DJBHash (uint8_t* str, uint16_t len);
uint32_t DEKHash (uint8_t* str, uint16_t len);
uint32_t FNVHash (uint8_t* str, uint16_t len);





#endif
