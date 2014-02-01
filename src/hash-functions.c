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
 * Hash functions - for util-bloomfilter.c
 */

#include "hash-functions.h"

#include<string.h>
#include<stdlib.h>
#include<stdio.h>
#include<math.h>


/*Hash Function for Bloom Filter
-Jenkin one at a time hash function
FP probability = (1-e^(-n/m))
where n = number of elements inserted in Bloom Filter
m = size of bitarray
*/

struct {
    uint32_t (*hash)(uint8_t *key, uint16_t len);
} hashfn_map[] = {
      { JHash },
      { RSHash },
      { JSHash },
      { PJWHash },
      { ELFHash },
      { BKDRHash },
      { SDBMHash },
      { DJBHash },
      { DEKHash },
      { FNVHash },
    }; 


uint32_t BloomFilterHashFn(void *data, uint16_t datalen, uint8_t iter, uint32_t hash_size) {
    uint32_t hash;
    uint8_t *str = (uint8_t*)data;
    if(iter >=0 && iter <= 9) 
    	hash = hashfn_map[iter].hash(str,datalen);
    else {
        printf("Error: hash-functions.c : BloomFilterHashFn iter < 0 or > 9 \n");
        return 0;
    }
    hash %= hash_size;
    return hash;
}


uint32_t JHash(uint8_t* str, uint16_t len)
{
    uint32_t hash;
    uint16_t i = 0;
    for(hash = i = 0; i < len; ++i)
    {
        hash += (uint32_t)*str++;
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}
/* Jenkin Hash Function */

uint32_t RSHash(uint8_t* str, uint16_t len)
{
   uint32_t b    = 378551;
   uint32_t a    = 63689;
   uint32_t hash = 0;
   uint16_t i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = hash * a + (*str);
      a    = a * b;
   }

   return hash;
}
/* End Of RS Hash Function */


uint32_t JSHash(uint8_t* str, uint16_t len)
{
   uint32_t hash = 1315423911;
   uint16_t i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash ^= ((hash << 5) + (*str) + (hash >> 2));
   }

   return hash;
}
/* End Of JS Hash Function */

uint32_t PJWHash(uint8_t* str, uint16_t len)
{
   const uint32_t BitsInUnsignedInt = (uint32_t)(sizeof(uint32_t) * 8);
   const uint32_t ThreeQuarters     = (uint32_t)((BitsInUnsignedInt  * 3) / 4);
   const uint32_t OneEighth         = (uint32_t)(BitsInUnsignedInt / 8);
   const uint32_t HighBits          = (uint32_t)(0xFFFFFFFF) << (BitsInUnsignedInt - OneEighth);
   uint32_t hash              = 0;
   uint32_t test              = 0;
   uint16_t i                 = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = (hash << OneEighth) + (*str);

      if((test = hash & HighBits)  != 0)
      {
         hash = (( hash ^ (test >> ThreeQuarters)) & (~HighBits));
      }
   }

   return hash;
}
/* End Of  P. J. Weinberger Hash Function */

uint32_t ELFHash(uint8_t* str, uint16_t len)
{
   uint32_t hash = 0;
   uint32_t x    = 0;
   uint16_t i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = (hash << 4) + (*str);
      if((x = hash & 0xF0000000L) != 0)
      {
         hash ^= (x >> 24);
      }
      hash &= ~x;
   }

   return hash;
}
/* End Of ELF Hash Function */

uint32_t BKDRHash(uint8_t* str, uint16_t len)
{
   uint32_t seed = 131; /* 31 131 1313 13131 131313 etc.. */
   uint32_t hash = 0;
   uint16_t i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = (hash * seed) + (*str);
   }

   return hash;
}
/* End Of BKDR Hash Function */

uint32_t SDBMHash(uint8_t* str, uint16_t len)
{
   uint32_t hash = 0;
   uint16_t i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = (*str) + (hash << 6) + (hash << 16) - hash;
   }

   return hash;
}
/* End Of SDBM Hash Function */

uint32_t DJBHash(uint8_t* str, uint16_t len)
{
   uint32_t hash = 5381;
   uint16_t i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = ((hash << 5) + hash) + (*str);
   }

   return hash;
}
/* End Of DJB Hash Function */

uint32_t DEKHash(uint8_t* str, uint16_t len)
{
   uint32_t hash = len;
   uint16_t i    = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash = ((hash << 5) ^ (hash >> 27)) ^ (*str);
   }
   return hash;
}
/* End Of DEK Hash Function */

uint32_t FNVHash(uint8_t* str, uint16_t len)
{
   const uint32_t fnv_prime = 0x811C9DC5;
   uint32_t hash      = 0;
   uint16_t i         = 0;

   for(i = 0; i < len; str++, i++)
   {
      hash *= fnv_prime;
      hash ^= (*str);
   }

   return hash;
}
/* End Of FNV Hash Function */





