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
 * Support for Adhoc Bloomfilter - for any heuristic using blacklisted tlds as part of heurisitic
 */

#include "global-bloomfilter.h"


BloomFilter* globalBloomFilter = NULL;
int globalBloomFilterCount;



void add_to_globalBloomFilter(char* host) {
    if(!globalBloomFilter) {
        globalBloomFilter = (BloomFilter*)malloc(sizeof(BloomFilter));
        globalBloomFilter = BloomFilterInit(256*1024,10,BloomFilterHashFn);
    }
    if(globalBloomFilter) {
        BloomFilterAdd(globalBloomFilter, host, strlen(host));
        globalBloomFilterCount += 1;
    }
}

/**
 * /brief Returns 1 if host is present in globalBloomFilter, 0 otherwise
 *
 */
int present_in_globalBloomFilter(char* host) {
    if(globalBloomFilter)
        return BloomFilterTest(globalBloomFilter,host,strlen(host)) ? 1 : 0;
    else
        return 0;
}

void refresh_globalBloomFilter(double threshold) {
    int size_bf = 262144;
    double n_by_m_gbf = -(globalBloomFilterCount/size_bf);
    double fp_rate_gbf = 1 - exp(n_by_m_gbf);
    if(fp_rate_gbf >= threshold) {
        BloomFilterFree(globalBloomFilter);
        globalBloomFilter = (BloomFilter*)malloc(sizeof(BloomFilter));
        globalBloomFilter = BloomFilterInit(256*1024,10,BloomFilterHashFn);
    }
}

