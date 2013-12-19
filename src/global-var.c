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
 * Global variable support for complex detection rules
 * Supported types atm are String and Integers
 */

#include "global-var.h"
#include<string.h>
#include<stdlib.h>


int globalInt[NUM_INT_VAR];
char* globalStr[NUM_STR_VAR];

//Called by suricata.c on startup
void GlobalVarInit() {
    //Initialize global variables of type int to 0 and assign memory for string variables of string type
    int i = 0;
    for(i=0;i<NUM_INT_VAR;i++) {
        globalInt[i] = 0;
    }
}

void GlobalVarFree() {
     int i = 0;
     for(i=0;i<NUM_STR_VAR;i++) {
         free(globalStr[i]);
     }
}

/** GlobalIntGet returns the value of global integer variable for a valid index
In case of invalid index, currently returning 0 - need to pack it in some struct to return NULL
*/
int GlobalIntGet(int idx) {
    if(idx >=0 && idx < NUM_INT_VAR)
        return globalInt[idx];
    else
        return 0;
}

char* GlobalStrGet(int idx) {
    if(idx >=0 && idx < NUM_STR_VAR)
         return globalStr[idx];
    else
         return "null";
}

// 1 on success and 0 on failure
int GlobalIntSet(int idx, int value) {
    if(idx >=0 && idx < NUM_INT_VAR) {
        globalInt[idx] = value;
        return 1;
    }
    else
        return 0;
}

int GlobalStrSet(int idx, char* value) {
    if(idx >=0 && idx < NUM_STR_VAR) {
        globalStr[idx] = (char*)malloc((strlen(value))*sizeof(char));
        strncpy(globalStr[idx],value,strlen(value));
        //printf("Allocated memory for string \n");
        return 1;
    }
    else
        return 0;
}

void GlobalStrFree(int idx) {
    free(globalStr[idx]);
    globalStr[idx] = NULL;
}

