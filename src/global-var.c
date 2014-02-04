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
 * Global variables support for complex detection rules
 * Supported types atm are String and Integers
 */

#include "global-var.h"

int globalInt[NUM_INT_VAR];
char* globalStr[NUM_STR_VAR];

/**
 * /brief Initilializes array of global variables (int) globalInt to 0
 * /note call to this function by suricata.c on startup
 *
 */
void GlobalVarInit() {
    int i = 0;
    for(i = 0; i < NUM_INT_VAR; i++) {
        globalInt[i] = 0;
    }
}

/**
 * /brief Frees array of dynamically allocated global variables (string) globalStr
 * /note call to this function by suricata.c just before engine shutdown
 *
 */
void GlobalVarFree() {
     int i = 0;
     for(i = 0; i < NUM_STR_VAR; i++) {
         free(globalStr[i]);
     }
}

/** 
 * /brief Returns the value of global integer variable for a valid index, otherwise returns 0
 * 
**/
int GlobalIntGet(int idx) {
    if(idx >=0 && idx < NUM_INT_VAR)
        return globalInt[idx];
    else
        return 0;
}

/** 
 * /brief Returns the value of global string variable for a valid index, otherwise returns NULL
 * 
**/
char* GlobalStrGet(int idx) {
    if(idx >=0 && idx < NUM_STR_VAR)
         return globalStr[idx];
    else
         return NULL;
}

/** 
 * /brief Sets the value of global integer variable for a valid index, returns 1 on success 0 on failure
 * 
**/
int GlobalIntSet(int idx, int value) {
    if(idx >=0 && idx < NUM_INT_VAR) {
        globalInt[idx] = value;
        return 1;
    }
    else
        return 0;
}

/** 
 * /brief Sets the value of global string variable for a valid index, returns 1 on success 0 on failure
 *  
**/
int GlobalStrSet(int idx, char* value) {
    if(idx >=0 && idx < NUM_STR_VAR) {
        globalStr[idx] = (char*)malloc((strlen(value))*sizeof(char));
        if(globalStr[idx]) {
            strncpy(globalStr[idx],value,strlen(value));
            return 1;
        }
        else {
            printf("Error: global-var.c GlobalStrSet() : malloc error \n");
            return 0;
        }
    }
    else
        return 0;
}

/** 
 * /brief Frees dynamincally allocated memory for a particular element(index parameter) in array of global variable (string) 
 *  
**/
void GlobalStrFree(int idx) {
    free(globalStr[idx]);
    globalStr[idx] = NULL;
}

