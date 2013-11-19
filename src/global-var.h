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
 * \author Victor Julien <victor@inliniac.net>
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 */

/**
#ifndef __GLOBAL_VAR_H__
#define __GLOBAL_VAR_H__

#include "flow.h"
#include "util-var.h"

// Available data types for Globalvars 

#define GLOBALVAR_TYPE_STR 1
#define GLOBALVAR_TYPE_INT 2

*/

#ifndef __GLOBAL_VAR_H__
#define __GLOBAL_VAR_H__

#define NUM_INT_VAR 10
#define NUM_STR_VAR 10

//Global Variable - Type int
extern int globalInt[NUM_INT_VAR];

//Global Variable - Type char*
extern char* globalStr[NUM_STR_VAR];

void GlobalVarInit();
int GlobalIntSet(int,int);
int GlobalIntGet(int);
int GlobalStrSet(int,char*);
char* GlobalStrGet(int);
void GlobalVarFree();

#endif __GLOBAL_VAR_H__

/**
// Struct used to hold the string data type for globalvars *
typedef struct GlobalVarTypeStr {
    uint8_t *value;
    uint16_t value_len;
} GlobalVarTypeStr;

// Struct used to hold the integer data type for globalvars *
typedef struct GlobalVarTypeInt_ {
    uint32_t value;
} GlobalVarTypeInt;

// Generic Globalvar Structure 
typedef struct 	GlobalVar_ {
   // uint8_t type;      //  no type for global var --DETECT_FLOWVAR in this case 
    GenericVar *next;    //List of next global variables
    uint16_t idx;       // name idx 
    uint8_t datatype;
    union {
        GlobalVarTypeStr gbv_str;
        GlobalVarTypeInt gbv_int;
    } data;

} FlowVar;

*/

/** Globalvar Interface API */

//Vivek - remove flow from these function parameters
/**
void GlobalVarAddStrNoLock(Flow *, uint16_t, uint8_t *, uint16_t);
void GlobalVarAddStr(Flow *, uint16_t, uint8_t *, uint16_t);
void GlobalVarAddIntNoLock(Flow *, uint16_t, uint32_t);
void GlobalVarAddInt(Flow *, uint16_t, uint32_t);
GlobalVar *GlobalVarGet(Flow *, uint16_t);
void GlobalVarFree(GlobalVar *);
void GlobalVarPrint(GenericVar *);

#endif //  __GLOBAL_VAR_H__ 
*/

