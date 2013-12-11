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
 * \author Victor Julien <victor@inliniac.net>
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 * Global variable support for complex detection rules
 * Supported types atm are String and Integers
 */

#include "global-var.h"
#include "suricata-common.h"
#include "decode.h"

#include "util-spm.h"
#include "util-var-name.h"
#include "util-debug.h"
#include "util-print.h"

#include<string.h>
#include<malloc.h>

int globalInt[15];
char* globalStr[15];

//Called by suricata.c on startup
void GlobalVarInit() {
    //Initialize global variables of type int to 0 and assign memory for string variables of string type
    int i = 0;
    for(i=0;i<15;i++) {
        globalInt[i] = 0;
    }
}

void GlobalVarFree() {
     int i = 0;
     for(i=0;i<15;i++) {
         SCFree(globalStr[i]);
     }
}

/** GlobalIntGet returns the value of global integer variable for a valid index
In case of invalid index, currently returning 0 - need to pack it in some struct to return NULL
*/
int GlobalIntGet(int idx) {
    if(idx >=0 && idx <15)
        return globalInt[idx];
    else
        return 0;
}

char* GlobalStrGet(int idx) {
    if(idx >=0 && idx <15)
         return globalStr[idx];
    else
         return "null";
}

// 1 on success and 0 on failure
int GlobalIntSet(int idx, int value) {
    if(idx >=0 && idx <15) {
        globalInt[idx] = value;
        return 1;
    }
    else
        return 0;
}

int GlobalStrSet(int idx, char* value) {
    if(idx >=0 && idx <15) {
        globalStr[idx] = SCMalloc(strlen(value));
        memcpy(globalStr[idx],value,strlen(value));
        //printf("Allocated memory for string \n");
        return 1;
    }
    else
        return 0;
}

void GlobalStrFree(int idx) {
    SCFree(globalStr[idx]);
    globalStr[idx] = NULL;
}

/**
 // puts a new value into a globalvar 
static void GlobalVarUpdateStr(GlobalVar *gbv, uint8_t *value, uint16_t size) {
    if (gbv->data.gbv_str.value)
        SCFree(gbv->data.gbv_str.value);
    gbv->data.gbv_str.value = value;
    gbv->data.gbv_str.value_len = size;
}

//  puts a new value into a globalvar 
static void FlowVarUpdateInt(GlobalVar *gbv, uint32_t value) {
    gbv->data.gbv_int.value = value;
}

// \brief get the globalvar with index 'idx' from the global pool of variables
 
GlobalVar *GlobalVarGet(Flow *f, uint16_t idx) {
    GenericVar *gv = f->flowvar;

    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_FLOWVAR && gv->idx == idx)
            return (FlowVar *)gv;
    }

    return NULL;
}

// add a flowvar to the flow, or update it 
void FlowVarAddStrNoLock(Flow *f, uint16_t idx, uint8_t *value, uint16_t size) {
    FlowVar *fv = FlowVarGet(f, idx);
    if (fv == NULL) {
        fv = SCMalloc(sizeof(FlowVar));
        if (unlikely(fv == NULL))
            return;

        fv->type = DETECT_FLOWVAR;
        fv->datatype = FLOWVAR_TYPE_STR;
        fv->idx = idx;
        fv->data.fv_str.value = value;
        fv->data.fv_str.value_len = size;
        fv->next = NULL;

        GenericVarAppend(&f->flowvar, (GenericVar *)fv);
    } else {
        FlowVarUpdateStr(fv, value, size);
    }
}

// add a flowvar to the flow, or update it 
void FlowVarAddStr(Flow *f, uint16_t idx, uint8_t *value, uint16_t size) {
    FLOWLOCK_WRLOCK(f);
    FlowVarAddStrNoLock(f, idx, value, size);
    FLOWLOCK_UNLOCK(f);
}

// add a flowvar to the flow, or update it 
void FlowVarAddIntNoLock(Flow *f, uint16_t idx, uint32_t value) {
    FlowVar *fv = FlowVarGet(f, idx);
    if (fv == NULL) {
        fv = SCMalloc(sizeof(FlowVar));
        if (unlikely(fv == NULL))
            return;

        fv->type = DETECT_FLOWVAR;
        fv->datatype = FLOWVAR_TYPE_INT;
        fv->idx = idx;
        fv->data.fv_int.value= value;
        fv->next = NULL;

        GenericVarAppend(&f->flowvar, (GenericVar *)fv);
    } else {
        FlowVarUpdateInt(fv, value);
    }
}

// add a flowvar to the flow, or update it 
void FlowVarAddInt(Flow *f, uint16_t idx, uint32_t value) {
    FLOWLOCK_WRLOCK(f);
    FlowVarAddIntNoLock(f, idx, value);
    FLOWLOCK_UNLOCK(f);
}

void FlowVarFree(FlowVar *fv) {
    if (fv == NULL)
        return;

    if (fv->datatype == FLOWVAR_TYPE_STR) {
        if (fv->data.fv_str.value != NULL)
            SCFree(fv->data.fv_str.value);
    }
    SCFree(fv);
}

void FlowVarPrint(GenericVar *gv) {
    uint16_t u;

    if (!SCLogDebugEnabled())
        return;

    if (gv == NULL)
        return;

    if (gv->type == DETECT_FLOWVAR || gv->type == DETECT_FLOWINT) {
        FlowVar *fv = (FlowVar *)gv;

        if (fv->datatype == FLOWVAR_TYPE_STR) {
            SCLogDebug("Name idx \"%" PRIu16 "\", Value \"", fv->idx);
            for (u = 0; u < fv->data.fv_str.value_len; u++) {
                if (isprint(fv->data.fv_str.value[u]))
                    SCLogDebug("%c", fv->data.fv_str.value[u]);
                else
                    SCLogDebug("\\%02X", fv->data.fv_str.value[u]);
            }
            SCLogDebug("\", Len \"%" PRIu16 "\"\n", fv->data.fv_str.value_len);
        } else if (fv->datatype == FLOWVAR_TYPE_INT) {
            SCLogDebug("Name idx \"%" PRIu16 "\", Value \"%" PRIu32 "\"", fv->idx,
                    fv->data.fv_int.value);
        } else {
            SCLogDebug("Unknown data type at flowvars\n");
        }
    }
    FlowVarPrint(gv->next);
}
*/
