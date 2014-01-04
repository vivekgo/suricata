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
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Functions to expose to the lua scripts.
 */

#include <string.h>
#include "suricata-common.h"
#include "conf.h"

#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-flowvar.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-print.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"

#include "stream-tcp.h"

#include "detect-luajit.h"

#include "queue.h"
#include "util-cpu.h"

//Vivek
#include "global-var.h"
#include "global-hashmap.h"

#ifdef HAVE_LUAJIT

static const char luaext_key_ld[] = "suricata:luajitdata";
static const char luaext_key_det_ctx[] = "suricata:det_ctx";
static const char luaext_key_flow[] = "suricata:flow";
static const char luaext_key_need_flow_lock[] = "suricata:need_flow_lock";

/*
Functionality added by Vivek - Support for Global Vars
Functions added:
-LuajitFreeGlobalStrvar()
-LuajitGetGlobalStrvar()
-LuajitSetGlobalStrvar()
-LuajitGetGlobalIntvar()
-LuajitSetGlobalIntvar()
*/

static void LuajitFreeGlobalStrvar(lua_State *luastate) {
    int id;
    DetectLuajitData *ld;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need flowvar idx */
    if (!lua_isnumber(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_GLOBALSTRVARS) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "global var id out of range");
        return 2;
    }
    GlobalStrFree(id);
}


static int LuajitGetGlobalStrvar(lua_State *luastate) {
    int id;
    DetectLuajitData *ld;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isnumber(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_GLOBALSTRVARS) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "global var id out of range");
        return 2;
    }

    char* globalstrvar = GlobalStrGet(id);
    if(globalstrvar == NULL) {
       lua_pushnil(luastate);
       lua_pushstring(luastate, "global string var uninitialized");
       return 2;
    }
    
    if(!strcmp(globalstrvar,"null")) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "global string var uninitialized");
        return 2;
    }    

    /* we're using a buffer sized at a multiple of 4 as lua_pushlstring generates
     * invalid read errors in valgrind otherwise. Adding in a nul to be sure.
     *
     * Buffer size = len + 1 (for nul) + whatever makes it a multiple of 4 */
    int var_len = strlen(globalstrvar);
    size_t buflen = var_len + 1 + ((var_len + 1) % 4);
    char buf[buflen];
    memset(buf, 0x00, buflen);

    memcpy(buf, globalstrvar, var_len);
    buf[var_len] = '\0';

    /* return value through luastate, as a luastring */
    lua_pushlstring(luastate, (char *)buf, buflen);

    return 1;
}

//Vivek - LuajitSetGlobalStrvar
int LuajitSetGlobalStrvar(lua_State *luastate) {
    int id;
    const char *str;
    int len;
    char *buffer;
    DetectEngineThreadCtx *det_ctx;
    DetectLuajitData *ld;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need det_ctx */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_det_ctx);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    det_ctx = lua_touserdata(luastate, -1);
    SCLogDebug("det_ctx %p", det_ctx);
    if (det_ctx == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no det_ctx");
        return 2;
    }
    
    if (!lua_isnumber(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_GLOBALSTRVARS) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "global str var id out of range");
        return 2;
    }

    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    str = lua_tostring(luastate, 2);
    if (str == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    if (!lua_isnumber(luastate, 3)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "3rd arg not a number");
        return 2;
    }
    len = lua_tonumber(luastate, 3);
    if (len < 0 || len > 0xffff) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "len out of range: max 64k");
        return 2;
    }
    SCLogDebug("Global String received %s \n",str);

    buffer = SCMalloc(len+1);
    if (unlikely(buffer == NULL)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "out of memory");
        return 2;
    }
    memcpy(buffer, str, len);
    buffer[len] = '\0';
    
    //Setting str value for particular id
    GlobalStrSet(id, buffer);

    return 0;
}


//Vivek - LuajitGetGlobalIntvar

static int LuajitGetGlobalIntvar(lua_State *luastate) {
    int id;
    DetectLuajitData *ld;
    int number;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isnumber(luastate, 1)) {
        SCLogDebug("1st arg not a number");
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_GLOBALINTVARS) {
        SCLogDebug("id %d", id);
        lua_pushnil(luastate);
        lua_pushstring(luastate, "global int var id out of range");
        return 2;
    }
    number = GlobalIntGet(id);
    lua_pushnumber(luastate, (lua_Number)number);

    return 1;
}

//Vivek - LuajitSetGlobalIntvar

int LuajitSetGlobalIntvar(lua_State *luastate) {
    int id;
    DetectEngineThreadCtx *det_ctx;
    DetectLuajitData *ld;
    int number;
    lua_Number luanumber;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need det_ctx */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_det_ctx);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    det_ctx = lua_touserdata(luastate, -1);
    SCLogDebug("det_ctx %p", det_ctx);
    if (det_ctx == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no det_ctx");
        return 2;
    }

    if (!lua_isnumber(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_GLOBALINTVARS) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "global var int id out of range");
        return 2;
    }

    if (!lua_isnumber(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a number");
        return 2;
    }
    luanumber = lua_tonumber(luastate, 2);
    if (luanumber < 0 || luanumber > (double)UINT_MAX) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "value out of range, value must be unsigned 32bit int");
        return 2;
    }
    number = (int)luanumber;

    GlobalIntSet(id, number);

    return 0;
}


static int LuajitGetFlowvar(lua_State *luastate) {
    uint16_t idx;
    int id;
    Flow *f;
    FlowVar *fv;
    DetectLuajitData *ld;
    int need_flow_lock = 0;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need flow */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_flow);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    f = lua_touserdata(luastate, -1);
    SCLogDebug("f %p", f);
    if (f == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow");
        return 2;
    }

    /* need flow lock hint */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_need_flow_lock);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    need_flow_lock = lua_toboolean(luastate, -1);

    /* need flowvar idx */
    if (!lua_isnumber(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWVARS) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowvar id out of range");
        return 2;
    }
    idx = ld->flowvar[id];
    if (idx == 0) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowvar id uninitialized");
        return 2;
    }

    /* lookup var */
    if (need_flow_lock)
        FLOWLOCK_RDLOCK(f);

    fv = FlowVarGet(f, idx);
    if (fv == NULL) {
        if (need_flow_lock)
            FLOWLOCK_UNLOCK(f);

        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow var");
        return 2;
    }

    //SCLogInfo("returning:");
    //PrintRawDataFp(stdout,fv->data.fv_str.value,fv->data.fv_str.value_len);

    /* we're using a buffer sized at a multiple of 4 as lua_pushlstring generates
     * invalid read errors in valgrind otherwise. Adding in a nul to be sure.
     *
     * Buffer size = len + 1 (for nul) + whatever makes it a multiple of 4 */
    size_t reallen = fv->data.fv_str.value_len;
    size_t buflen = fv->data.fv_str.value_len + 1 + ((fv->data.fv_str.value_len + 1) % 4);
    uint8_t buf[buflen];
    memset(buf, 0x00, buflen);
    memcpy(buf, fv->data.fv_str.value, fv->data.fv_str.value_len);
    buf[fv->data.fv_str.value_len] = '\0';

    if (need_flow_lock)
        FLOWLOCK_UNLOCK(f);

    /* return value through luastate, as a luastring */
    lua_pushlstring(luastate, (char *)buf, reallen);

    return 1;

}


int LuajitSetFlowvar(lua_State *luastate) {
    uint16_t idx;
    int id;
    Flow *f;
    const char *str;
    int len;
    uint8_t *buffer;
    DetectEngineThreadCtx *det_ctx;
    DetectLuajitData *ld;
    int need_flow_lock = 0;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need det_ctx */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_det_ctx);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    det_ctx = lua_touserdata(luastate, -1);
    SCLogDebug("det_ctx %p", det_ctx);
    if (det_ctx == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no det_ctx");
        return 2;
    }

    /* need flow */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_flow);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    f = lua_touserdata(luastate, -1);
    SCLogDebug("f %p", f);
    if (f == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow");
        return 2;
    }

    /* need flow lock hint */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_need_flow_lock);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    need_flow_lock = lua_toboolean(luastate, -1);

    /* need flowvar idx */
    if (!lua_isnumber(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWVARS) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowvar id out of range");
        return 2;
    }

    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    str = lua_tostring(luastate, 2);
    if (str == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    if (!lua_isnumber(luastate, 3)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "3rd arg not a number");
        return 2;
    }
    len = lua_tonumber(luastate, 3);
    if (len < 0 || len > 0xffff) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "len out of range: max 64k");
        return 2;
    }

    idx = ld->flowvar[id];
    if (idx == 0) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowvar id uninitialized");
        return 2;
    }

    buffer = SCMalloc(len+1);
    if (unlikely(buffer == NULL)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "out of memory");
        return 2;
    }
    memcpy(buffer, str, len);
    buffer[len] = '\0';

    if (need_flow_lock)
        FlowVarAddStr(f, idx, buffer, len);
    else
        FlowVarAddStrNoLock(f, idx, buffer, len);

    //SCLogInfo("stored:");
    //PrintRawDataFp(stdout,buffer,len);
    return 0;
}

static int LuajitGetFlowint(lua_State *luastate) {
    uint16_t idx;
    int id;
    Flow *f;
    FlowVar *fv;
    DetectLuajitData *ld;
    int need_flow_lock = 0;
    uint32_t number;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need flow */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_flow);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    f = lua_touserdata(luastate, -1);
    SCLogDebug("f %p", f);
    if (f == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow");
        return 2;
    }

    /* need flow lock hint */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_need_flow_lock);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    need_flow_lock = lua_toboolean(luastate, -1);

    /* need flowint idx */
    if (!lua_isnumber(luastate, 1)) {
        SCLogDebug("1st arg not a number");
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWINTS) {
        SCLogDebug("id %d", id);
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id out of range");
        return 2;
    }
    idx = ld->flowint[id];
    if (idx == 0) {
        SCLogDebug("idx %u", idx);
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id uninitialized");
        return 2;
    }

    /* lookup var */
    if (need_flow_lock)
        FLOWLOCK_RDLOCK(f);

    fv = FlowVarGet(f, idx);
    if (fv == NULL) {
        SCLogDebug("fv NULL");
        if (need_flow_lock)
            FLOWLOCK_UNLOCK(f);

        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow var");
        return 2;
    }
    number = fv->data.fv_int.value;

    if (need_flow_lock)
        FLOWLOCK_UNLOCK(f);

    /* return value through luastate, as a luanumber */
    lua_pushnumber(luastate, (lua_Number)number);
    SCLogDebug("retrieved flow:%p idx:%u value:%u", f, idx, number);

    return 1;

}

int LuajitSetFlowint(lua_State *luastate) {
    uint16_t idx;
    int id;
    Flow *f;
    DetectEngineThreadCtx *det_ctx;
    DetectLuajitData *ld;
    int need_flow_lock = 0;
    uint32_t number;
    lua_Number luanumber;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need det_ctx */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_det_ctx);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    det_ctx = lua_touserdata(luastate, -1);
    SCLogDebug("det_ctx %p", det_ctx);
    if (det_ctx == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no det_ctx");
        return 2;
    }

    /* need flow */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_flow);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    f = lua_touserdata(luastate, -1);
    SCLogDebug("f %p", f);
    if (f == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow");
        return 2;
    }
    /* need flow lock hint */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_need_flow_lock);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    need_flow_lock = lua_toboolean(luastate, -1);

    /* need flowint idx */
    if (!lua_isnumber(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWVARS) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id out of range");
        return 2;
    }

    if (!lua_isnumber(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a number");
        return 2;
    }
    luanumber = lua_tonumber(luastate, 2);
    if (luanumber < 0 || id > (double)UINT_MAX) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "value out of range, value must be unsigned 32bit int");
        return 2;
    }
    number = (uint32_t)luanumber;

    idx = ld->flowint[id];
    if (idx == 0) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id uninitialized");
        return 2;
    }

    if (need_flow_lock)
        FlowVarAddInt(f, idx, number);
    else
        FlowVarAddIntNoLock(f, idx, number);

    SCLogDebug("stored flow:%p idx:%u value:%u", f, idx, number);
    return 0;
}

static int LuajitIncrFlowint(lua_State *luastate) {
    uint16_t idx;
    int id;
    Flow *f;
    FlowVar *fv;
    DetectLuajitData *ld;
    int need_flow_lock = 0;
    uint32_t number;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need flow */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_flow);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    f = lua_touserdata(luastate, -1);
    SCLogDebug("f %p", f);
    if (f == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow");
        return 2;
    }

    /* need flow lock hint */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_need_flow_lock);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    need_flow_lock = lua_toboolean(luastate, -1);

    /* need flowint idx */
    if (!lua_isnumber(luastate, 1)) {
        SCLogDebug("1st arg not a number");
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWINTS) {
        SCLogDebug("id %d", id);
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id out of range");
        return 2;
    }
    idx = ld->flowint[id];
    if (idx == 0) {
        SCLogDebug("idx %u", idx);
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id uninitialized");
        return 2;
    }

    /* lookup var */
    if (need_flow_lock)
        FLOWLOCK_RDLOCK(f);

    fv = FlowVarGet(f, idx);
    if (fv == NULL) {
        number = 1;
    } else {
        number = fv->data.fv_int.value;
        if (number < UINT_MAX)
            number++;
    }
    FlowVarAddIntNoLock(f, idx, number);

    if (need_flow_lock)
        FLOWLOCK_UNLOCK(f);

    /* return value through luastate, as a luanumber */
    lua_pushnumber(luastate, (lua_Number)number);
    SCLogDebug("incremented flow:%p idx:%u value:%u", f, idx, number);

    return 1;

}

static int LuajitDecrFlowint(lua_State *luastate) {
    uint16_t idx;
    int id;
    Flow *f;
    FlowVar *fv;
    DetectLuajitData *ld;
    int need_flow_lock = 0;
    uint32_t number;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need flow */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_flow);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    f = lua_touserdata(luastate, -1);
    SCLogDebug("f %p", f);
    if (f == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow");
        return 2;
    }

    /* need flow lock hint */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_need_flow_lock);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    need_flow_lock = lua_toboolean(luastate, -1);

    /* need flowint idx */
    if (!lua_isnumber(luastate, 1)) {
        SCLogDebug("1st arg not a number");
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWINTS) {
        SCLogDebug("id %d", id);
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id out of range");
        return 2;
    }
    idx = ld->flowint[id];
    if (idx == 0) {
        SCLogDebug("idx %u", idx);
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id uninitialized");
        return 2;
    }

    /* lookup var */
    if (need_flow_lock)
        FLOWLOCK_RDLOCK(f);

    fv = FlowVarGet(f, idx);
    if (fv == NULL) {
        number = 0;
    } else {
        number = fv->data.fv_int.value;
        if (number > 0)
            number--;
    }
    FlowVarAddIntNoLock(f, idx, number);

    if (need_flow_lock)
        FLOWLOCK_UNLOCK(f);

    /* return value through luastate, as a luanumber */
    lua_pushnumber(luastate, (lua_Number)number);
    SCLogDebug("decremented flow:%p idx:%u value:%u", f, idx, number);

    return 1;

}


/*
Functionality added by Vivek - Support for Global HashMap
Functions added:
-LuajitHashMapFindKey
-LuajitHashMapFindDstIp
-LuajitHashMapAddBoth
-LuajitHashMapAddDstIp
-LuajitHashMapAddUri
-LuajitUpdateUriList
-LuajitGetIpCountUriList
-LuajitGetInfoUriList
-LuajitHashMapDeleteRecord
*/

/*
Pushes 1 if key found else 0
*/
static int LuajitHashMapFindKey(lua_State *luastate) {
    char* srcip_key;
    DetectLuajitData *ld;
    int found;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    found = find_key(srcip_key);
    lua_pushnumber(luastate, (lua_Number)found);

    return 1;
}

/*
LuajitHashMapFindDstIp
Pushes
-1 for error
1 for found
0 for not found
*/
static int LuajitHashMapFindDstIp(lua_State *luastate) {
    char* srcip_key;
    char* dstIp;
    DetectLuajitData *ld;
    int found;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }


    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    dstIp = lua_tostring(luastate, 2);
    if (dstIp == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    found = find_dst_ip_In_BF_DSTIP(srcip_key,dstIp);
    lua_pushnumber(luastate, (lua_Number)found);

    return 1;
}



/*
LuajitHashMapFindUri
Pushes
-1 for error
1 for found
0 for not found
*/
static int LuajitHashMapFindUri(lua_State *luastate) {
    char* srcip_key;
    char* uri;
    DetectLuajitData *ld;
    int found;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }


    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    uri = lua_tostring(luastate, 2);
    if (uri == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    found = find_uri_In_BF_URI(srcip_key,uri);
    lua_pushnumber(luastate, (lua_Number)found);

    return 1;
}

/*
LuajitHashMapAddBoth

*/

static int LuajitHashMapAddBoth(lua_State *luastate) {
     char *srcip_key, *dstIp, *uri;
//    int srcip_len,dstip,len,uri_len;
//    char *buffer;
    DetectLuajitData *ld;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }
    

    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    dstIp = lua_tostring(luastate, 2);
    if (dstIp == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    if (!lua_isstring(luastate, 3)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "3rd arg not a string");
        return 2;
    }
    uri = lua_tostring(luastate, 3);
    if (uri == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

/*
    if (!lua_isnumber(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a number");
        return 2;
    }
    srcip_len = lua_tonumber(luastate, 1);
    if (id < 0 || id >= 16) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "srcip_len out of range");
        return 2;
    }
*/
/*
    buffer = SCMalloc(len+1);
    if (unlikely(buffer == NULL)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "out of memory");
        return 2;
    }
    memcpy(buffer, str, len);
    buffer[len] = '\0';
*/    
    add_to_both_BF(srcip_key,dstIp,uri);
    return 1;
}


/*
LuajitHashMapAddDstIp

*/

static int LuajitHashMapAddDstIp(lua_State *luastate) {
    char *srcip_key, *dstIp;
//    int srcip_len,dstip,len,uri_len;
//    char *buffer;
    DetectLuajitData *ld;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }
    

    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    dstIp = lua_tostring(luastate, 2);
    if (dstIp == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

/*
    if (!lua_isnumber(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a number");
        return 2;
    }
    srcip_len = lua_tonumber(luastate, 1);
    if (id < 0 || id >= 16) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "srcip_len out of range");
        return 2;
    }
*/
/*
    buffer = SCMalloc(len+1);
    if (unlikely(buffer == NULL)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "out of memory");
        return 2;
    }
    memcpy(buffer, str, len);
    buffer[len] = '\0';
*/    
    add_to_BF_DSTIP(srcip_key,dstIp);
    return 1;
}

/*
LuajitHashMapAddUri

*/

static int LuajitHashMapAddUri(lua_State *luastate) {
    char *srcip_key, *uri;
//    int srcip_len,dstip,len,uri_len;
//    char *buffer;
    DetectLuajitData *ld;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }
    
    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    uri = lua_tostring(luastate, 2);
    if (uri == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

/*
    if (!lua_isnumber(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a number");
        return 2;
    }
    srcip_len = lua_tonumber(luastate, 1);
    if (id < 0 || id >= 16) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "srcip_len out of range");
        return 2;
    }
*/
/*
    buffer = SCMalloc(len+1);
    if (unlikely(buffer == NULL)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "out of memory");
        return 2;
    }
    memcpy(buffer, str, len);
    buffer[len] = '\0';
*/    
    add_to_BF_URI(srcip_key,uri);
    return 1;
}



/*
LuajitUpdateUriList

*/

static int LuajitUpdateUriList(lua_State *luastate) {
    char *srcip_key, *dstIp, *uri;
//    int srcip_len,dstip,len,uri_len;
//    char *buffer;
    DetectLuajitData *ld;
    int count;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }
    

    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    dstIp = lua_tostring(luastate, 2);
    if (dstIp == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    if (!lua_isstring(luastate, 3)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "3rd arg not a string");
        return 2;
    }
    uri = lua_tostring(luastate, 3);
    if (uri == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

/*
    if (!lua_isnumber(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a number");
        return 2;
    }
    srcip_len = lua_tonumber(luastate, 1);
    if (id < 0 || id >= 16) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "srcip_len out of range");
        return 2;
    }
*/
/*
    buffer = SCMalloc(len+1);
    if (unlikely(buffer == NULL)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "out of memory");
        return 2;
    }
    memcpy(buffer, str, len);
    buffer[len] = '\0';
*/    
    count = update_URI_List(srcip_key,dstIp,uri);
    lua_pushnumber(luastate, (lua_Number)count);

    return 1;
   
}


/*
LuajitGetIpCountUriList

*/

static int LuajitGetIpCountUriList(lua_State *luastate) {
    char *srcip_key, *uri;
//    int srcip_len,dstip,len,uri_len;
//    char *buffer;
    DetectLuajitData *ld;
    int count;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }
    
    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    uri = lua_tostring(luastate, 2);
    if (uri == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

/*
    if (!lua_isnumber(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a number");
        return 2;
    }
    srcip_len = lua_tonumber(luastate, 1);
    if (id < 0 || id >= 16) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "srcip_len out of range");
        return 2;
    }
*/
/*
    buffer = SCMalloc(len+1);
    if (unlikely(buffer == NULL)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "out of memory");
        return 2;
    }
    memcpy(buffer, str, len);
    buffer[len] = '\0';
*/    
    count = get_ipcount_from_URI_List(srcip_key,uri);
    lua_pushnumber(luastate, (lua_Number)count);

    return 1;
}



/*
LuajitGetInfoUriList

*/

static int LuajitGetInfoUriList(lua_State *luastate) {
    char *srcip_key, *uri;
//    int srcip_len,dstip,len,uri_len;
//    char *buffer;
    DetectLuajitData *ld;


    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }
    
    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    uri = lua_tostring(luastate, 2);
    if (uri == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

/*
    if (!lua_isnumber(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a number");
        return 2;
    }
    srcip_len = lua_tonumber(luastate, 1);
    if (id < 0 || id >= 16) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "srcip_len out of range");
        return 2;
    }
*/
/*
    buffer = SCMalloc(len+1);
    if (unlikely(buffer == NULL)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "out of memory");
        return 2;
    }
    memcpy(buffer, str, len);
    buffer[len] = '\0';
*/    

    char* info = get_info_from_URI_List(srcip_key,uri);
    if(info == NULL) {
       lua_pushlstring(luastate,NULL,0);
       return 1;
    }
    else {

	    /* we're using a buffer sized at a multiple of 4 as lua_pushlstring generates
	     * invalid read errors in valgrind otherwise. Adding in a nul to be sure.
	     *
	     * Buffer size = len + 1 (for nul) + whatever makes it a multiple of 4 */
	    int var_len = strlen(info);
	    size_t buflen = var_len + 1 + ((var_len + 1) % 4);
	    char buf[buflen];
	    memset(buf, 0x00, buflen);

	    memcpy(buf, info, var_len);
	    buf[var_len] = '\0';
            printf("IN DETECT-LUAJIT-EXTENSIONS info is %s and buffer is %s \n",info,buf);
	    /* return value through luastate, as a luastring */
	    lua_pushlstring(luastate, (char *)buf, buflen);

    return 1;
    }


}


/*
LuajitHashMapDeleteRecord

*/

static int LuajitHashMapDeleteRecord(lua_State *luastate) {
    char *srcip_key;
//    int srcip_len,dstip,len,uri_len;
//    char *buffer;
    DetectLuajitData *ld;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }
    

/*
    if (!lua_isnumber(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a number");
        return 2;
    }
    srcip_len = lua_tonumber(luastate, 1);
    if (id < 0 || id >= 16) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "srcip_len out of range");
        return 2;
    }
*/
/*
    buffer = SCMalloc(len+1);
    if (unlikely(buffer == NULL)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "out of memory");
        return 2;
    }
    memcpy(buffer, str, len);
    buffer[len] = '\0';
*/    
    delete_record(srcip_key);
    
    return 1;
}


/*
Functions for RedirectHashMap
*/

/*FindKey in RedirectsMap
Pushes 1 on success
else 0
*/
static int LuajitRedirectHashMapFindKey(lua_State *luastate) {
    char* srcip_key;
    DetectLuajitData *ld;
    int found;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    found = find_key_redirectsHashMap(srcip_key);
    lua_pushnumber(luastate, (lua_Number)found);

    return 1;
}

/*
Find Location in RedirectsMap
Pushes 1 on success
0 on not found
-1 on error
*/
static int LuajitRedirectHashMapFindLocation(lua_State *luastate) {
    char* srcip_key;
    char* location;
    DetectLuajitData *ld;
    int found;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }
    
    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    location = lua_tostring(luastate, 2);
    if (location == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    found = find_location_redirectsHashMap(srcip_key,location);
    lua_pushnumber(luastate, (lua_Number)found);

    return 1;
}

/*Add Location for particular srcIp in RedirectsMap*/
static int LuajitRedirectHashMapAddLocation(lua_State *luastate) {
    char* srcip_key;
    char* dstIp;
    char* location;
    char* redirectType;
    DetectLuajitData *ld;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    dstIp = lua_tostring(luastate, 2);
    if (location == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    if (!lua_isstring(luastate, 3)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "3rd arg not a number");
        return 2;
    }
    location = lua_tostring(luastate, 3);
    if (redirectType == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    if (!lua_isstring(luastate, 4)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "3rd arg not a number");
        return 2;
    }
    redirectType = lua_tostring(luastate, 4);
    if (redirectType == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    
    add_location_redirectsHashMap(srcip_key,dstIp,location,redirectType);

    return 1;
}

/*
Increase Count
*/
static int LuajitRedirectHashMapIncreaseLocationCount(lua_State *luastate) {
    char* srcip_key;
    DetectLuajitData *ld;
    int threshold;
    int count;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }
    
    if (!lua_isnumber(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a number");
        return 2;
    }
    threshold = lua_tonumber(luastate, 2);


    count = get_redirectcount_redirectsHashMap(srcip_key,threshold);
    lua_pushnumber(luastate, (lua_Number)count);

    return 1;
}


/*
GetCount
*/
static int LuajitRedirectHashMapGetCount(lua_State *luastate) {
    char* srcip_key;
    DetectLuajitData *ld;
    int count;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    count = get_redirectcount_redirectsHashMap(srcip_key);
    lua_pushnumber(luastate, (lua_Number)count);

    return 1;
}

static int LuajitRedirectHashMapGetLocationCount(lua_State *luastate) {
    char* srcip_key;
    char* location;
    DetectLuajitData *ld;
    int count;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    location = lua_tostring(luastate, 2);
    if (location == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    count = get_count_location_redirectsHashMap(srcip_key,location);
    lua_pushnumber(luastate, (lua_Number)count);

    return 1;
}

/*Delete*/

static int LuajitRedirectHashMapDeleteLocation(lua_State *luastate) {
    char* srcip_key;
    char* location;
    DetectLuajitData *ld;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    location = lua_tostring(luastate, 2);
    if (location == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    remove_location_redirectsHashMap(srcip_key,location);

    return 1;
}

static int LuajitRedirectHashMapDeleteRecord(lua_State *luastate) {
    char* srcip_key;
    DetectLuajitData *ld;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    if (!lua_isstring(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a string");
        return 2;
    }
    srcip_key = lua_tostring(luastate, 1);
    if (srcip_key == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    delete_record_redirectsHashMap(srcip_key);

    return 1;
}







void LuajitExtensionsMatchSetup(lua_State *lua_state, DetectLuajitData *ld, DetectEngineThreadCtx *det_ctx, Flow *f, int need_flow_lock) {
    SCLogDebug("det_ctx %p, f %p", det_ctx, f);

    /* luajit keyword data */
    lua_pushlightuserdata(lua_state, (void *)&luaext_key_ld);
    lua_pushlightuserdata(lua_state, (void *)ld);
    lua_settable(lua_state, LUA_REGISTRYINDEX);

    /* detection engine thread ctx */
    lua_pushlightuserdata(lua_state, (void *)&luaext_key_det_ctx);
    lua_pushlightuserdata(lua_state, (void *)det_ctx);
    lua_settable(lua_state, LUA_REGISTRYINDEX);

    /* flow */
    lua_pushlightuserdata(lua_state, (void *)&luaext_key_flow);
    lua_pushlightuserdata(lua_state, (void *)f);
    lua_settable(lua_state, LUA_REGISTRYINDEX);

    /* flow lock status hint */
    lua_pushlightuserdata(lua_state, (void *)&luaext_key_need_flow_lock);
    lua_pushboolean(lua_state, need_flow_lock);
    lua_settable(lua_state, LUA_REGISTRYINDEX);
}

/**
 *  \brief Register Suricata Lua functions
 */
int LuajitRegisterExtensions(lua_State *lua_state) {
    lua_pushcfunction(lua_state, LuajitGetFlowvar);
    lua_setglobal(lua_state, "ScFlowvarGet");

    lua_pushcfunction(lua_state, LuajitSetFlowvar);
    lua_setglobal(lua_state, "ScFlowvarSet");

    lua_pushcfunction(lua_state, LuajitGetFlowint);
    lua_setglobal(lua_state, "ScFlowintGet");

    lua_pushcfunction(lua_state, LuajitSetFlowint);
    lua_setglobal(lua_state, "ScFlowintSet");

    lua_pushcfunction(lua_state, LuajitIncrFlowint);
    lua_setglobal(lua_state, "ScFlowintIncr");

    lua_pushcfunction(lua_state, LuajitDecrFlowint);
    lua_setglobal(lua_state, "ScFlowintDecr");

    //LuajitExtensions for Functions(GlobalVar) 
    lua_pushcfunction(lua_state, LuajitGetGlobalStrvar);
    lua_setglobal(lua_state, "ScGlobalStrGet");
    
    lua_pushcfunction(lua_state, LuajitGetGlobalIntvar);
    lua_setglobal(lua_state, "ScGlobalIntGet");
    
    lua_pushcfunction(lua_state, LuajitSetGlobalStrvar);
    lua_setglobal(lua_state, "ScGlobalStrSet");
    
    lua_pushcfunction(lua_state, LuajitSetGlobalIntvar);
    lua_setglobal(lua_state, "ScGlobalIntSet");
    
    lua_pushcfunction(lua_state, LuajitFreeGlobalStrvar);
    lua_setglobal(lua_state, "ScGlobalStrFree");

    /*
    LuajitExtensions for Functions(GlobalHashMap) 
    */
    
    /*Find */
    lua_pushcfunction(lua_state, LuajitHashMapFindKey);
    lua_setglobal(lua_state, "ScHashMapFindKey");
    
    lua_pushcfunction(lua_state, LuajitHashMapFindDstIp);
    lua_setglobal(lua_state, "ScHashMapFindDstIp");

    lua_pushcfunction(lua_state, LuajitHashMapFindUri);
    lua_setglobal(lua_state, "ScHashMapFindUri");
    
    /*Add */
    lua_pushcfunction(lua_state, LuajitHashMapAddBoth);
    lua_setglobal(lua_state, "ScHashMapAddBoth");
    
    lua_pushcfunction(lua_state, LuajitHashMapAddDstIp);
    lua_setglobal(lua_state, "ScHashMapAddDstIp");

    lua_pushcfunction(lua_state, LuajitHashMapAddUri);
    lua_setglobal(lua_state, "ScHashMapAddUri");

    /*URI_List*/
    lua_pushcfunction(lua_state, LuajitUpdateUriList);
    lua_setglobal(lua_state, "ScUpdateUriList");
    
    lua_pushcfunction(lua_state, LuajitGetIpCountUriList);
    lua_setglobal(lua_state, "ScGetIpCountUriList");
    
    lua_pushcfunction(lua_state, LuajitGetInfoUriList);
    lua_setglobal(lua_state, "ScGetInfoUriList");

    /*Delete*/
    lua_pushcfunction(lua_state, LuajitHashMapDeleteRecord);
    lua_setglobal(lua_state, "ScHashMapDeleteRecord");
 
    /*
    LuajitExtensions for Functions(RedirectsMap)
    */
    /*Find */
    lua_pushcfunction(lua_state, LuajitRedirectHashMapFindKey);
    lua_setglobal(lua_state, "ScRedirectHashMapFindKey");
    
    lua_pushcfunction(lua_state, LuajitRedirectHashMapFindLocation);
    lua_setglobal(lua_state, "ScRedirectHashMapFindLocation");
    
    /*Add*/
    lua_pushcfunction(lua_state, LuajitRedirectHashMapAddLocation);
    lua_setglobal(lua_state, "ScRedirectHashMapAddLocation");
    
    /*Increment*/
    lua_pushcfunction(lua_state, LuajitRedirectHashMapIncreaseLocationCount);
    lua_setglobal(lua_state, "ScRedirectHashMapIncreaseLocationCount");

    /*GetCount*/
    lua_pushcfunction(lua_state, LuajitRedirectHashMapGetCount);
    lua_setglobal(lua_state, "ScRedirectHashMapGetCount");

    lua_pushcfunction(lua_state, LuajitRedirectHashMapGetLocationCount);
    lua_setglobal(lua_state, "ScRedirectHashMapGetLocationCount");
    
    /*Delete*/
    lua_pushcfunction(lua_state, LuajitRedirectHashMapDeleteLocation);
    lua_setglobal(lua_state, "ScRedirectHashMapDeleteLocation");
    
    lua_pushcfunction(lua_state, LuajitRedirectHashMapDeleteRecord);
    lua_setglobal(lua_state, "ScRedirectHashMapDeleteRecord");

    return 0;
}

#endif /* HAVE_LUAJIT */
