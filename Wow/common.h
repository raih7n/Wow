#pragma once

#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <spdlog/spdlog.h>

#define PHNT_VERSION PHNT_THRESHOLD
#include <phnt_windows.h>
#include <phnt.h>
#include <ntpsapi.h>
#include <ntrtl.h>
#include <ntpebteb.h>

#define EMIT(a) __asm __emit (a)
#define REX_W EMIT(0x48) __asm

#define X64_Start() \
    { \
    EMIT(0x6A) EMIT(0x33)                        /*  push   0x33             */ \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)   /*  call   $+5             */  \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(5)        /*  add    dword [esp], 5  */  \
    EMIT(0xCB)                                   /*  retf                   */  \
    }

#define X64_End() \
    { \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                  /*  call   $+5                   */  \
    EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(4) EMIT(0x23) EMIT(0) EMIT(0) EMIT(0) /*  mov    dword [rsp + 4], 0x23  */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(0xD)                                     /*  add    dword [rsp], 0xD      */  \
    EMIT(0xCB)                                                                  /*  retf                         */  \
    }


#define X64_Push(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x50 | ((r) & 7))
#define X64_Pop(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))