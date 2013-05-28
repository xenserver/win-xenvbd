/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 * 
 * *   Redistributions of source code must retain the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer in the documentation and/or other 
 *     materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 */ 

#ifndef _XENVBD_ASSERT_H
#define _XENVBD_ASSERT_H

#include <ntddk.h>

#include "debug.h"

static FORCEINLINE VOID
__BugCheck(
    __in  ULONG       Code,
    __in_opt ULONG_PTR   Parameter1,
    __in_opt ULONG_PTR   Parameter2,
    __in_opt ULONG_PTR   Parameter3,
    __in_opt ULONG_PTR   Parameter4
    )
{
#pragma prefast(suppress:28159)
    KeBugCheckEx(Code,
                 Parameter1,
                 Parameter2,
                 Parameter3,
                 Parameter4);
}

#define ASSERTION_FAILURE   0x0000DEAD


#define BUG(_TEXT)                                              \
        do {                                                    \
            const CHAR  *_Text = (_TEXT);                       \
            const CHAR  *_File = __FILE__;                      \
            ULONG       _Line = __LINE__;                       \
                                                                \
            Error("BUG: " _TEXT "\n");                          \
            __BugCheck(ASSERTION_FAILURE,                       \
                       (ULONG_PTR)_Text,                        \
                       (ULONG_PTR)_File,                        \
                       (ULONG_PTR)_Line,                        \
                       0);                                      \
        } while (FALSE)

#define BUG_MSG(_TEXT1, _TEXT2)                                 \
        do {                                                    \
            const CHAR  *_Text1 = (_TEXT1);                     \
            const CHAR  *_Text2 = (_TEXT2);                     \
            const CHAR  *_File = __FILE__;                      \
            ULONG       _Line = __LINE__;                       \
                                                                \
            Error("BUG: " _TEXT1 " %s\n", _Text2);              \
            __BugCheck(ASSERTION_FAILURE,                       \
                       (ULONG_PTR)_Text1,                       \
                       (ULONG_PTR)_File,                        \
                       (ULONG_PTR)_Line,                        \
                       (ULONG_PTR)_Text2);                      \
        } while (FALSE)

#define BUG_ON(_EXP)                           \
        if (_EXP) BUG(#_EXP)

#define BUG_ON_MSG(_EXP, _TEXT)                \
        if (_EXP) BUG_MSG(#_EXP, _TEXT)

#if DBG

#define __NT_ASSERT(_EXP)                                       \
        ((!(_EXP)) ?                                            \
        (Error("ASSERTION FAILED: " #_EXP "\n"),                \
         __annotation(L"Debug", L"AssertFail", L#_EXP),         \
         DbgRaiseAssertionFailure(), FALSE) :                   \
        TRUE)

#define __NT_ASSERT_MSG(_EXP, _TEXT)                            \
        ((!(_EXP)) ?                                            \
        (Error("ASSERTION FAILED: " #_EXP " " #_TEXT "\n"),     \
         __annotation(L"Debug", L"AssertFail", L#_EXP),         \
         DbgRaiseAssertionFailure(), FALSE) :                   \
        TRUE)

#define __ASSERT(_EXP)              __NT_ASSERT(_EXP)
#define __ASSERT_MSG(_EXP, _TEXT)   __NT_ASSERT_MSG(_EXP, _TEXT)

#else   // DBG

#define __ASSERT(_EXP)              BUG_ON(!(_EXP))
#define __ASSERT_MSG(_EXP, _TEXT)   BUG_ON_MSG(!(_EXP), _TEXT)

#endif  // DBG

#undef  ASSERT

#define ASSERT(_EXP)                    \
        do {                            \
            __ASSERT(_EXP);             \
            __analysis_assume(_EXP);    \
        } while (FALSE)

#define ASSERT_MSG(_EXP, _TEXT)         \
        do {                            \
            __ASSERT_MSG(_EXP, _TEXT);  \
            __analysis_assume(_EXP);    \
        } while (FALSE)

#define ASSERT3U(_X, _OP, _Y)                       \
        do {                                        \
            ULONGLONG   _Lval = (ULONGLONG)(_X);    \
            ULONGLONG   _Rval = (ULONGLONG)(_Y);    \
            if (!(_Lval _OP _Rval)) {               \
                Error("%s = %llu\n", #_X, _Lval);   \
                Error("%s = %llu\n", #_Y, _Rval);   \
                ASSERT(_X _OP _Y);                  \
            }                                       \
        } while (FALSE)

#define ASSERT3S(_X, _OP, _Y)                       \
        do {                                        \
            LONGLONG    _Lval = (LONGLONG)(_X);     \
            LONGLONG    _Rval = (LONGLONG)(_Y);     \
            if (!(_Lval _OP _Rval)) {               \
                Error("%s = %lld\n", #_X, _Lval);   \
                Error("%s = %lld\n", #_Y, _Rval);   \
                ASSERT(_X _OP _Y);                  \
            }                                       \
        } while (FALSE)

#define ASSERT3P(_X, _OP, _Y)                       \
        do {                                        \
            PVOID   _Lval = (PVOID)(_X);            \
            PVOID   _Rval = (PVOID)(_Y);            \
            if (!(_Lval _OP _Rval)) {               \
                Error("%s = %p\n", #_X, _Lval);     \
                Error("%s = %p\n", #_Y, _Rval);     \
                ASSERT(_X _OP _Y);                  \
            }                                       \
        } while (FALSE)

#define ASSERTREFCOUNT(_X, _OP, _Y, _Z)             \
        do {                                        \
            LONG    _L = (LONG)(_X);                \
            LONG    _R = (LONG)(_Y);                \
            if (!(_L _OP _R)) {                     \
                Error("%s:%s = %d\n", (_Z), #_X, _L); \
                Error("%s:%s = %d\n", (_Z), #_Y, _R); \
                ASSERT_MSG(_X _OP _Y, (_Z));        \
            }                                       \
        } while (FALSE)

#ifndef TEST_MEMORY
#define TEST_MEMORY DBG
#endif

#if TEST_MEMORY

__checkReturn
static __inline BOOLEAN
_IsZeroMemory(
    __in const PCHAR Caller,
    __in const PCHAR Name,
    __in PVOID       Buffer,
    __in ULONG       Length
    )
{
    ULONG           Offset;

    Offset = 0;
    while (Offset < Length) {
        if (*((PUCHAR)Buffer + Offset) != 0) {
            Error("%s: non-zero byte in %s (0x%p+0x%x)\n", Caller, Name, Buffer, Offset);
            return FALSE;
        }
        Offset++;
    }

    return TRUE;
}

#define IsZeroMemory(_Buffer, _Length) \
        _IsZeroMemory(__FUNCTION__, #_Buffer, (_Buffer), (_Length))

#else   // TEST_MEMORY

#define IsZeroMemory(_Buffer, _Length)  TRUE

#endif  // TEST_MEMORY

#define IMPLY(_X, _Y)   (!(_X) || (_Y))
#define EQUIV(_X, _Y)   (IMPLY((_X), (_Y)) && IMPLY((_Y), (_X)))

#endif  // _XENVBD_ASSERT_H

