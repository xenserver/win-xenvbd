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

#include "log.h"
#include "driver.h"
#include "assert.h"
#include <stdio.h>

static PVOID Port12 = ((PVOID)(ULONG_PTR)0x12);

static DECLSPEC_NOINLINE VOID
LogQemuPut(
    IN  CHAR        Char
    )
{
    WRITE_PORT_UCHAR(Port12, (UCHAR)Char);
}

static DECLSPEC_NOINLINE PCHAR
LogFormatNumber(
    IN  PCHAR       Buffer,
    IN  ULONGLONG   Value,
    IN  UCHAR       Base,
    IN  BOOLEAN     UpperCase
    )
{
    ULONGLONG       Next = Value / Base;

    if (Next != 0)
        Buffer = LogFormatNumber(Buffer, Next, Base, UpperCase);

    Value %= Base;

    if (Value < 10)
        *Buffer++ = '0' + (CHAR)Value;
    else
        *Buffer++ = ((UpperCase) ? 'A' : 'a') + (CHAR)(Value - 10);

    *Buffer = '\0';

    return Buffer;
}

#define LOG_FORMAT_NUMBER(_Arguments, _Type, _Character, _Buffer)                               \
        do {                                                                                    \
            U ## _Type  _Value = va_arg((_Arguments), U ## _Type);                              \
            BOOLEAN     _UpperCase = FALSE;                                                     \
            UCHAR       _Base = 0;                                                              \
            ULONG       _Index = 0;                                                             \
                                                                                                \
            if ((_Character) == 'd' && (_Type)_Value < 0) {                                     \
                _Value = -((_Type)_Value);                                                      \
                (_Buffer)[_Index++] = '-';                                                      \
            }                                                                                   \
                                                                                                \
            switch (_Character) {                                                               \
            case 'o':                                                                           \
                _Base = 8;                                                                      \
                break;                                                                          \
                                                                                                \
            case 'd':                                                                           \
            case 'u':                                                                           \
                _Base = 10;                                                                     \
                break;                                                                          \
                                                                                                \
            case 'p':                                                                           \
            case 'X':                                                                           \
                _UpperCase = TRUE;                                                              \
                /* FALLTHRU */                                                                  \
                                                                                                \
            case 'x':                                                                           \
                _Base = 16;                                                                     \
                break;                                                                          \
            }                                                                                   \
                                                                                                \
            (VOID) LogFormatNumber(&(_Buffer)[_Index], (ULONGLONG)_Value, _Base, _UpperCase);   \
        } while (FALSE)

static DECLSPEC_NOINLINE VOID
LogVPrintf(
    IN  VOID        (*Put)(CHAR),
    IN  const CHAR  *Format,
    IN  va_list     Arguments
    )
{
    CHAR            Character;

    while ((Character = *Format++) != '\0') {
        UCHAR   Pad = 0;
        UCHAR   Long = 0;
        BOOLEAN ZeroPrefix = FALSE;
        BOOLEAN LeftJustify = FALSE;
        
        if (Character != '%') {
            Put(Character);
            continue;
        }

        Character = *Format++;
        ASSERT(Character != '\0');

        if (Character == '-') {
            LeftJustify = TRUE;
            Character = *Format++;
            ASSERT(Character != '\0');
        }

        if (isdigit((UCHAR)Character)) {
            ZeroPrefix = (Character == '0') ? TRUE : FALSE;

            while (isdigit((UCHAR)Character)) {
                Pad = (Pad * 10) + (Character - '0');
                Character = *Format++;
                ASSERT(Character != '\0');
            }
        }

        while (Character == 'l') {
            Long++;
            Character = *Format++;
            ASSERT(Character != '\0');
        }
        ASSERT3U(Long, <=, 2);

        switch (Character) {
        case 'c': {
            CHAR    Value = va_arg(Arguments, CHAR);

            Put(Value);
            break;
        }
        case 'p':
            ZeroPrefix = TRUE;
            Pad = sizeof (ULONG_PTR) * 2;
            Long = sizeof (ULONG_PTR) / sizeof (ULONG);
            /* FALLTHRU */

        case 'd':
        case 'u':
        case 'o':
        case 'x':
        case 'X': {
            CHAR    Buffer[23]; // Enough for 8 bytes in octal plus the NUL terminator
            ULONG   Length;
            ULONG   Index;

            if (Long == 2)
                LOG_FORMAT_NUMBER(Arguments, LONGLONG, Character, Buffer);
            else
                LOG_FORMAT_NUMBER(Arguments, LONG, Character, Buffer);

            Length = (ULONG)strlen(Buffer);
            while (Pad > Length) {
                Put((ZeroPrefix) ? '0' : ' ');
                --Pad;
            }
            for (Index = 0; Index < Length; Index++)
                Put(Buffer[Index]);

            break;
        }
        case 's': {
            PCHAR   Value = va_arg(Arguments, PCHAR);
            ULONG   Length;
            ULONG   Index;

            Length = (ULONG)strlen(Value);
            if (!LeftJustify) {
                while (Pad > Length) {
                    Put(' ');
                    --Pad;
                }
            }
            for (Index = 0; Index < Length; Index++)
                Put(Value[Index]);
            if (LeftJustify) {
                while (Pad > Length) {
                    Put(' ');
                    --Pad;
                }
            }

            break;
        }
        default:
            Put(Character);
            break;
        }
    }
}

static DECLSPEC_NOINLINE VOID
LogPrintf(
    IN  VOID        (*Put)(CHAR),
    IN  const CHAR  *Format,
    ...
    )
{
    va_list Args;

    va_start(Args, Format);
    LogVPrintf(Put, Format, Args);
    va_end(Args);
}

static FORCEINLINE const CHAR*
__Mode()
{
    switch (DriverGetOperatingMode()) {
    case DUMP_MODE:     return "CRASH";
    case HIBER_MODE:    return "HIBER";
    case NORMAL_MODE:   return "NORMAL";
    default:            return "UNKNOWN";
    }
}

static FORCEINLINE VOID
LogVDebug(
    IN  ULONG       Level,
    IN  const CHAR  *Module,
    IN  const CHAR  *Function,
    IN  const CHAR  *Format,
    IN  va_list     Args
    )
{
    static CHAR Buffer[256];

#pragma warning(suppress : 28719) // SDV
    sprintf(Buffer, "%s|%s|%s:", Module, __Mode(), Function);
    Buffer[255] = 0;

    vDbgPrintExWithPrefix(Buffer,
                          DPFLTR_IHVDRIVER_ID,
                          Level,
                          Format,
                          Args);
}

void
__LogMessage(
    IN  ULONG       Level,
    IN  const char* Function,
    IN  const char* Format,
    ...
    )
{
    // Note: __MODULE__ is not defined in SDV builds :(
    static const char* Module = "XENCRSH";
    va_list     Args;

    va_start(Args, Format);
    LogPrintf(LogQemuPut, "%s|%s|%s:", Module, __Mode(), Function);
    LogVPrintf(LogQemuPut, Format, Args);
    LogQemuPut('\0');
    va_end(Args);

#if DBG
    va_start(Args, Format);
    LogVDebug(Level, Module, Function, Format, Args);
    va_end(Args);
#else
    UNREFERENCED_PARAMETER(Level);
#endif
}
