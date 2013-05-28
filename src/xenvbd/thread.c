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

#include <ntddk.h>
#include "util.h"

#include "thread.h"
#include "debug.h"
#include "assert.h"

#define THREAD_POOL_TAG 'rhTX'

struct _XENVBD_THREAD {
    PCHAR                   Name;
    XENVBD_THREAD_FUNCTION  Function;
    PVOID                   Context;
    KEVENT                  WorkEvent;
    BOOLEAN                 Alerted;
    LONG                    References;
    PKTHREAD                Thread;
};

__checkReturn
__drv_allocatesMem(mem)
__bcount(Length)
static FORCEINLINE PVOID
#pragma warning(suppress: 28195)
___ThreadAllocate(
    __in PCHAR   Caller,
    __in ULONG   Line,
    __in ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Caller, Line, Length, THREAD_POOL_TAG);
}
#define __ThreadAllocate(Length) ___ThreadAllocate(__FUNCTION__, __LINE__, Length)

static FORCEINLINE VOID
#pragma warning(suppress: 28197)
__ThreadFree(
    __in __drv_freesMem(mem) PVOID Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer, THREAD_POOL_TAG);
}

static FORCEINLINE VOID
__ThreadWake(
    __in PXENVBD_THREAD  Thread
    )
{
    ASSERT((Thread->Thread == NULL) || (Thread->Thread != KeGetCurrentThread()));
    KeSetEvent(&Thread->WorkEvent, IO_NO_INCREMENT, FALSE);
}

VOID
ThreadWake(
    __in PXENVBD_THREAD  Thread
    )
{
    __ThreadWake(Thread);
}

static FORCEINLINE VOID
__ThreadAlert(
    __in PXENVBD_THREAD  Thread
    )
{
    Thread->Alerted = TRUE;
    __ThreadWake(Thread);
}

VOID
ThreadAlert(
    __in PXENVBD_THREAD  Thread
    )
{
    __ThreadAlert(Thread);
}

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
BOOLEAN
ThreadWait(
    __in PXENVBD_THREAD  Thread
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT((Thread->Thread == NULL) || (Thread->Thread == KeGetCurrentThread()));

    (VOID) KeWaitForSingleObject(&Thread->WorkEvent, 
                                Executive, 
                                KernelMode, 
                                FALSE, 
                                NULL);
    KeClearEvent(&Thread->WorkEvent);
    return !Thread->Alerted;
}

KSTART_ROUTINE  ThreadFunction;

VOID
ThreadFunction(
    __in PVOID       Argument
    )
{
    PXENVBD_THREAD  Self = Argument;
    NTSTATUS        status;

    status = Self->Function(Self, Self->Context);

    if (InterlockedDecrement(&Self->References) == 0) {
        Verbose("Thread %s dereferenced during thread function\n", Self->Name);
        RtlZeroMemory(Self, sizeof(XENVBD_THREAD));
        __ThreadFree(Self);
    }

    PsTerminateSystemThread(status);
    // NOT REACHED
}

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
_ThreadCreate(
    __in  PCHAR                   Name,
    __in  XENVBD_THREAD_FUNCTION  Function,
    __in_opt PVOID                Context,
    __out PXENVBD_THREAD          *_Thread
    )
{
    HANDLE                      Handle;
    NTSTATUS                    status;
    PXENVBD_THREAD              Thread;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    *_Thread = NULL;
#pragma warning(suppress: 6014)
    Thread = __ThreadAllocate(sizeof (XENVBD_THREAD));

    status = STATUS_NO_MEMORY;
    if (Thread == NULL)
        goto fail1;

    Thread->Name = Name;
    Thread->Function = Function;
    Thread->Context = Context;
    Thread->Alerted = FALSE;
    Thread->References = 2; // One for us, one for the thread function

    KeInitializeEvent(&Thread->WorkEvent, NotificationEvent, FALSE);
    
    status = PsCreateSystemThread(&Handle,
                                  STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL,
                                  NULL,
                                  NULL,
                                  NULL,
                                  ThreadFunction,
                                  Thread);
    if (!NT_SUCCESS(status)) {
        --Thread->References;    // Fake thread function termination
        goto fail2;
    }

    status = ObReferenceObjectByHandle(Handle,
                                       SYNCHRONIZE,
                                       *PsThreadType,
                                       KernelMode,
                                       &Thread->Thread,
                                       NULL);
    if (!NT_SUCCESS(status))
        goto fail3;

    ZwClose(Handle);

    *_Thread = Thread;
    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    __ThreadAlert(Thread);
    ZwClose(Handle);

fail2:
    Error("fail2\n");

    if (InterlockedDecrement(&Thread->References) == 0)
        __ThreadFree(Thread);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

PKEVENT
ThreadGetEvent(
    __in PXENVBD_THREAD  Thread
    )
{
    return &Thread->WorkEvent;
}

__checkReturn
BOOLEAN
ThreadIsAlerted(
    __in PXENVBD_THREAD  Thread
    )
{
    return Thread->Alerted;
}

__drv_maxIRQL(PASSIVE_LEVEL)
VOID
ThreadJoin(
    __in PXENVBD_THREAD  Thread
    )
{
    LONG                References;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3P(KeGetCurrentThread(), !=, Thread->Thread);

    (VOID) KeWaitForSingleObject(Thread->Thread,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);

    References = InterlockedDecrement(&Thread->References);
    ASSERT3U(References, ==, 0);

    Verbose("Thread %s Terminated\n", Thread->Name);
    RtlZeroMemory(Thread, sizeof(XENVBD_THREAD));
    __ThreadFree(Thread);
}
