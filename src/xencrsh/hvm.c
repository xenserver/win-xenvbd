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

#include <wdm.h>
#include "..\..\include\xenvbd-storport.h"


#include "..\..\include\xen-version.h"
#include "..\..\include\xen\xen-compat.h"

#include "..\..\include\xen-warnings.h"
#include "..\..\include\xen-types.h"
#include "..\..\include\xen-errno.h"
#include "..\..\include\xen\xen-compat.h"
#include "..\..\include\xen\memory.h"
#include "..\..\include\xen\hvm\params.h"

#include "hvm.h"
#include "hypercall.h"

#include "log.h"
#include "assert.h"

#define MAXIMUM_HYPERCALL_PFN_COUNT 2

#pragma code_seg("hypercall")
__declspec(allocate("hypercall"))
static UCHAR    __HypercallSection[(MAXIMUM_HYPERCALL_PFN_COUNT + 1) * PAGE_SIZE];

#define XEN_SIGNATURE   "XenVMMXenVMM"

static ULONG            __BaseLeaf = 0x40000000;
static USHORT           __MajorVersion;
static USHORT           __MinorVersion;
static PFN_NUMBER       __Pfn[MAXIMUM_HYPERCALL_PFN_COUNT];
static ULONG            __PfnCount;

PHYPERCALL_GATE         Hypercall;

//#pragma code_seg("sharedinfo")
//__declspec(allocate("sharedinfo"))
//static UCHAR    __SharedInfoSection[(1 + 1) * PAGE_SIZE];
//
//PVOID                   SharedInfo;

extern PHYSICAL_ADDRESS MmGetPhysicalAddress(IN PVOID  BaseAddress);

static FORCEINLINE NTSTATUS
MemoryOp(
    IN  ULONG       Command,
    IN  PVOID       Argument
    )
{
    LONG_PTR ret;
    NTSTATUS Status;

    ret = Hypercall2(LONG_PTR, memory_op, Command, Argument);
    if (ret < 0) {
        ERRNO_TO_STATUS(-ret, Status);
        goto fail;
    }

    return STATUS_SUCCESS;

fail:
    return Status;
}

static FORCEINLINE VOID
CpuId(
    IN  ULONG   Leaf,
    OUT PULONG  EAX OPTIONAL,
    OUT PULONG  EBX OPTIONAL,
    OUT PULONG  ECX OPTIONAL,
    OUT PULONG  EDX OPTIONAL
    )
{
    ULONG       Value[4] = {0};

    __cpuid(Value, Leaf);

    if (EAX)
        *EAX = Value[0];

    if (EBX)
        *EBX = Value[1];

    if (ECX)
        *ECX = Value[2];

    if (EDX)
        *EDX = Value[3];
}

static FORCEINLINE NTSTATUS
__InitHypercallPage()
{
    ULONG   eax = 'DEAD';
    ULONG   ebx = 'DEAD';
    ULONG   ecx = 'DEAD';
    ULONG   edx = 'DEAD';
    ULONG   Index;
    ULONG   HypercallMsr;

    NTSTATUS    Status;

    Status = STATUS_UNSUCCESSFUL;
    for (;;) {
        CHAR Signature[13] = { 0 };

        CpuId(__BaseLeaf, &eax, &ebx, &ecx, &edx);
        *((PULONG)(Signature + 0)) = ebx;
        *((PULONG)(Signature + 4)) = ecx;
        *((PULONG)(Signature + 8)) = edx;

        if (strcmp(Signature, XEN_SIGNATURE) == 0 &&
            eax >= __BaseLeaf + 2)
            break;

        __BaseLeaf += 0x100;

        if (__BaseLeaf > 0x40000100)
            goto fail1;
    }

    CpuId(__BaseLeaf + 1, &eax, NULL, NULL, NULL);
    __MajorVersion = (USHORT)(eax >> 16);
    __MinorVersion = (USHORT)(eax & 0xFFFF);

    LogVerbose("XEN %d.%d\n", __MajorVersion, __MinorVersion);
    LogVerbose("INTERFACE 0x%08x\n", __XEN_INTERFACE_VERSION__);

    if ((ULONG_PTR)__HypercallSection & (PAGE_SIZE - 1))
        Hypercall = (PVOID)(((ULONG_PTR)__HypercallSection + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
    else
        Hypercall = (PVOID)__HypercallSection;

    ASSERT3U(((ULONG_PTR)Hypercall & (PAGE_SIZE - 1)), ==, 0);

    for (Index = 0; Index < MAXIMUM_HYPERCALL_PFN_COUNT; Index++) {
        PHYSICAL_ADDRESS    PhysicalAddress;

        PhysicalAddress = MmGetPhysicalAddress((PUCHAR)Hypercall + (Index << PAGE_SHIFT));
        __Pfn[Index] = (PFN_NUMBER)(PhysicalAddress.QuadPart >> PAGE_SHIFT);
    }

    CpuId(__BaseLeaf + 2, &eax, &ebx, NULL, NULL);
    __PfnCount = eax;
    ASSERT(__PfnCount <= MAXIMUM_HYPERCALL_PFN_COUNT);
    HypercallMsr = ebx;

    for (Index = 0; Index < __PfnCount; Index++) {
        LogVerbose("HypercallPfn[%d]: %p\n", Index, (PVOID)__Pfn[Index]);
        __writemsr(HypercallMsr, (ULONG64)__Pfn[Index] << PAGE_SHIFT);
    }

    return STATUS_SUCCESS;

fail1:
    LogError("fail1 (%08x)", Status);

    return Status;
}

//static NTSTATUS
//__InitSharedInfo()
//{
//    NTSTATUS            Status;
//    PFN_NUMBER          Pfn;
//    PHYSICAL_ADDRESS    PhysicalAddress;
//    xen_memory_reservation_t reservation;
//
//    if ((ULONG_PTR)__SharedInfoSection & (PAGE_SIZE - 1))
//        SharedInfo = (PVOID)(((ULONG_PTR)__SharedInfoSection + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
//    else
//        SharedInfo = (PVOID)__SharedInfoSection;
//
//    PhysicalAddress = MmGetPhysicalAddress((PUCHAR)SharedInfo);
//    Pfn = (PFN_NUMBER)(PhysicalAddress.QuadPart >> PAGE_SHIFT);
//
//    reservation.extent_start.p = &Pfn;
//    reservation.extent_order = 0;
//    reservation.address_bits = 0;
//    reservation.domid = DOMID_SELF;
//    reservation.nr_extents = 1;
//
//    Status = MemoryOp(XENMEM_decrease_reservation, &reservation);
//    if (!NT_SUCCESS(Status))
//        goto fail;
//
//    LogTrace("SHARED_INFO 0x%p\n", SharedInfo);
//
//    Status = HvmAddToPhysMap(Pfn, XENMAPSPACE_shared_info, 0);
//    if (!NT_SUCCESS(Status))
//        goto fail;
//    // might be different ops, depending on XenVersion
//
//    return STATUS_SUCCESS;
//
//fail:
//    return Status;
//}

NTSTATUS
HvmInitialize()
{
    NTSTATUS    Status;

    Status = __InitHypercallPage();
    if (!NT_SUCCESS(Status))
        goto fail;

    //Status = __InitSharedInfo();
    //if (!NT_SUCCESS(Status))
    //    goto fail;

#ifdef AMD64
    LogVerbose("64-bit HVM\n");
#else
    LogVerbose("32-bit HVM\n");
#endif 

    return STATUS_SUCCESS;

fail:
    return Status;
}

VOID
HvmTerminate()
{
    ULONG Index;

    Hypercall = NULL;
    for (Index = 0; Index < MAXIMUM_HYPERCALL_PFN_COUNT; ++Index) {
        __Pfn[Index] = 0;
    }
    //SharedInfo = NULL;
}

NTSTATUS
HvmAddToPhysMap(
    IN  PFN_NUMBER      Pfn,
    IN  ULONG           Space,
    IN  ULONG           Offset
    )
{
    struct xen_add_to_physmap xatp;

#ifdef AMD64
    ASSERT3U(Pfn >> 32, ==, 0);
#endif

    xatp.domid = DOMID_SELF;
    xatp.space = Space;
    xatp.idx = Offset;
    xatp.gpfn = (xen_pfn_t)Pfn;

    return MemoryOp(XENMEM_add_to_physmap, &xatp);
}

static FORCEINLINE ULONG_PTR
HvmOp(
    IN  ULONG   Command,
    IN  PVOID   Argument
    )
{
    return Hypercall2(ULONG_PTR, hvm_op, Command, Argument);
}

NTSTATUS
HvmGetParameter(
    IN  ULONG           Param,
    OUT PULONG_PTR      Value
    )
{
    struct xen_hvm_param a;
    LONG_PTR rc;

    a.domid = DOMID_SELF;
    a.index = Param;
    a.value = 0xf001dead;

    rc = HvmOp(HVMOP_get_param, &a);
    if (rc < 0) {
        return STATUS_UNSUCCESSFUL;
    }

    /* Horrible hack to cope with the transition from
       return parameters through the hypercall return
       value to returning them through an in-memory
       structure. */
    if (a.value != 0xf001dead)
        *Value = (ULONG_PTR)a.value;
    else
        *Value = (ULONG_PTR)rc;

    return STATUS_SUCCESS;
}

NTSTATUS
HvmSetParameter(
    IN  ULONG           Param,
    IN  ULONG_PTR       Value
    )
{
    struct xen_hvm_param a;
    a.domid = DOMID_SELF;
    a.index = Param;
    a.value = Value;
    if (HvmOp(HVMOP_set_param, &a) == 0)
        return STATUS_UNSUCCESSFUL;
    else
        return STATUS_SUCCESS;
}
