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

#ifndef _XENVBD_SRBEXT_H
#define _XENVBD_SRBEXT_H

#include <wdm.h>
#include <xenvbd-storport.h>
#include <xen.h>
#include "assert.h"

// Segments - extension of blkif_segment_t
typedef struct _XENVBD_SEGMENT {
    PVOID               Grant;
    UCHAR               FirstSector;
    UCHAR               LastSector;
} XENVBD_SEGMENT, *PXENVBD_SEGMENT;

typedef struct _XENVBD_MAPPING {
    PVOID               BufferId;
    PVOID               Buffer; // VirtAddr mapped to PhysAddr(s)
    ULONG               Length;
    MDL                 Mdl;
    PFN_NUMBER          Pfn[2];
} XENVBD_MAPPING, *PXENVBD_MAPPING;

// Request - extension of blkif_request_t
typedef struct _XENVBD_REQUEST_READWRITE {
    UCHAR               NrSegments;
    ULONG64             FirstSector;
    XENVBD_SEGMENT      Segments[BLKIF_MAX_SEGMENTS_PER_REQUEST];
    XENVBD_MAPPING      Mappings[BLKIF_MAX_SEGMENTS_PER_REQUEST];
} XENVBD_REQUEST_READWRITE, *PXENVBD_REQUEST_READWRITE;

typedef struct _XENVBD_REQUEST_BARRIER {
    ULONG64             FirstSector;
} XENVBD_REQUEST_BARRIER, *PXENVBD_REQUEST_BARRIER;

typedef struct _XENVBD_REQUEST_DISCARD {
    UCHAR               Flags;  // {0, BLKIF_DISCARD_SECURE}
    ULONG64             FirstSector;
    ULONG64             NrSectors;
} XENVBD_REQUEST_DISCARD, *PXENVBD_REQUEST_DISCARD;

typedef struct _XENVBD_REQUEST_INDIRECT {
    UCHAR               Operation;  // BLKIF_OP_{READ/WRITE}
    USHORT              NrSegments; // 1-4096
    ULONG64             FirstSector;
    PVOID               Grants[BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST];
    PXENVBD_SEGMENT     Segments[BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST];
    PXENVBD_MAPPING     Mappings[BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST];
} XENVBD_REQUEST_INDIRECT, *PXENVBD_REQUEST_INDIRECT;

typedef struct _XENVBD_REQUEST {
    PSCSI_REQUEST_BLOCK Srb;
    LIST_ENTRY          Entry;

    UCHAR               Operation;
    union _XENVBD_REQUEST_TYPE {
        XENVBD_REQUEST_READWRITE    ReadWrite;  // BLKIF_OP_{READ/WRITE}
        XENVBD_REQUEST_BARRIER      Barrier;    // BLKIF_OP_WRITE_BARRIER
        // nothing                              // BLKIF_OP_FLUSH_DISKCACHE
        XENVBD_REQUEST_DISCARD      Discard;    // BLKIF_OP_DISCARD
        XENVBD_REQUEST_INDIRECT     Indirect;   // BLKIF_OP_INDIRECT
    } u;
} XENVBD_REQUEST, *PXENVBD_REQUEST;

// SRBExtension - context for SRBs
typedef struct _XENVBD_SRBEXT {
    PSCSI_REQUEST_BLOCK     Srb;
    LIST_ENTRY              Entry;
    LONG                    Count;
} XENVBD_SRBEXT, *PXENVBD_SRBEXT;

FORCEINLINE PXENVBD_SRBEXT
GetSrbExt(
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    if (Srb && Srb->Function != SRB_FUNCTION_STORAGE_REQUEST_BLOCK) {
        ASSERT3P(Srb->SrbExtension, !=, NULL);
        return Srb->SrbExtension;
    }
    return NULL;
}

FORCEINLINE VOID
InitSrbExt(
    __in PSCSI_REQUEST_BLOCK    Srb
    )
{
    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);
    if (SrbExt) {
        RtlZeroMemory(SrbExt, sizeof(XENVBD_SRBEXT));
        SrbExt->Srb = Srb;
    }
    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
}

#endif // _XENVBD_SRBEXT_H
