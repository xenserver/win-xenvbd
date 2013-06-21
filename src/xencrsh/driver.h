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

#ifndef _XENVBD_XENVBD_H
#define _XENVBD_XENVBD_H

#include "fdo.h"
#include <xen.h>

// Constants Not pulled in from xenvbd-wdm.h???
#ifndef PAGE_SHIFT
#define PAGE_SHIFT      12
#endif
#ifndef PAGE_SIZE
#define PAGE_SIZE       (1 << PAGE_SHIFT)
#endif
#ifndef PAGE_OFFSET
#define PAGE_OFFSET     (PAGE_SIZE - 1)
#endif
#ifndef PAGE_MASK
#define PAGE_MASK       ~(PAGE_OFFSET)
#endif

#define NORMAL_MODE     0
#define HIBER_MODE      1
#define DUMP_MODE       2

// Global Constants
#define XENVBD_MAX_TARGETS              (128)

#define XENVBD_MAX_RING_PAGE_ORDER      (0)
#define XENVBD_MAX_RING_PAGES           (1)

#define XENVBD_MAX_SEGMENTS_PER_REQUEST (BLKIF_MAX_SEGMENTS_PER_REQUEST)
#define XENVBD_MAX_REQUESTS_PER_SRB     (2)
#define XENVBD_MAX_SEGMENTS_PER_SRB     (XENVBD_MAX_REQUESTS_PER_SRB * XENVBD_MAX_SEGMENTS_PER_REQUEST)
#define XENVBD_MAX_TRANSFER_LENGTH      (XENVBD_MAX_SEGMENTS_PER_SRB * PAGE_SIZE)
#define XENVBD_MAX_PHYSICAL_BREAKS      (XENVBD_MAX_SEGMENTS_PER_SRB - 1)

#define XENVBD_MIN_GRANT_REFS           (XENVBD_MAX_SEGMENTS_PER_SRB)

// Fdo Device Extension management
VOID
DriverLinkFdo(
    IN  PXENVBD_FDO             Fdo
    );

VOID
DriverUnlinkFdo(
    IN  PXENVBD_FDO             Fdo
    );

// Global Functions
PCHAR
DriverFormat(
    IN  PCHAR                   Format,
    ...
    );

ULONG   
DriverGetOperatingMode(
    );

#endif // _XENVBD_XENVBD_H
