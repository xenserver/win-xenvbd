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

#ifndef _XENVBD_PDO_INQUIRY_H
#define _XENVBD_PDO_INQUIRY_H

#include <ntddk.h>
#include <xenvbd-storport.h>
#include "frontend.h"

extern VOID
PdoReadInquiryData(
    __in  PXENVBD_FRONTEND        Frontend,
    __out __drv_allocatesMem(mem) PVOID* _Inquiry
    );

extern VOID
PdoFreeInquiryData(
    __in __drv_freesMem(mem) PVOID Inquiry
    );

extern VOID
PdoUpdateInquiryData(
    __in  PXENVBD_FRONTEND       Frontend,
    __in  PVOID                  _Inquiry
    );

extern VOID
PdoInquiry(
    __in ULONG                   TargetId,
    __in PVOID                   Inquiry,
    __in PSCSI_REQUEST_BLOCK     Srb,
    __in XENVBD_DEVICE_TYPE      DeviceType
    );

#endif // _XENVBD_PDO_INQUIRY_H

