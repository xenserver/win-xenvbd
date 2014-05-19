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

#include "pdoinquiry.h"
#include "driver.h"
#include "debug.h"
#include "assert.h"
#include "util.h"
#include <xencdb.h>
#include <xenvbd-ntstrsafe.h>
#include <stdlib.h>

// "00000000-0000-0000-0000-000000000000"
#define GUID_LENGTH     36 

// 00 00 00 00 00 00 00 00 "XENSRC  00000000"
#define PAGE83_MIN_SIZE (4 + 4 + 16 + 1)

// 00 00 00 00 + GUID_LENGTH
#define VDI_ID_LENGTH   (4 + GUID_LENGTH)

#define INQUIRY_POOL_TAG 'qnIX'

typedef struct _XENVBD_PAGE {
    PCHAR   Data;
    ULONG   Length;
} XENVBD_PAGE, *PXENVBD_PAGE;

typedef struct _XENVBD_INQUIRY {
    XENVBD_PAGE Page80;
    XENVBD_PAGE Page83;
    CHAR        VdiUuid[GUID_LENGTH + 1];
} XENVBD_INQUIRY, *PXENVBD_INQUIRY;

static FORCEINLINE ULONG
__Min3(
    __in ULONG  A,
    __in ULONG  B,
    __in ULONG  C
    )
{
    return A < B ? __min(A, C) : __min(B, C);
}

__checkReturn
__drv_allocatesMem(mem)
__bcount(Size)
static FORCEINLINE PVOID 
#pragma warning(suppress: 28195)
___InquiryAlloc(
    __in PCHAR               Caller,
    __in ULONG               Line,
    __in SIZE_T              Size
    )
{
    return __AllocateNonPagedPoolWithTag(Caller, Line, Size, INQUIRY_POOL_TAG);
}
#define __InquiryAlloc(Size) ___InquiryAlloc(__FUNCTION__, __LINE__, Size)

static FORCEINLINE VOID
#pragma warning(suppress: 28197)
__InquiryFree(
    __in __drv_freesMem(mem) PVOID Buffer
    )
{
    if (Buffer != NULL)
        __FreePoolWithTag(Buffer, INQUIRY_POOL_TAG);
}

static FORCEINLINE UCHAR
__DecodeChar(
    __in CHAR    Char
    )
{
    if (Char >= 'A' && Char <= 'Z') return Char - 'A';
    if (Char >= 'a' && Char <= 'z') return Char - 'a' + 26;
    if (Char >= '0' && Char <= '9') return Char - '0' + 52;
    if (Char == '+')                return 62;
    if (Char == '/')                return 63;
    if (Char == '=')                return 0;
    return 0xFF;
}
static DECLSPEC_NOINLINE UCHAR
__Decode(
    __in PUCHAR  Dest,
    __in PCHAR   Src,
    __in ULONG   RemainingChars
    )
{
    UCHAR   Values[4]; 

    if (RemainingChars < 4)
        return 0xFF;

    // take 4 Src chars -> 1, 2, or 3 Dest bytes
    Values[0] = __DecodeChar(Src[0]);
    Values[1] = __DecodeChar(Src[1]);
    Values[2] = __DecodeChar(Src[2]);
    Values[3] = __DecodeChar(Src[3]);

    // sanity checks
    if ((Src[0] == '=' || Src[1] == '=') ||
        (Src[2] == '=' && Src[3] != '='))
        return 0xFF;
    if (Values[0] == 0xFF || Values[1] == 0xFF ||
        Values[2] == 0xFF || Values[3] == 0xFF)
        return 0xFF;

    // convert
    Dest[0] = (Values[1] >> 4) | (Values[0] << 2);
    if (Src[2] == '=')  return 2;
    Dest[1] = (Values[2] >> 2) | (Values[1] << 4);
    if (Src[3] == '=')  return 1;
    Dest[2] = (Values[3]     ) | (Values[2] << 6);
    return 0;
}
__checkReturn
static NTSTATUS
__DecodeBase64(
    __in  PCHAR   Base64,
    __in  ULONG   Base64Length,
    __out PVOID   *_Buffer,
    __out PULONG  BufferLength
    )
{
    // convert Base64(4chars) into Buffer(3bytes)
    PUCHAR      Buffer;
    ULONG       NumBlocks;
    ULONG       i;
    UCHAR       Pad = 0;

    NumBlocks = Base64Length / 4;

    Buffer = (PUCHAR)__InquiryAlloc(NumBlocks * 3);
    if (Buffer == NULL) {
        Error("__InquiryAlloc (STATUS_INSUFFICIENT_RESOURCES)\n");
        goto fail1;
    }

    for (i = 0; i < NumBlocks; ++i) {
        if (Pad)        goto invalid_base64;
        Pad = __Decode(Buffer + (i * 3), Base64 + (i * 4), Base64Length - (i * 4));
        if (Pad > 2)    goto invalid_base64;
    }

    *BufferLength = (NumBlocks * 3) - Pad;
    *_Buffer = Buffer;
    return STATUS_SUCCESS;

invalid_base64:
    Error("Invalid BASE64 encoding\n");
    __InquiryFree((PVOID)Buffer);
    return STATUS_UNSUCCESSFUL;

fail1:
    return STATUS_INSUFFICIENT_RESOURCES;
}
static DECLSPEC_NOINLINE BOOLEAN 
__ReadPage(
    __in PXENVBD_FRONTEND       Frontend,
    __in PXENVBD_PAGE           Page,
    __in PCHAR                  Path
    )
{
    NTSTATUS    Status;
    PCHAR       Value;

    Status = FrontendStoreReadBackend(Frontend, Path, &Value);
    if (!NT_SUCCESS(Status))
        goto fail1;

    Status = __DecodeBase64(Value, (ULONG)strlen(Value), (PVOID*)&Page->Data, &Page->Length);
    if (!NT_SUCCESS(Status))
        goto fail2;

    FrontendStoreFree(Frontend, Value);
    return TRUE;

fail2:
    FrontendStoreFree(Frontend, Value);
fail1:
    Page->Data = NULL;
    Page->Length = 0;
    return FALSE;
}

static FORCEINLINE BOOLEAN
__HandlePageStd(
    __in XENVBD_DEVICE_TYPE         DeviceType,
    __in PSCSI_REQUEST_BLOCK        Srb
    )
{
    PINQUIRYDATA    Data = (PINQUIRYDATA)Srb->DataBuffer;
    ULONG           Length = Srb->DataTransferLength;

    if (Length < INQUIRYDATABUFFERSIZE)
        return FALSE;

    switch (DeviceType) {
    case XENVBD_DEVICE_TYPE_DISK:
        Data->DeviceType            = DIRECT_ACCESS_DEVICE;
        Data->DeviceTypeQualifier   = DEVICE_CONNECTED;
        Data->Versions              = 4;
        Data->ResponseDataFormat    = 2;
        Data->AdditionalLength      = INQUIRYDATABUFFERSIZE - 4;
        Data->CommandQueue          = 1;
        RtlCopyMemory(Data->VendorId,               "XENSRC  ", 8);
        RtlCopyMemory(Data->ProductId,              "PVDISK          ", 16);
        RtlCopyMemory(Data->ProductRevisionLevel,   "2.0 ", 4);
        break;
    case XENVBD_DEVICE_TYPE_CDROM:
        Data->DeviceType            = READ_ONLY_DIRECT_ACCESS_DEVICE;
        Data->DeviceTypeQualifier   = DEVICE_CONNECTED;
        Data->RemovableMedia        = TRUE;
        Data->Versions              = 2;
        Data->ResponseDataFormat    = 2;
        Data->Wide32Bit             = TRUE;
        Data->Synchronous           = TRUE;
        Data->AdditionalLength      = INQUIRYDATABUFFERSIZE - 4;
        RtlCopyMemory(Data->VendorId,               "XENSRC  ", 8);
        RtlCopyMemory(Data->ProductId,              "PVCDROM         ", 16);
        RtlCopyMemory(Data->ProductRevisionLevel,   "2.0 ", 4);
        break;
    default:
        return FALSE;
        break;
    }

    Srb->DataTransferLength = INQUIRYDATABUFFERSIZE;
    return TRUE;
}
static FORCEINLINE BOOLEAN
__HandlePage00(
    __in PSCSI_REQUEST_BLOCK        Srb
    )
{
    PCHAR   Data = (PCHAR)Srb->DataBuffer;
    ULONG   Length = Srb->DataTransferLength;

    if (Length < 7)
        return FALSE;
    RtlZeroMemory(Data, Length);

    // 00 00 00 NumPages+1 00 [Page [...]]
    Data[3] = 3;
    Data[4] = 0x00;
    Data[5] = 0x80;
    Data[6] = 0x83;
    Srb->DataTransferLength = 7;

    return TRUE;
}
static FORCEINLINE BOOLEAN
__HandlePage80(
    __in ULONG                      TargetId,
    __in PXENVBD_INQUIRY            Inquiry,
    __in PSCSI_REQUEST_BLOCK        Srb
    )
{
    PCHAR   Data = (PCHAR)Srb->DataBuffer;
    ULONG   Length = Srb->DataTransferLength;

	RtlZeroMemory(Data, Length);
	if (DriverParameters.SynthesizeInquiry ||
        Inquiry == NULL || 
        Inquiry->Page80.Data == NULL || 
        Inquiry->Page80.Length == 0) {
        // generate the serial number page
        PVPD_SERIAL_NUMBER_PAGE Serial;
        if (Length < sizeof(VPD_SERIAL_NUMBER_PAGE) + 4)
            return FALSE;

        Serial = (PVPD_SERIAL_NUMBER_PAGE)Data;
        Serial->PageCode        = 0x80;
        Serial->PageLength      = 4;
        (VOID) RtlStringCchPrintfA((PCHAR)Serial->SerialNumber, 5, "%04u", TargetId);

        Verbose("Target[%u] : INQUIRY Using Fake Page80 Data\n", TargetId);

        Srb->DataTransferLength = sizeof(VPD_SERIAL_NUMBER_PAGE) + 4; 
        // VPD_SERIAL_NUMBER_PAGE includes 1 char already
    } else {
        if (Length < Inquiry->Page80.Length)
            return FALSE;

		RtlCopyMemory(Data, Inquiry->Page80.Data, Inquiry->Page80.Length);
        Srb->DataTransferLength = Inquiry->Page80.Length;
    }

    // if possible, append additional data
    //if (Inquiry && Length >= Srb->DataTransferLength + ADDITIONAL_LENGTH) {
    //    Srb->DataTransferLength += ADDITIONAL_LENGTH;
    //}
    return TRUE;
}
static FORCEINLINE BOOLEAN
__HandlePage83(
    __in ULONG                      TargetId,
    __in PXENVBD_INQUIRY            Inquiry,
    __in PSCSI_REQUEST_BLOCK        Srb
    )
{
    PCHAR   Data = (PCHAR)Srb->DataBuffer;
    ULONG   Length = Srb->DataTransferLength;

	RtlZeroMemory(Data, Length);
	if (DriverParameters.SynthesizeInquiry ||
        Inquiry == NULL || 
        Inquiry->Page83.Data == NULL || 
        Inquiry->Page83.Length == 0) {
        // generate the id page data
        PVPD_IDENTIFICATION_DESCRIPTOR  Id;

        if (Length < PAGE83_MIN_SIZE)
            return FALSE;

        Data[1]                 = 0x83;
        Data[3]                 = 16;

        Id = (PVPD_IDENTIFICATION_DESCRIPTOR)(Data + 4);
        Id->CodeSet             = VpdCodeSetAscii;
        Id->IdentifierType      = VpdIdentifierTypeVendorId;
        Id->IdentifierLength    = 16;
        (VOID) RtlStringCchPrintfA((PCHAR)Id->Identifier, 17, "XENSRC  %08u", TargetId);

        Verbose("Target[%u] : INQUIRY Using Fake Page83 Data\n", TargetId);

        Srb->DataTransferLength = PAGE83_MIN_SIZE;
    } else {
        if (Length < Inquiry->Page83.Length)
            return FALSE;

        RtlCopyMemory(Data, Inquiry->Page83.Data, Inquiry->Page83.Length);
        Srb->DataTransferLength = Inquiry->Page83.Length;
    }

    // if possible, append vdi-uuid as VendorSpecific
    if (Inquiry && Length >= Srb->DataTransferLength + VDI_ID_LENGTH) {
        PVPD_IDENTIFICATION_DESCRIPTOR Id;
        
        // update internal size
        *(Data + 3) += VDI_ID_LENGTH;

        // copy new data
        Id = (PVPD_IDENTIFICATION_DESCRIPTOR)(Data + Srb->DataTransferLength);
        Id->CodeSet             = VpdCodeSetAscii;
        Id->IdentifierType      = VpdIdentifierTypeVendorSpecific;
        Id->IdentifierLength    = GUID_LENGTH;
        RtlCopyMemory(Id->Identifier, Inquiry->VdiUuid, GUID_LENGTH);        
 
        Srb->DataTransferLength += VDI_ID_LENGTH;
    }
    return TRUE;
}

#define MAX_BUFFER      64

static FORCEINLINE VOID
__TracePage80(
    __in ULONG                    TargetId,
    __in PXENVBD_INQUIRY          Inquiry
    )
{
    ULONG           Length;
    CHAR            Buffer[MAX_BUFFER+1];

    Length = __Min3(Inquiry->Page80.Data[3], MAX_BUFFER, Inquiry->Page80.Length - 4);
    RtlCopyMemory(Buffer, Inquiry->Page80.Data + 4, Length);
    Buffer[Length] = 0;
    Verbose("Target[%u] : SerialNumber = \"%s\"\n", TargetId, Buffer);
}
static FORCEINLINE VOID
__TracePage83(
    __in ULONG                    TargetId,
    __in PXENVBD_INQUIRY          Inquiry
    )
{
    ULONG           Length;
    ULONG           Index;
    CHAR            Buffer[MAX_BUFFER+1];

    for (Index = 4; Index < Inquiry->Page83.Length; ) {
        PVPD_IDENTIFICATION_DESCRIPTOR Identifier = (PVPD_IDENTIFICATION_DESCRIPTOR)&Inquiry->Page83.Data[Index];

        switch (Identifier->CodeSet) {
        case VpdCodeSetAscii:
            Length = __Min3(Identifier->IdentifierLength, MAX_BUFFER, Inquiry->Page83.Length - Index - 4);
            RtlCopyMemory(Buffer, Identifier->Identifier, Length);
            Buffer[Length] = 0;
            Verbose("Target[%u] : Identifier (ASCII, Type %02x, \"%s\")\n", 
                    TargetId, Identifier->IdentifierType, Buffer);
            break;

        default:
            Verbose("Target[%u] : Identifier (CodeSet %02x, Type %02x, Length %02x)\n", 
                    TargetId, Identifier->CodeSet, Identifier->IdentifierType, Identifier->IdentifierLength);
            break;
        }

        Index += (4 + Identifier->IdentifierLength);
    }
}

VOID
#pragma warning(suppress: 28195)
PdoReadInquiryData(
    __in  PXENVBD_FRONTEND        Frontend,
    __out __drv_allocatesMem(mem) PVOID* _Inquiry
    )
{
    PXENVBD_INQUIRY Inquiry;
    const CHAR      GuidNull[] = "00000000-0000-0000-0000-000000000000";
    const ULONG     TargetId = FrontendGetTargetId(Frontend);
    
    *_Inquiry = NULL;
    Inquiry = (PXENVBD_INQUIRY)__InquiryAlloc(sizeof(XENVBD_INQUIRY));
    if (Inquiry == NULL) {
        Error("Target[%d] : Memory allocation getting INQUIRY data (%d bytes failed)\n", 
                TargetId, sizeof(XENVBD_INQUIRY));
        return;
    }
    
    // initialize VDI-UUID
    RtlCopyMemory(Inquiry->VdiUuid, GuidNull, GUID_LENGTH);
    Inquiry->VdiUuid[GUID_LENGTH] = 0;

    // read page80
    if (!__ReadPage(Frontend, &Inquiry->Page80, "sm-data/scsi/0x12/0x80")) {
        Warning("Target[%d] : Failed to get Page80 data\n", TargetId);
    } else {
        __TracePage80(TargetId, Inquiry);
    }

    // read page83
    if (!__ReadPage(Frontend, &Inquiry->Page83, "sm-data/scsi/0x12/0x83")) {
        Warning("Target[%d] : Failed to get Page83 data\n", TargetId);
    } else {
        __TracePage83(TargetId, Inquiry);
    }

    *_Inquiry = Inquiry;
}

VOID
PdoFreeInquiryData(
    __in __drv_freesMem(mem) PVOID _Inquiry
    )
{
    PXENVBD_INQUIRY Inquiry = (PXENVBD_INQUIRY)_Inquiry;

    if (_Inquiry == NULL)
        return;

    __InquiryFree((PVOID)Inquiry->Page80.Data);
    __InquiryFree((PVOID)Inquiry->Page83.Data);
    __InquiryFree((PVOID)Inquiry);
}

VOID
PdoUpdateInquiryData(
    __in  PXENVBD_FRONTEND       Frontend,
    __in  PVOID                  _Inquiry
    )
{
    PXENVBD_INQUIRY Inquiry = (PXENVBD_INQUIRY)_Inquiry;
    NTSTATUS        Status;
    PCHAR           Value;
    ULONG           Length;
    const CHAR      GuidNull[] = "00000000-0000-0000-0000-000000000000";

    if (_Inquiry == NULL)
        return;

    RtlCopyMemory(Inquiry->VdiUuid, GuidNull, GUID_LENGTH);
    Inquiry->VdiUuid[GUID_LENGTH] = 0;

    Status = FrontendStoreReadBackend(Frontend, "sm-data/vdi-uuid", &Value);
    if (NT_SUCCESS(Status)) {
        Length = (ULONG)strlen(Value);

        if (Length == GUID_LENGTH) {
            RtlCopyMemory(Inquiry->VdiUuid, Value, Length);
            Inquiry->VdiUuid[GUID_LENGTH] = 0;
        }

        FrontendStoreFree(Frontend, Value);
    }

    Verbose("Target[%u] : VDI-UUID = {%s}\n", FrontendGetTargetId(Frontend), Inquiry->VdiUuid);
}

VOID
PdoInquiry(
    __in ULONG                   TargetId,
    __in PVOID                   Inquiry,
    __in PSCSI_REQUEST_BLOCK     Srb,
    __in XENVBD_DEVICE_TYPE      DeviceType
    )
{
    BOOLEAN         Success;
    const UCHAR     Evpd = Cdb_EVPD(Srb);
    const UCHAR     PageCode = Cdb_PageCode(Srb);

    Trace("Target[%d] : INQUIRY %02x%s\n", TargetId, PageCode, Evpd ? " EVPD" : "");
    if (Evpd) {
        switch (PageCode) {
        case 0x00:  Success = __HandlePage00(Srb);                      break;
        case 0x80:  Success = __HandlePage80(TargetId, (PXENVBD_INQUIRY)Inquiry, Srb);   break;
        case 0x83:  Success = __HandlePage83(TargetId, (PXENVBD_INQUIRY)Inquiry, Srb);   break;
        default:    Success = FALSE;                                    break;
        }
    } else {
        switch (PageCode) {
        case 0x00:  Success = __HandlePageStd(DeviceType, Srb);         break;
        default:    Success = FALSE;                                    break;
        }
    }

    if (Success) {
        Srb->ScsiStatus = 0; /* SUCCESS */
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
    } else {
        Error("Target[%d] : INQUIRY failed %02x%s\n", TargetId, PageCode, Evpd ? " EVPD" : "");
        Srb->ScsiStatus = 0x02; /* CHECK_CONDITION */
        Srb->SrbStatus = SRB_STATUS_ERROR;
    }
}
