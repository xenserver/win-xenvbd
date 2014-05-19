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

#include "store.h"
#include "austere.h"

#include <xencdb.h>
#include "log.h"
#include "assert.h"
#include "util.h"

#include <stdlib.h>

typedef struct _XENVBD_PAGE {
    LIST_ENTRY  List;

    UCHAR       PageCode;
    PVOID       Data;
    ULONG       Length;
} XENVBD_PAGE, *PXENVBD_PAGE;

typedef struct _XENVBD_INQUIRY {
    LIST_ENTRY  ListHead;

    XENVBD_PAGE StandardPage;

    XENVBD_PAGE Page00;
} XENVBD_INQUIRY, *PXENVBD_INQUIRY;

#define INQUIRY_POOL_TAG 'IBVX'

static VOID
__DefaultInquiry(
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    const UCHAR Evpd = Cdb_EVPD(Srb);
    const UCHAR PageCode = Cdb_PageCode(Srb);

    if (Evpd == 0)
    {
        if (PageCode == 0 && Srb->DataTransferLength >= INQUIRYDATABUFFERSIZE)
        {
            PINQUIRYDATA InqData = (PINQUIRYDATA)Srb->DataBuffer;
            // setup inquiry data
            InqData->Versions = 4;
            InqData->ResponseDataFormat = 2;
            InqData->AdditionalLength = 0;
            InqData->CommandQueue = 1;
            RtlCopyMemory(&InqData->VendorId,             "XENSRC  ", 8);
            RtlCopyMemory(&InqData->ProductId,            "PVDISK          ", 16);
            RtlCopyMemory(&InqData->ProductRevisionLevel, "2.0 ", 4);
            // succeed
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            Srb->DataTransferLength = INQUIRYDATABUFFERSIZE;
        }
    } else
    {
        PUCHAR Buffer = (PUCHAR)Srb->DataBuffer;
        switch (PageCode) 
        {
        case 0x00:
            if (Srb->DataTransferLength >= 7)
            {
                Buffer[0] = 0x00;
                Buffer[1] = PageCode;
                Buffer[2] = 0x00;
                Buffer[3] = 3;
                Buffer[4] = 0x00;
                Buffer[5] = 0x80;
                Buffer[6] = 0x83;
                Srb->SrbStatus = SRB_STATUS_SUCCESS;
                Srb->DataTransferLength = 7;
            }
            break;
        case 0x80:
            if (Srb->DataTransferLength >= 5)
            {
                Buffer[0] = 0x00;
                Buffer[1] = PageCode;
                Buffer[2] = 0x00;
                Buffer[3] = 1;
                Buffer[4] = ' ';
                Srb->SrbStatus = SRB_STATUS_SUCCESS;
                Srb->DataTransferLength = 5;
            }
            break;
        case 0x83:
            if (Srb->DataTransferLength >= 4)
            {
                Buffer[0] = 0x00;
                Buffer[1] = PageCode;
                Buffer[2] = 0x00;
                Buffer[3] = 0;
                Srb->SrbStatus = SRB_STATUS_SUCCESS;
                Srb->DataTransferLength = 4;
            }
            break;
        }
    }
}

static FORCEINLINE PXENVBD_PAGE
__FindPage(
    IN  PXENVBD_INQUIRY Inquiry,
    IN  UCHAR           Evpd,
    IN  UCHAR           PageCode
    )
{
    PLIST_ENTRY     Entry;
    PXENVBD_PAGE    Page = NULL;

    if (Evpd == 0) {
        if (PageCode == 0) {
            Page = &Inquiry->StandardPage;
        }
    } else {
        if (PageCode == 0) {
            Page = &Inquiry->Page00;
        } else {
            for (Entry = Inquiry->ListHead.Flink; Entry != &Inquiry->ListHead; Entry = Entry->Flink) {
                PXENVBD_PAGE ThisPage = CONTAINING_RECORD(Entry, XENVBD_PAGE, List);
                if (ThisPage->PageCode == PageCode) {
                    Page = ThisPage;
                    break;
                }
            }
        }
    }
    if (Page && Page->Data && Page->Length) {
        return Page;
    } else {
        LogTrace("Inquiry Page %d:%d not found\n", Evpd, PageCode);
        return NULL;
    }
}


static VOID
__FreeInquiryData(
    IN  PXENVBD_INQUIRY     Inquiry
    )
{
    PLIST_ENTRY     Entry;
    PXENVBD_PAGE    Page;

    // free standard page
    if (Inquiry->StandardPage.Data) {
        AustereFree(Inquiry->StandardPage.Data);
    }
    // free page00
    if (Inquiry->Page00.Data) {
        AustereFree(Inquiry->Page00.Data);
    }

    // free other pages
    while ((Entry = RemoveHeadList(&Inquiry->ListHead)) != &Inquiry->ListHead) {
        Page = CONTAINING_RECORD(Entry, XENVBD_PAGE, List);
        if (Page->Data) {
            AustereFree(Page->Data);
        }
        AustereFree(Page);
    }

    // free data
    AustereFree(Inquiry);
}


static FORCEINLINE UCHAR
__PageCode(
    IN  PCHAR   PageCode
    )
{
    ULONG Ret;
    if (PageCode[0] == '0' && PageCode[1] == 'x')
        Ret = strtoul(PageCode + 2, NULL, 16);
    else
        Ret = strtoul(PageCode, NULL, 10);
    ASSERT3U(Ret, <, 256);
    return (UCHAR)Ret;
}
static FORCEINLINE UCHAR
__DecodeChar(
    IN  CHAR    Char
    )
{
    if (Char >= 'A' && Char <= 'Z')
        return Char - 'A';
    if (Char >= 'a' && Char <= 'z')
        return Char - 'a' + 26;
    if (Char >= '0' && Char <= '9')
        return Char - '0' + 52;
    if (Char == '+')
        return 62;
    if (Char == '/')
        return 63;
    if (Char == '=')
        return 0;
    
    return 0xFF;
}
static FORCEINLINE UCHAR
__Decode(
    IN  PUCHAR  Dest,
    IN  PCHAR   Src,
    IN  ULONG   RemainingChars
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
static NTSTATUS
__DecodeBase64(
    IN  PCHAR   Base64,
    IN  ULONG   Base64Length,
    OUT PVOID   *_Buffer,
    OUT PULONG  BufferLength
    )
{
    // convert Base64(4chars) into Buffer(3bytes)
    PUCHAR      Buffer;
    ULONG       NumBlocks;
    ULONG       i;
    UCHAR       Pad = 0;

    NumBlocks = Base64Length / 4;

    Buffer = (PUCHAR)AustereAllocate(NumBlocks * 3);
    if (!Buffer) {
        LogError("AustereAllocate (STATUS_INSUFFICIENT_RESOURCES)\n");
        goto fail1;
    }
    RtlZeroMemory(Buffer, NumBlocks * 3);

    for (i = 0; i < NumBlocks; ++i) {
        if (Pad)        goto invalid_base64;
        Pad = __Decode(Buffer + (i * 3), Base64 + (i * 4), Base64Length - (i * 4));
        if (Pad > 2)    goto invalid_base64;
    }

    *BufferLength = (NumBlocks * 3) - Pad;
    *_Buffer = Buffer;
    return STATUS_SUCCESS;

invalid_base64:
    LogError("Invalid BASE64 encoding\n");
    AustereFree(Buffer);
    return STATUS_UNSUCCESSFUL;

fail1:
    return STATUS_INSUFFICIENT_RESOURCES;
}
static NTSTATUS
__ReadPage(
    IN  PXENVBD_INQUIRY         Inquiry,
    IN  PCHAR                   BasePath,
    IN  PCHAR                   PageCode
    )
{
    NTSTATUS        Status;
    PCHAR           Base64;
    ULONG           Base64Length;
    PVOID           Buffer;
    ULONG           BufferLength;
    PXENVBD_PAGE    Page;

    Status = StoreRead(NULL, BasePath, PageCode, &Base64);
    if (!NT_SUCCESS(Status)) {
        LogError("STORE:Read %s/%s (%08x)\n", BasePath, PageCode, Status);
        goto fail1;
    }
    Base64Length = (ULONG)strlen(Base64);

    Status = __DecodeBase64(Base64, Base64Length, &Buffer, &BufferLength);
    if (!NT_SUCCESS(Status)) {
        goto fail2;
    }
    AustereFree(Base64);

    if (!strcmp(PageCode, "default")) {
        Inquiry->StandardPage.PageCode = 0;
        Inquiry->StandardPage.Data = Buffer;
        Inquiry->StandardPage.Length = BufferLength;
    } else {
        Page = (PXENVBD_PAGE)AustereAllocate(sizeof(XENVBD_PAGE));
        if (!Page) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            LogError("AustereAllocate (STATUS_INSUFFICIENT_RESOURCES)\n");
            goto fail3;
        }
        RtlZeroMemory(Page, sizeof(XENVBD_PAGE));

        Page->PageCode = __PageCode(PageCode);
        if (Page->PageCode == 0) {
            LogError("PageCode %s is not Valid\n", PageCode);
            goto fail4;
        }
        Page->Data = Buffer;
        Page->Length = BufferLength;

        InsertHeadList(&Inquiry->ListHead, &Page->List);
    }

    return STATUS_SUCCESS;

fail4:
    AustereFree(Page);

fail3:
    AustereFree(Buffer);

fail2:
    AustereFree(Base64);

fail1:
    return Status;
}
static NTSTATUS
__GeneratePage83(
    IN  PXENVBD_INQUIRY         Inquiry
    )
{
    PXENVBD_PAGE    Page;
    PUCHAR          Data;

    Page = (PXENVBD_PAGE)AustereAllocate(sizeof(XENVBD_PAGE));
    if (!Page) {
        LogError("AustereAllocate (STATUS_INSUFFICIENT_RESOURCES)\n");
        goto fail1;
    }
    RtlZeroMemory(Page, sizeof(XENVBD_PAGE));

    Page->PageCode = 0x83;
    Page->Length = 4;
    Page->Data = AustereAllocate(Page->Length);
    if (!Page->Data) {
        LogError("AustereAllocate (STATUS_INSUFFICIENT_RESOURCES)\n");
        goto fail2;
    }
    RtlZeroMemory(Page->Data, Page->Length);
    Data =  (PUCHAR)Page->Data;

    Data[1] = 0x83;

    InsertHeadList(&Inquiry->ListHead, &Page->List);
    return STATUS_SUCCESS;

fail2:
    AustereFree(Page);
fail1:
    return STATUS_INSUFFICIENT_RESOURCES;
}
static NTSTATUS
__GeneratePage80(
    IN  PXENVBD_INQUIRY         Inquiry
    )
{
    PXENVBD_PAGE            Page;
    PVPD_SERIAL_NUMBER_PAGE Data;

    Page = (PXENVBD_PAGE)AustereAllocate(sizeof(XENVBD_PAGE));
    if (!Page) {
        LogError("AustereAllocate (STATUS_INSUFFICIENT_RESOURCES)\n");
        goto fail1;
    }
    RtlZeroMemory(Page, sizeof(XENVBD_PAGE));

    Page->PageCode = 0x80;
    Page->Length = sizeof(VPD_SERIAL_NUMBER_PAGE) + 1;
    Page->Data = AustereAllocate(Page->Length);
    if (!Page->Data) {
        LogError("AustereAllocate (STATUS_INSUFFICIENT_RESOURCES)\n");
        goto fail2;
    }
    RtlZeroMemory(Page->Data, Page->Length);
    Data =  (PVPD_SERIAL_NUMBER_PAGE)Page->Data;

    Data->PageCode          = VPD_SERIAL_NUMBER;
    Data->PageLength        = 1;
    Data->SerialNumber[0]   = ' ';

    InsertHeadList(&Inquiry->ListHead, &Page->List);
    return STATUS_SUCCESS;

fail2:
    AustereFree(Page);
fail1:
    return STATUS_INSUFFICIENT_RESOURCES;
}
static FORCEINLINE NTSTATUS
__GeneratePageStd(
    IN  PXENVBD_INQUIRY         Inquiry
    )
{
    INQUIRYDATA     *Data;

    Inquiry->StandardPage.PageCode = 0;
    Inquiry->StandardPage.Length = sizeof(INQUIRYDATA);
    Inquiry->StandardPage.Data = AustereAllocate(sizeof(INQUIRYDATA));
    if (!Inquiry->StandardPage.Data) {
        LogError("AustereAllocate (STATUS_INSUFFICIENT_RESOURCES)\n");
        goto fail1;
    }
    RtlZeroMemory(Inquiry->StandardPage.Data, Inquiry->StandardPage.Length);
    Data = (PINQUIRYDATA)Inquiry->StandardPage.Data;

    // fill in some bits
    Data->DeviceType            = DIRECT_ACCESS_DEVICE;
    Data->DeviceTypeQualifier   = DEVICE_CONNECTED;
    Data->Versions              = 4;
    Data->ResponseDataFormat    = 2;
    Data->AdditionalLength      = sizeof(INQUIRYDATA) - 5;
    Data->CommandQueue          = 1;
    RtlCopyMemory(Data->VendorId,               "XENSRC  ", 8);
    RtlCopyMemory(Data->ProductId,              "PVDISK          ", 16);
    RtlCopyMemory(Data->ProductRevisionLevel,   "2.0 ", 4);

    return STATUS_SUCCESS;

fail1:
    return STATUS_INSUFFICIENT_RESOURCES;
}
static NTSTATUS
__GeneratePage00(
    IN  PXENVBD_INQUIRY         Inquiry
    )
{
    PUCHAR          Buffer;
    ULONG           PageNum;
    PLIST_ENTRY     Entry;
    PXENVBD_PAGE    Page;
    ULONG           NumPages = 0;
    
    for (Entry = Inquiry->ListHead.Flink; Entry != &Inquiry->ListHead; Entry = Entry->Flink) {
        ++NumPages;
    }

    Inquiry->Page00.PageCode = 0;
    Inquiry->Page00.Length = 5 + NumPages;
    Inquiry->Page00.Data = AustereAllocate(Inquiry->Page00.Length);
    if (!Inquiry->Page00.Data) {
        LogError("AustereAllocate (STATUS_INSUFFICIENT_RESOURCES)\n");
        goto fail1;
    }
    RtlZeroMemory(Inquiry->Page00.Data, Inquiry->Page00.Length);
    Buffer = (PUCHAR)Inquiry->Page00.Data;
    
    if (Inquiry->Page00.Length < 5 + NumPages) {
        // PREFAST:Warning suppress
        goto fail2;
    }
    // 00 00 00 NumPages+1 00 [Page [...]]
    Buffer[3] = (UCHAR)(NumPages + 1);

    ASSERT(Inquiry->Page00.Length == 5 + NumPages);

    PageNum = 0;
    for (Entry = Inquiry->ListHead.Flink; Entry != &Inquiry->ListHead; Entry = Entry->Flink) {
        Page = CONTAINING_RECORD(Entry, XENVBD_PAGE, List);
        Buffer[5 + PageNum] = Page->PageCode;
        ++PageNum;
    }

    return STATUS_SUCCESS;

fail2:
    AustereFree(Inquiry->Page00.Data);
    Inquiry->Page00.Data = NULL;
    Inquiry->Page00.Length = 0;

fail1:
    return STATUS_INSUFFICIENT_RESOURCES;
}
static NTSTATUS
__ReadInquiry(
    IN  PCHAR                   Path,
    OUT PVOID*                  _Inquiry
    )
{
    NTSTATUS        Status;
    PXENVBD_INQUIRY Inquiry;
    PCHAR           InquiryPath;
    PCHAR           PageList;
    PCHAR           ThisPage;

    Status = STATUS_INSUFFICIENT_RESOURCES;
    InquiryPath = DriverFormat("%s/sm-data/scsi/0x12", Path);
    if (!InquiryPath) {
        goto fail1;
    }

    Inquiry = (PXENVBD_INQUIRY)AustereAllocate(sizeof(XENVBD_INQUIRY));
    if (!Inquiry) {
        AustereFree(InquiryPath);
        goto fail2;
    }
    RtlZeroMemory(Inquiry, sizeof(XENVBD_INQUIRY));
    InitializeListHead(&Inquiry->ListHead);

    Status = StoreDirectory(NULL, NULL, InquiryPath, &PageList);
    if (!NT_SUCCESS(Status)) {
        AustereFree(InquiryPath);
        goto fail3;
    }

    ThisPage = PageList;
    while (*ThisPage != '\0') {
        Status = __ReadPage(Inquiry, InquiryPath, ThisPage);
        if (!NT_SUCCESS(Status)) {
            AustereFree(PageList);
            goto fail4;
        }
        // Advance to next page
        for ( ; *ThisPage; ++ThisPage)  ;
        ++ThisPage;
    }
    AustereFree(PageList);

    // generate Page 0x83
    if (!__FindPage(Inquiry, 1, 0x83)) {
        Status = __GeneratePage83(Inquiry);
        if (!NT_SUCCESS(Status)) {
            goto fail4;
        }
    }
    // generate Page 0x80
    if (!__FindPage(Inquiry, 1, 0x80)) {
        Status = __GeneratePage80(Inquiry);
        if (!NT_SUCCESS(Status)) {
            goto fail4;
        }
    }
    // generate StdPage
    if (!__FindPage(Inquiry, 0, 0x00)) {
        Status = __GeneratePageStd(Inquiry);
        if (!NT_SUCCESS(Status)) {
            goto fail4;
        }
    }

    // generate Page 0x00
    Status = __GeneratePage00(Inquiry);
    if (!NT_SUCCESS(Status)) {
        goto fail4;
    }

    // Succeed
    AustereFree(InquiryPath);
    *_Inquiry = Inquiry;
    return STATUS_SUCCESS;

fail4:
    LogError("Fail4\n");
fail3:
    LogError("Fail3\n");
    __FreeInquiryData(Inquiry);
fail2:
    LogError("Fail2\n");
    AustereFree(InquiryPath);
fail1:
    LogError("Fail1 (%08x)\n", Status);
    return Status;
}

static FORCEINLINE ULONG
__Min(
    IN  ULONG   A,
    IN  ULONG   B
    )
{
    return A < B ? A : B;
}
static FORCEINLINE VOID
__DumpBytes(
    IN  PUCHAR  Bytes,
    IN  ULONG   Length
    )
{
    ULONG ThisTime, Index;

    for (Index = 0; Index < Length; ) {
        ThisTime = __Min(Length - Index, 8);
        switch (ThisTime) {
        case 1:
            LogTrace("[%02x-%02x] : %02x\n", Index, Index + 0, Bytes[Index + 0]);
            break;
        case 2:
            LogTrace("[%02x-%02x] : %02x %02x\n", Index, Index + 1, Bytes[Index + 0], Bytes[Index + 1]);
            break;
        case 3:
            LogTrace("[%02x-%02x] : %02x %02x %02x\n", Index, Index + 2, 
                Bytes[Index + 0], Bytes[Index + 1], Bytes[Index + 2]);
            break;
        case 4:
            LogTrace("[%02x-%02x] : %02x %02x %02x %02x\n", Index, Index + 3, 
                Bytes[Index + 0], Bytes[Index + 1], Bytes[Index + 2], Bytes[Index + 3]);
            break;
        case 5:
            LogTrace("[%02x-%02x] : %02x %02x %02x %02x %02x\n", Index, Index + 4, 
                Bytes[Index + 0], Bytes[Index + 1], Bytes[Index + 2], Bytes[Index + 3],
                Bytes[Index + 4]);
            break;
        case 6:
            LogTrace("[%02x-%02x] : %02x %02x %02x %02x %02x %02x\n", Index, Index + 5, 
                Bytes[Index + 0], Bytes[Index + 1], Bytes[Index + 2], Bytes[Index + 3],
                Bytes[Index + 4], Bytes[Index + 5]);
            break;
        case 7:
            LogTrace("[%02x-%02x] : %02x %02x %02x %02x %02x %02x %02x\n", Index, Index + 6, 
                Bytes[Index + 0], Bytes[Index + 1], Bytes[Index + 2], Bytes[Index + 3],
                Bytes[Index + 4], Bytes[Index + 5], Bytes[Index + 6]);
            break;
        case 8:
            LogTrace("[%02x-%02x] : %02x %02x %02x %02x %02x %02x %02x %02x\n", Index, Index + 7, 
                Bytes[Index + 0], Bytes[Index + 1], Bytes[Index + 2], Bytes[Index + 3],
                Bytes[Index + 4], Bytes[Index + 5], Bytes[Index + 6], Bytes[Index + 7]);
            break;
        }
        Index += ThisTime;
    }
}
static FORCEINLINE VOID
__DumpPage(
    IN  PXENVBD_PAGE    Page
    )
{
    LogTrace("PAGE_CODE : %02x\n", Page->PageCode);
    LogTrace("Length    : %d bytes\n", Page->Length);
    __DumpBytes((PUCHAR)Page->Data, Page->Length);
}
static FORCEINLINE VOID
__DumpPageStandard(
    IN  PXENVBD_PAGE    Page
    )
{
    LogTrace("PAGE_CODE : %02x STANDARD\n", Page->PageCode);
    LogTrace("Length    : %d bytes\n", Page->Length);
    __DumpBytes((PUCHAR)Page->Data, Page->Length);
}
static FORCEINLINE VOID
__DumpInquiry(
    IN  PVOID           _Inquiry
    )
{
    PLIST_ENTRY     Entry;
    PXENVBD_INQUIRY Inquiry = (PXENVBD_INQUIRY)_Inquiry;

    __DumpPageStandard(&Inquiry->StandardPage);

    __DumpPage(&Inquiry->Page00);

    for (Entry = Inquiry->ListHead.Flink; Entry != &Inquiry->ListHead; Entry = Entry->Flink) {
        PXENVBD_PAGE Page = CONTAINING_RECORD(Entry, XENVBD_PAGE, List);
        __DumpPage(Page);
    }
}

VOID
PdoReadInquiryData(
    IN  PXENVBD_FRONTEND        Frontend,
    OUT PVOID*                  _Inquiry
    )
{
    NTSTATUS        Status;

    Status = __ReadInquiry(Frontend->BackendPath, _Inquiry);
    if (!NT_SUCCESS(Status))
        goto fail;

    __DumpInquiry(*_Inquiry);
    return;

fail:
    LogError("Fail (%08x)\n", Status);
}

VOID
PdoFreeInquiryData(
    IN  PVOID                   Inquiry
    )
{
    __FreeInquiryData((PXENVBD_INQUIRY)Inquiry);
}

VOID
PdoInquiry(
    IN  PVOID                   Inquiry,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    ULONG           Length;
    PXENVBD_PAGE    Page;
    const UCHAR     Evpd = Cdb_EVPD(Srb);
    const UCHAR     PageCode = Cdb_PageCode(Srb);

    if (Inquiry) {
        Page = __FindPage((PXENVBD_INQUIRY)Inquiry, Evpd, PageCode);
        if (Page) {
            Length = Page->Length;
            if (Srb->DataTransferLength < Length)
                Length = Srb->DataTransferLength;
            RtlCopyMemory(Srb->DataBuffer, Page->Data, Length);
            Srb->DataTransferLength = Length;
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
        }
    } else {
        __DefaultInquiry(Srb);
    }
}

