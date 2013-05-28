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

#ifndef XENCDB_H
#define XENCDB_H

#define XENCDB_SCSIOP_INVALID 0xFF

FORCEINLINE USHORT Cdb_get_big_endian_word(const UCHAR src[2])
{
    return src[1] | ((USHORT)src[0] << 8);
}
FORCEINLINE ULONG Cdb_get_big_endian_dword(const UCHAR src[4])
{
    return src[3] | ((ULONG)src[2] << 8) | ((ULONG)src[1] << 16) |
            ((ULONG)src[0] << 24);
}

FORCEINLINE ULONG64 Cdb_get_big_endian_qword(const UCHAR src[8])
{
    return src[7] | ((ULONG64)src[6] << 8) | ((ULONG64)src[5] << 16) |
        ((ULONG64)src[4] << 24) | ((ULONG64)src[3] << 32) |
        ((ULONG64)src[2] << 40) | ((ULONG64)src[1] << 48) |
        ((ULONG64)src[0] << 56);
}

FORCEINLINE UCHAR Cdb_CheckLen6(UCHAR op)
{
    return (/*op >= SCSIOP_TEST_UNIT_READY && */op <= SCSIOP_MEDIUM_REMOVAL) ? op : XENCDB_SCSIOP_INVALID;
}
FORCEINLINE UCHAR Cdb_CheckLen10(UCHAR op)
{
    return (op >= SCSIOP_READ_FORMATTED_CAPACITY && op <= SCSIOP_PERSISTENT_RESERVE_OUT) ? op : XENCDB_SCSIOP_INVALID;
}
FORCEINLINE UCHAR Cdb_CheckLen12(UCHAR op)
{
    return (op >= SCSIOP_REPORT_LUNS && op <= SCSIOP_INIT_ELEMENT_RANGE) ? op : XENCDB_SCSIOP_INVALID;
}
FORCEINLINE UCHAR Cdb_CheckLen16(UCHAR op)
{
    return (op >= SCSIOP_XDWRITE_EXTENDED16 && op <= SCSIOP_SERVICE_ACTION_OUT16) ? op : XENCDB_SCSIOP_INVALID;
}
FORCEINLINE UCHAR Cdb_OperationRaw(UCHAR len, const UCHAR* _cdb)
{
    CDB* const cdb = (CDB*)_cdb;
    switch (len) {
    case 6:
        return Cdb_CheckLen6(cdb->CDB6GENERIC.OperationCode);
    case 10:
        return Cdb_CheckLen10(cdb->CDB10.OperationCode);
    case 12:
        return Cdb_CheckLen12(cdb->CDB12.OperationCode);
    case 16:
        return Cdb_CheckLen16(cdb->CDB16.OperationCode);
    }
    //TraceBugCheck(("Bad CDB Length %d\n", len));
    return XENCDB_SCSIOP_INVALID;
}
FORCEINLINE UCHAR Cdb_Operation(const SCSI_REQUEST_BLOCK* const srb)
{
    return Cdb_OperationRaw(srb->CdbLength, srb->Cdb);
}
FORCEINLINE UCHAR Cdb_OperationEx(const SCSI_REQUEST_BLOCK* const srb)
{
    UCHAR ret = Cdb_Operation(srb);
    /* roll SCSIOP_READ* into SCSIOP_READ and SCSIOP_WRITE* into SCSIOP_WRITE */
    switch (ret) {
    case SCSIOP_READ6:
    case SCSIOP_READ12:
    case SCSIOP_READ16:
        return SCSIOP_READ;
    case SCSIOP_WRITE6:
    case SCSIOP_WRITE12:
    case SCSIOP_WRITE16:
        return SCSIOP_WRITE;
    case SCSIOP_SYNCHRONIZE_CACHE16:
        return SCSIOP_SYNCHRONIZE_CACHE;
    default:
        return ret;
    }
}
FORCEINLINE ULONG Cdb_TransferBlockRaw(UCHAR len, const UCHAR* _cdb)
{
    CDB* const cdb = (CDB*)_cdb;
    switch (len) {
    case 6:
        return cdb->CDB6READWRITE.TransferBlocks;
    case 10:
        return cdb->CDB10.TransferBlocksLsb | ((ULONG)cdb->CDB10.TransferBlocksMsb << 8);
    case 12:
        return Cdb_get_big_endian_dword(cdb->CDB12.TransferLength);
    case 16:
        return Cdb_get_big_endian_dword(cdb->CDB16.TransferLength);
    default:
        //TraceBugCheck(("Bad CDB Length %d\n", len));
        return 0;
    }
}
FORCEINLINE ULONG Cdb_TransferBlock(const SCSI_REQUEST_BLOCK* const srb)
{
    return Cdb_TransferBlockRaw(srb->CdbLength, srb->Cdb);
}
FORCEINLINE ULONG64 Cdb_LogicalBlockRaw(UCHAR len, const UCHAR* _cdb)
{
    CDB* const cdb = (CDB*)_cdb;
    switch (len) {
    case 6:
        return cdb->CDB6READWRITE.LogicalBlockLsb |
            ((ULONG)cdb->CDB6READWRITE.LogicalBlockMsb0 << 8) |
            ((ULONG)cdb->CDB6READWRITE.LogicalBlockMsb1 << 16);
    case 10:
        return cdb->CDB10.LogicalBlockByte3 |
            ((ULONG)cdb->CDB10.LogicalBlockByte2 << 8) |
            ((ULONG)cdb->CDB10.LogicalBlockByte1 << 16) |
            ((ULONG)cdb->CDB10.LogicalBlockByte0 << 24);
   case 12:
        return Cdb_get_big_endian_dword(cdb->CDB12.LogicalBlock);
    case 16:
        return Cdb_get_big_endian_qword(cdb->CDB16.LogicalBlock);
    default:
        //TraceBugCheck(("Bad CDB Length %d\n", len));
        return 0;
    }
}
FORCEINLINE ULONG64 Cdb_LogicalBlock(const SCSI_REQUEST_BLOCK* const srb)
{
    return Cdb_LogicalBlockRaw(srb->CdbLength, srb->Cdb);
}

FORCEINLINE ULONG Cdb_AllocationLength(const SCSI_REQUEST_BLOCK* const srb)
{
    CDB* const cdb = (CDB*)srb->Cdb;

    switch (Cdb_Operation(srb)) {
    case SCSIOP_REPORT_LUNS:
        return Cdb_get_big_endian_dword(cdb->REPORT_LUNS.AllocationLength);
    case SCSIOP_MODE_SENSE:
        return cdb->MODE_SENSE.AllocationLength;
    case SCSIOP_MODE_SENSE10:
        return Cdb_get_big_endian_word(cdb->MODE_SENSE10.AllocationLength);
    default:
        return 0;
    }
}

FORCEINLINE UCHAR Cdb_PMIRaw(UCHAR len, const UCHAR* _cdb)
{
    CDB* const cdb = (CDB*)_cdb;

    switch (len) {
    case 10:
        return (_cdb[8] & 0x01) > 0 ? 1 : 0;
    case 16:
        return cdb->READ_CAPACITY16.PMI;
    default:
        return 0;
    }
}

FORCEINLINE UCHAR Cdb_PMI(const SCSI_REQUEST_BLOCK* const srb)
{
    return Cdb_PMIRaw(srb->CdbLength, srb->Cdb);
}

FORCEINLINE UCHAR Cdb_ModeSensePageCodeRaw(UCHAR len, const UCHAR* _cdb)
{
    CDB* const cdb = (CDB*)_cdb;

    switch (len) {
    case 6:
        return cdb->MODE_SENSE.PageCode;
    case 10:
        return cdb->MODE_SENSE10.PageCode;
    default:
        return 0;
    }
}

FORCEINLINE UCHAR Cdb_InquiryPageCodeRaw(UCHAR len, const UCHAR* _cdb)
{
    CDB* const cdb = (CDB*)_cdb;

    switch (len) {
    case 6:
        return cdb->CDB6INQUIRY3.PageCode;
    default:
        return 0;
    }
}

FORCEINLINE UCHAR Cdb_PageCode(const SCSI_REQUEST_BLOCK* const srb)
{
    if (Cdb_Operation(srb) == SCSIOP_INQUIRY)
        return Cdb_InquiryPageCodeRaw(srb->CdbLength, srb->Cdb);
    else
        return Cdb_ModeSensePageCodeRaw(srb->CdbLength, srb->Cdb);
}

FORCEINLINE UCHAR Cdb_DbdRaw(UCHAR len, const UCHAR* _cdb)
{
    CDB* const cdb = (CDB*)_cdb;

    switch (len) {
    case 6:
        return cdb->MODE_SENSE.Dbd;
    case 10:
        return cdb->MODE_SENSE10.Dbd;
    default:
        return 0;
    }
}

FORCEINLINE UCHAR Cdb_Dbd(const SCSI_REQUEST_BLOCK* const srb)
{
    return Cdb_DbdRaw(srb->CdbLength, srb->Cdb);
}

FORCEINLINE UCHAR Cdb_EVPDRaw(UCHAR len, const UCHAR* _cdb)
{
    CDB* const cdb = (CDB*)_cdb;

    switch (len) {
    case 6:
        return cdb->CDB6INQUIRY3.EnableVitalProductData;
    default:
        return 0;
    }
}

FORCEINLINE UCHAR Cdb_EVPD(const SCSI_REQUEST_BLOCK* const srb)
{
    return Cdb_EVPDRaw(srb->CdbLength, srb->Cdb);
}

FORCEINLINE const char* Cdb_OperationName(UCHAR op)
{
#define _SCSIOP_NAME(x) case x: return #x;
    switch (op) {
        _SCSIOP_NAME(SCSIOP_INQUIRY)
        _SCSIOP_NAME(SCSIOP_REPORT_LUNS)
        _SCSIOP_NAME(SCSIOP_READ_CAPACITY)
        _SCSIOP_NAME(SCSIOP_READ_CAPACITY16)
        _SCSIOP_NAME(SCSIOP_READ)
        _SCSIOP_NAME(SCSIOP_READ6)
        _SCSIOP_NAME(SCSIOP_READ12)
        _SCSIOP_NAME(SCSIOP_READ16)
        _SCSIOP_NAME(SCSIOP_WRITE)
        _SCSIOP_NAME(SCSIOP_WRITE6)
        _SCSIOP_NAME(SCSIOP_WRITE12)
        _SCSIOP_NAME(SCSIOP_WRITE16)
        _SCSIOP_NAME(SCSIOP_VERIFY)
        _SCSIOP_NAME(SCSIOP_START_STOP_UNIT)
        _SCSIOP_NAME(SCSIOP_SYNCHRONIZE_CACHE)
        _SCSIOP_NAME(SCSIOP_MEDIUM_REMOVAL)
        _SCSIOP_NAME(SCSIOP_TEST_UNIT_READY)
        _SCSIOP_NAME(SCSIOP_MODE_SENSE)
        _SCSIOP_NAME(SCSIOP_MODE_SENSE10)
        _SCSIOP_NAME(SCSIOP_MODE_SELECT)
        _SCSIOP_NAME(SCSIOP_MODE_SELECT10)
        _SCSIOP_NAME(SCSIOP_REQUEST_SENSE)
        _SCSIOP_NAME(SCSIOP_RESERVE_UNIT)
        _SCSIOP_NAME(SCSIOP_RESERVE_UNIT10)
        _SCSIOP_NAME(SCSIOP_RELEASE_UNIT)
        _SCSIOP_NAME(SCSIOP_RELEASE_UNIT10)
        /* add to this as you find <unknown> entries */
    default: return "<unknown>";
    }
#undef _SCSIOP_NAME
}

#endif
