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

#ifndef _XENVBD_NAMES_H
#define _XENVBD_NAMES_H

#include "..\..\include\xenvbd-storport.h"
#include "..\..\include\xen.h"

static FORCEINLINE const PCHAR
XenbusStateName(
    IN  XenbusState     State
    )
{
    switch (State) {
    case XenbusStateUnknown:        return "Unknown";
    case XenbusStateInitialising:   return "Initialising";
    case XenbusStateInitWait:       return "InitWait";
    case XenbusStateInitialised:    return "Initialised";
    case XenbusStateConnected:      return "Connected";
    case XenbusStateClosing:        return "Closing";
    case XenbusStateClosed:         return "Closed";
    case XenbusStateReconfiguring:  return "Reconfiguring";
    case XenbusStateReconfigured:   return "Reconfigured";
    default:                        return "UNKNOWN";
    }
}

static FORCEINLINE const PCHAR
SrbStatusName(
    IN  ULONG       Status
    )
{
    switch (Status) {
    case SRB_STATUS_SUCCESS:            return "SUCCESS";
    case SRB_STATUS_ERROR:              return "ERROR";
    case SRB_STATUS_INVALID_REQUEST:    return "INVALID_REQUEST";
    case SRB_STATUS_DATA_OVERRUN:       return "DATA_OVERRUN";
    case SRB_STATUS_ABORT_FAILED:       return "ABORT_FAILED";
    case SRB_STATUS_NO_DEVICE:          return "NO_DEVICE";
    case SRB_STATUS_INVALID_PATH_ID:    return "INVALID_PATH_ID";
    case SRB_STATUS_INVALID_LUN:        return "INVALID_LUN";
    default:                            return "UNKNOWN";
    }
}

static FORCEINLINE const PCHAR
StorStatusName(
    IN  ULONG       Status
    )
{
    switch (Status) {
    case STOR_STATUS_SUCCESS:           return "Success";
    case STOR_STATUS_NOT_IMPLEMENTED:   return "NotImplemented";
    case STOR_STATUS_INVALID_PARAMETER: return "InvalidParameter";
    default:                            return "UNKNOWN";
    }
}
static FORCEINLINE const PCHAR
ScsiAdapterControlTypeName(
    IN  SCSI_ADAPTER_CONTROL_TYPE   ControlType
    )
{
#define _SCSI_CONTROL_TYPE_NAME(_type)      \
    case Scsi ## _type:                     \
    return #_type;

    switch (ControlType) {
    _SCSI_CONTROL_TYPE_NAME(QuerySupportedControlTypes);
    _SCSI_CONTROL_TYPE_NAME(StopAdapter);
    _SCSI_CONTROL_TYPE_NAME(RestartAdapter);
    _SCSI_CONTROL_TYPE_NAME(SetBootConfig);
    _SCSI_CONTROL_TYPE_NAME(SetRunningConfig);
    default:    return "UNKNOWN";
    }

#undef _SCSI_CONTROL_TYPE_NAME
}
static FORCEINLINE const PCHAR
StorPnPActionName(
    IN  STOR_PNP_ACTION         Action
    )
{
    switch (Action) {
    case StorStartDevice:	            return "StartDevice";
    case StorStopDevice:                return "StopDevice";
    case StorQueryCapabilities:         return "QueryCapabilities";
    case StorFilterResourceRequirements:return "FilterResourceRequirements";
    case StorSurpriseRemoval:           return "SurpriseRemoval";
    default:                            return "UNKNOWN";
    }
}
static FORCEINLINE const PCHAR
StorDeviceStateName(
    IN  STOR_DEVICE_POWER_STATE     State
    )
{
    switch (State) {
    case StorPowerDeviceUnspecified:    return "Unspecified";
    case StorPowerDeviceD0:             return "D0";
    case StorPowerDeviceD1:             return "D1";
    case StorPowerDeviceD2:             return "D2";
    case StorPowerDeviceD3:             return "D3";
    case StorPowerDeviceMaximum:        return "Maximum";
    default:                            return "UNKNOWN";
    }
}
static FORCEINLINE const PCHAR
StorPowerActionName(
    IN  STOR_POWER_ACTION           Action
    )
{
    switch (Action) {
    case StorPowerActionNone:           return "None";
    case StorPowerActionReserved:       return "Reserved";
    case StorPowerActionSleep:          return "Sleep";
    case StorPowerActionHibernate:      return "Hibernate";
    case StorPowerActionShutdown:       return "Shutdown";
    case StorPowerActionShutdownReset:  return "ShutdownReset";
    case StorPowerActionShutdownOff:    return "ShutdownOff";
    case StorPowerActionWarmEject:      return "WarmEject";
    default:                            return "UNKNOWN";
    }
}

static FORCEINLINE const PCHAR
PowerTypeName(
    IN  POWER_STATE_TYPE    Type
    )
{
#define _POWER_TYPE_NAME(_Type) \
        case _Type:             \
            return #_Type;

    switch (Type) {
    _POWER_TYPE_NAME(SystemPowerState);
    _POWER_TYPE_NAME(DevicePowerState);
    default:
        break;
    }

    return ("UNKNOWN");
#undef  _POWER_ACTION_NAME
}

static FORCEINLINE const PCHAR
PowerSystemStateName(
    IN  SYSTEM_POWER_STATE State
    )
{
#define _POWER_SYSTEM_STATE_NAME(_State)    \
        case PowerSystem ## _State:         \
            return #_State;

    switch (State) {
    _POWER_SYSTEM_STATE_NAME(Unspecified);
    _POWER_SYSTEM_STATE_NAME(Working);
    _POWER_SYSTEM_STATE_NAME(Sleeping1);
    _POWER_SYSTEM_STATE_NAME(Sleeping2);
    _POWER_SYSTEM_STATE_NAME(Sleeping3);
    _POWER_SYSTEM_STATE_NAME(Hibernate);
    _POWER_SYSTEM_STATE_NAME(Shutdown);
    _POWER_SYSTEM_STATE_NAME(Maximum);
    default:
        break;
    }

    return ("UNKNOWN");
#undef  _POWER_SYSTEM_STATE_NAME
}

static FORCEINLINE const PCHAR
PowerDeviceStateName(
    IN  DEVICE_POWER_STATE State
    )
{
#define _POWER_DEVICE_STATE_NAME(_State)    \
        case PowerDevice ## _State:         \
            return #_State;

    switch (State) {
    _POWER_DEVICE_STATE_NAME(Unspecified);
    _POWER_DEVICE_STATE_NAME(D0);
    _POWER_DEVICE_STATE_NAME(D1);
    _POWER_DEVICE_STATE_NAME(D2);
    _POWER_DEVICE_STATE_NAME(D3);
    _POWER_DEVICE_STATE_NAME(Maximum);
    default:
        break;
    }

    return ("UNKNOWN");
#undef  _POWER_DEVICE_STATE_NAME
}

static FORCEINLINE const PCHAR
PowerActionName(
    IN  POWER_ACTION    Type
    )
{
#define _POWER_ACTION_NAME(_Type)   \
        case PowerAction ## _Type:  \
            return #_Type;

    switch (Type) {
    _POWER_ACTION_NAME(None);
    _POWER_ACTION_NAME(Reserved);
    _POWER_ACTION_NAME(Sleep);
    _POWER_ACTION_NAME(Hibernate);
    _POWER_ACTION_NAME(Shutdown);
    _POWER_ACTION_NAME(ShutdownReset);
    _POWER_ACTION_NAME(ShutdownOff);
    _POWER_ACTION_NAME(WarmEject);
    default:
        break;
    }

    return ("UNKNOWN");
#undef  _POWER_ACTION_NAME
}

static FORCEINLINE const PCHAR
PowerMinorFunctionName(
    IN  ULONG   MinorFunction
    )
{
#define _POWER_MINOR_FUNCTION_NAME(_Function)   \
    case IRP_MN_ ## _Function:                  \
        return #_Function;

    switch (MinorFunction) {
    _POWER_MINOR_FUNCTION_NAME(WAIT_WAKE);
    _POWER_MINOR_FUNCTION_NAME(POWER_SEQUENCE);
    _POWER_MINOR_FUNCTION_NAME(SET_POWER);
    _POWER_MINOR_FUNCTION_NAME(QUERY_POWER);

    default:
        return "UNKNOWN";
    }

#undef  _POWER_MINOR_FUNCTION_NAME
}

static FORCEINLINE const PCHAR
PnpMinorFunctionName(
    IN  ULONG   Function
    )
{
#define _PNP_MINOR_FUNCTION_NAME(_Function) \
    case IRP_MN_ ## _Function:              \
        return #_Function;

    switch (Function) {
    _PNP_MINOR_FUNCTION_NAME(START_DEVICE);
    _PNP_MINOR_FUNCTION_NAME(QUERY_REMOVE_DEVICE);
    _PNP_MINOR_FUNCTION_NAME(REMOVE_DEVICE);
    _PNP_MINOR_FUNCTION_NAME(CANCEL_REMOVE_DEVICE);
    _PNP_MINOR_FUNCTION_NAME(STOP_DEVICE);
    _PNP_MINOR_FUNCTION_NAME(QUERY_STOP_DEVICE);
    _PNP_MINOR_FUNCTION_NAME(CANCEL_STOP_DEVICE);
    _PNP_MINOR_FUNCTION_NAME(QUERY_DEVICE_RELATIONS);
    _PNP_MINOR_FUNCTION_NAME(QUERY_INTERFACE);
    _PNP_MINOR_FUNCTION_NAME(QUERY_CAPABILITIES);
    _PNP_MINOR_FUNCTION_NAME(QUERY_RESOURCES);
    _PNP_MINOR_FUNCTION_NAME(QUERY_RESOURCE_REQUIREMENTS);
    _PNP_MINOR_FUNCTION_NAME(QUERY_DEVICE_TEXT);
    _PNP_MINOR_FUNCTION_NAME(FILTER_RESOURCE_REQUIREMENTS);
    _PNP_MINOR_FUNCTION_NAME(READ_CONFIG);
    _PNP_MINOR_FUNCTION_NAME(WRITE_CONFIG);
    _PNP_MINOR_FUNCTION_NAME(EJECT);
    _PNP_MINOR_FUNCTION_NAME(SET_LOCK);
    _PNP_MINOR_FUNCTION_NAME(QUERY_ID);
    _PNP_MINOR_FUNCTION_NAME(QUERY_PNP_DEVICE_STATE);
    _PNP_MINOR_FUNCTION_NAME(QUERY_BUS_INFORMATION);
    _PNP_MINOR_FUNCTION_NAME(DEVICE_USAGE_NOTIFICATION);
    _PNP_MINOR_FUNCTION_NAME(SURPRISE_REMOVAL);
    //_PNP_MINOR_FUNCTION_NAME(QUERY_LEGACY_BUS_INFORMATION);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _PNP_MINOR_FUNCTION_NAME
}

static FORCEINLINE const PCHAR
PartialResourceDescriptorTypeName(
    IN  UCHAR   Type
    )
{
#define _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(_Type)   \
    case CmResourceType ## _Type:                       \
        return #_Type;

    switch (Type) {
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(Null);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(Port);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(Interrupt);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(Memory);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(Dma);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(DeviceSpecific);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(BusNumber);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(MemoryLarge);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(ConfigData);
    _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME(DevicePrivate);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _PARTIAL_RESOURCE_DESCRIPTOR_TYPE_NAME
}

static FORCEINLINE const PCHAR
PnPMinorFunction(
    IN  ULONG   Func
    )
{
#define _PNP_MINOR_FUNC_NAME(_func)     \
    case IRP_MN_ ## _func:              \
    return #_func;

    switch (Func) {
    _PNP_MINOR_FUNC_NAME(CANCEL_REMOVE_DEVICE);
    _PNP_MINOR_FUNC_NAME(CANCEL_STOP_DEVICE);
    _PNP_MINOR_FUNC_NAME(DEVICE_USAGE_NOTIFICATION);
    _PNP_MINOR_FUNC_NAME(EJECT);
    _PNP_MINOR_FUNC_NAME(FILTER_RESOURCE_REQUIREMENTS);
    _PNP_MINOR_FUNC_NAME(QUERY_BUS_INFORMATION);
    _PNP_MINOR_FUNC_NAME(QUERY_CAPABILITIES);
    _PNP_MINOR_FUNC_NAME(QUERY_DEVICE_RELATIONS);
    _PNP_MINOR_FUNC_NAME(QUERY_DEVICE_TEXT);
    _PNP_MINOR_FUNC_NAME(QUERY_ID);
    _PNP_MINOR_FUNC_NAME(QUERY_INTERFACE);
    _PNP_MINOR_FUNC_NAME(QUERY_PNP_DEVICE_STATE);
    _PNP_MINOR_FUNC_NAME(QUERY_REMOVE_DEVICE);
    _PNP_MINOR_FUNC_NAME(QUERY_RESOURCE_REQUIREMENTS);
    _PNP_MINOR_FUNC_NAME(QUERY_RESOURCES);
    _PNP_MINOR_FUNC_NAME(QUERY_STOP_DEVICE);
    _PNP_MINOR_FUNC_NAME(READ_CONFIG);
    _PNP_MINOR_FUNC_NAME(REMOVE_DEVICE);
    _PNP_MINOR_FUNC_NAME(SET_LOCK);
    _PNP_MINOR_FUNC_NAME(START_DEVICE);
    _PNP_MINOR_FUNC_NAME(STOP_DEVICE);
    _PNP_MINOR_FUNC_NAME(SURPRISE_REMOVAL);
    _PNP_MINOR_FUNC_NAME(WRITE_CONFIG);
    default:   
        return "UNKNOWN";
    };


#undef _PNP_MINOR_FUNC_NAME
}

static FORCEINLINE const PCHAR
QueryDeviceRelationsName(
    IN  ULONG   Type
    )
{
    switch (Type) {
    case BusRelations:          return "Bus";
    case TargetDeviceRelation:  return "TargetDevice";
    case RemovalRelations:      return "Removal";
    case EjectionRelations:     return "Ejection";
    default:                    return "UNKNOWN";
    }
}

#endif // _XENVBD_NAMES_H