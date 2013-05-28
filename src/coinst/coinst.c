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

#define INITGUID

#include <windows.h>
#include <setupapi.h>
#include <stdio.h>
#include <stdlib.h>

#pragma prefast(push)
#pragma prefast(disable: 6001 6054 28196, "strsafe.h PreFast warnings")
#include <strsafe.h>
#pragma prefast(pop)

#include <malloc.h>

__user_code;

#define MAXIMUM_BUFFER_SIZE 1024

static VOID
#pragma prefast(suppress:6262) // Function uses '1036' bytes of stack: exceeds /analyze:stacksize'1024'
__Log(
    IN  const CHAR  *Format,
    IN  ...
    )
{
    TCHAR               Buffer[MAXIMUM_BUFFER_SIZE];
    va_list             Arguments;
    size_t              Length;
    SP_LOG_TOKEN        LogToken;
    DWORD               Category;
    DWORD               Flags;
    HRESULT             Result;

    va_start(Arguments, Format);
    Result = StringCchVPrintf(Buffer, MAXIMUM_BUFFER_SIZE, Format, Arguments);
    va_end(Arguments);

    if (Result != S_OK && Result != STRSAFE_E_INSUFFICIENT_BUFFER)
        return;

    Result = StringCchLength(Buffer, MAXIMUM_BUFFER_SIZE, &Length);
    if (Result != S_OK)
        return;

    LogToken = SetupGetThreadLogToken();
    Category = TXTLOG_VENDOR;
    Flags = TXTLOG_DETAILS;

    SetupWriteTextLog(LogToken, Category, Flags, Buffer);
    Length = __min(MAXIMUM_BUFFER_SIZE, Length + 4);

    __analysis_assume(Length >= 4);
    __analysis_assume(Length < MAXIMUM_BUFFER_SIZE);
    Buffer[Length - 1] = '\0';
    Buffer[Length - 2] = '\n';
    Buffer[Length - 3] = '\r';

    OutputDebugString(Buffer);
}

#define Log(_Format, ...) \
        __Log(__MODULE__ "|" __FUNCTION__ ": " _Format, __VA_ARGS__)

static PTCHAR
GetErrorMessage(
    IN  DWORD   Error
    )
{
    PTCHAR      Message;
    ULONG       Index;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                  FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL,
                  Error,
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR)&Message,
                  0,
                  NULL);

    for (Index = 0; Message[Index] != '\0'; Index++) {
        if (Message[Index] == '\r' || Message[Index] == '\n') {
            Message[Index] = '\0';
            break;
        }
    }

    return Message;
}

static const CHAR *
FunctionName(
    IN  DI_FUNCTION Function
    )
{
#define _NAME(_Function)        \
        case DIF_ ## _Function: \
            return #_Function;

    switch (Function) {
    _NAME(INSTALLDEVICE);
    _NAME(REMOVE);
    _NAME(SELECTDEVICE);
    _NAME(ASSIGNRESOURCES);
    _NAME(PROPERTIES);
    _NAME(FIRSTTIMESETUP);
    _NAME(FOUNDDEVICE);
    _NAME(SELECTCLASSDRIVERS);
    _NAME(VALIDATECLASSDRIVERS);
    _NAME(INSTALLCLASSDRIVERS);
    _NAME(CALCDISKSPACE);
    _NAME(DESTROYPRIVATEDATA);
    _NAME(VALIDATEDRIVER);
    _NAME(MOVEDEVICE);
    _NAME(DETECT);
    _NAME(INSTALLWIZARD);
    _NAME(DESTROYWIZARDDATA);
    _NAME(PROPERTYCHANGE);
    _NAME(ENABLECLASS);
    _NAME(DETECTVERIFY);
    _NAME(INSTALLDEVICEFILES);
    _NAME(ALLOW_INSTALL);
    _NAME(SELECTBESTCOMPATDRV);
    _NAME(REGISTERDEVICE);
    _NAME(NEWDEVICEWIZARD_PRESELECT);
    _NAME(NEWDEVICEWIZARD_SELECT);
    _NAME(NEWDEVICEWIZARD_PREANALYZE);
    _NAME(NEWDEVICEWIZARD_POSTANALYZE);
    _NAME(NEWDEVICEWIZARD_FINISHINSTALL);
    _NAME(INSTALLINTERFACES);
    _NAME(DETECTCANCEL);
    _NAME(REGISTER_COINSTALLERS);
    _NAME(ADDPROPERTYPAGE_ADVANCED);
    _NAME(ADDPROPERTYPAGE_BASIC);
    _NAME(TROUBLESHOOTER);
    _NAME(POWERMESSAGEWAKE);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _NAME
}

#define SERVICES_KEY "SYSTEM\\CurrentControlSet\\Services"

#define SERVICE_KEY(_Driver)    \
        SERVICES_KEY ## "\\" ## #_Driver ## "\\Parameters"

#define DEVICE_LIST_SIZE 9

static BOOLEAN
InstallVbdDevices()
{
    HKEY                    Key;
    LONG                    Error;
    TCHAR                   Devices[DEVICE_LIST_SIZE];

    Log("====>");

    Error = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                     SERVICE_KEY(XENFILT),
                     0,
                     KEY_ALL_ACCESS,
                     &Key);
    if (Error != ERROR_SUCCESS)
        goto fail1;

    memset(Devices, 0, DEVICE_LIST_SIZE);
    Devices[0] = '0'; // Devices[1] = '\0';
    Devices[2] = '1'; // Devices[3] = '\0';
    Devices[4] = '2'; // Devices[5] = '\0';
    Devices[6] = '3'; // Devices[7] = '\0';
    // Devices[8] = '\0';

    Error = RegSetValueEx(Key,
                          "VBD",
                          0,
                          REG_MULTI_SZ,
                          (PBYTE)Devices,
                          DEVICE_LIST_SIZE * sizeof(TCHAR));
    if (Error != ERROR_SUCCESS)
        goto fail2;

    RegCloseKey(Key);

    Log("<====");

    return TRUE;

fail2:
    Log("fail2");

    RegCloseKey(Key);

fail1:
    {
        PTCHAR  Message;

        Message = GetErrorMessage(GetLastError());
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
RemoveVbdDevices()
{
    HKEY                    Key;
    DWORD                   Size;
    DWORD                   Type;
    LONG                    Error;

    Log("====>");

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                     SERVICE_KEY(XENFILT),
                     0,
                     KEY_ALL_ACCESS,
                     &Key) != ERROR_SUCCESS)
        goto fail1;

    Size = 0;
    Error = RegQueryValueEx(Key,
                            "VBD",
                            NULL,
                            &Type,
                            NULL,
                            &Size);
    if (Error != ERROR_SUCCESS)
        goto fail2;

    if (Type != REG_MULTI_SZ) {
        SetLastError(ERROR_BAD_FORMAT);
        goto fail3;
    }

    Error = RegDeleteValue(Key,
                           "VBD");
    if (Error != ERROR_SUCCESS)
        goto fail4;

    RegCloseKey(Key);

    Log("<====");

    return TRUE;

fail4:
    Log("fail4");

fail3:
    Log("fail3");

fail2:
    Log("fail2");

    RegCloseKey(Key);

fail1:
    {
        PTCHAR  Message;

        Message = GetErrorMessage(GetLastError());
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
InstallUnplugClass(
    IN  PTCHAR              Class
    )
{
    HKEY                    Key;
    DWORD                   Size;
    DWORD                   Type;
    LONG                    Error;
    PTCHAR                  Classes;
    ULONG                   Offset;
    BOOLEAN                 Added;

    Log("====>");

    Added = FALSE;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                     SERVICE_KEY(XENFILT),
                     0,
                     KEY_ALL_ACCESS,
                     &Key) != ERROR_SUCCESS)
        goto fail1;

    Size = 0;
    Error = RegQueryValueEx(Key,
                            "UnplugClasses",
                            NULL,
                            &Type,
                            NULL,
                            &Size);
    if (Error != ERROR_SUCCESS) {
        if (Error != ERROR_FILE_NOT_FOUND)
            goto fail2;

        Size = sizeof (TCHAR);
        Type = REG_MULTI_SZ;
    }

    if (Type != REG_MULTI_SZ) {
        SetLastError(ERROR_BAD_FORMAT);
        goto fail3;
    }

    Classes = malloc(Size + strlen(Class) + sizeof (TCHAR));
    if (Classes == NULL)
        goto fail4;

    memset(Classes, 0, Size + strlen(Class) + sizeof (TCHAR));

    Offset = 0;
    if (Size != sizeof (TCHAR)) {
        Error = RegQueryValueEx(Key,
                                "UnplugClasses",
                                NULL,
                                NULL,
                                (PBYTE)Classes,
                                &Size);
        if (Error != ERROR_SUCCESS)
            goto fail5;

        while (Classes[Offset] != '\0') {
            ULONG   Length;

            Log("Found %s", &Classes[Offset]);
            Length = (ULONG)strlen(&Classes[Offset]) / sizeof (TCHAR);

            if (_stricmp(&Classes[Offset], Class) == 0)
                goto done;

            Offset += Length + 1;
        }
    }

    memmove(&Classes[Offset], Class, strlen(Class));
    Log("Added %s", Class);

    Error = RegSetValueEx(Key,
                          "UnplugClasses",
                          0,
                          Type,
                          (PBYTE)Classes,
                          (DWORD)(Size + strlen(Class) + sizeof (TCHAR)));
    if (Error != ERROR_SUCCESS)
        goto fail6;

    Added = TRUE;

done:
    free(Classes);
    RegCloseKey(Key);

    Log("<====");

    return Added;

fail6:
    Log("fail6");

fail5:
    Log("fail5");

    free(Classes);

fail4:
    Log("fail4");

fail3:
    Log("fail3");

fail2:
    Log("fail2");

    RegCloseKey(Key);

fail1:
    {
        PTCHAR  Message;

        Message = GetErrorMessage(GetLastError());
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static BOOLEAN
RemoveUnplugClass(
    IN  PTCHAR              Class
    )
{
    HKEY                    Key;
    DWORD                   Size;
    DWORD                   Type;
    LONG                    Error;
    PTCHAR                  Classes;
    ULONG                   Offset;
    ULONG                   Length;
    BOOLEAN                 Removed;

    Log("====>");

    Removed = FALSE;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                     SERVICE_KEY(XENFILT),
                     0,
                     KEY_ALL_ACCESS,
                     &Key) != ERROR_SUCCESS)
        goto fail1;

    Size = 0;
    Error = RegQueryValueEx(Key,
                            "UnplugClasses",
                            NULL,
                            &Type,
                            NULL,
                            &Size);
    if (Error != ERROR_SUCCESS)
        goto fail2;

    if (Type != REG_MULTI_SZ) {
        SetLastError(ERROR_BAD_FORMAT);
        goto fail3;
    }

    Classes = malloc(Size);
    if (Classes == NULL)
        goto fail4;

    memset(Classes, 0, Size);

    Error = RegQueryValueEx(Key,
                            "UnplugClasses",
                            NULL,
                            NULL,
                            (PBYTE)Classes,
                            &Size);
    if (Error != ERROR_SUCCESS)
        goto fail5;

    Offset = 0;
    Length = 0;
    while (Classes[Offset] != '\0') {
        Log("Found %s", &Classes[Offset]);
        Length = (ULONG)strlen(&Classes[Offset]) / sizeof (TCHAR);

        if (_stricmp(&Classes[Offset], Class) == 0)
            break;

        Offset += Length + 1;
    }

    if (Classes[Offset] == '\0')
        goto done;

    memmove(&Classes[Offset],
            &Classes[Offset + Length + 1],
            Size - ((Length + 1) * sizeof (TCHAR)));
    Log("Removed %s", Class);

    Error = RegSetValueEx(Key,
                          "UnplugClasses",
                          0,
                          Type,
                          (PBYTE)Classes,
                          Size - ((Length + 1) * sizeof (TCHAR)));
    if (Error != ERROR_SUCCESS)
        goto fail6;

    Removed = TRUE;

done:
    free(Classes);
    RegCloseKey(Key);

    Log("<====");

    return Removed;

fail6:
    Log("fail6");

fail5:
    Log("fail5");

    free(Classes);

fail4:
    Log("fail4");

fail3:
    Log("fail3");

fail2:
    Log("fail2");

    RegCloseKey(Key);

fail1:
    {
        PTCHAR  Message;

        Message = GetErrorMessage(GetLastError());
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }

    return FALSE;
}

static VOID
RequestReboot(
    IN  HDEVINFO            DeviceInfoSet,
    IN  PSP_DEVINFO_DATA    DeviceInfoData
    )
{
    SP_DEVINSTALL_PARAMS    DeviceInstallParams;

    Log("====>");

    DeviceInstallParams.cbSize = sizeof (DeviceInstallParams);

    if (!SetupDiGetDeviceInstallParams(DeviceInfoSet,
                                       DeviceInfoData,
                                       &DeviceInstallParams))
        goto fail1;

    DeviceInstallParams.Flags |= DI_NEEDREBOOT;

    if (!SetupDiSetDeviceInstallParams(DeviceInfoSet,
                                       DeviceInfoData,
                                       &DeviceInstallParams))
        goto fail2;

    Log("<====");
    return;

fail2:
    Log("fail2");

fail1:
    {
        PTCHAR  Message;

        Message = GetErrorMessage(GetLastError());
        Log("fail1 (%s)", Message);
        LocalFree(Message);
    }
}

static DECLSPEC_NOINLINE DWORD
DifInstall(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    DWORD                           Error;

    if (!Context->PostProcessing) {
        Log("PreProcessing");

        Error = ERROR_DI_POSTPROCESSING_REQUIRED; 
    } else {
        Log("PostProcessing (%08x)",
            Context->InstallResult);

        if (Context->InstallResult == NO_ERROR) {
            InstallUnplugClass("VBD");
            InstallVbdDevices();
            RequestReboot(DeviceInfoSet, DeviceInfoData);
        }

        Error = Context->InstallResult;
    }

    return Error;
}

static DECLSPEC_NOINLINE DWORD
DifRemove(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    DWORD                           Error;

    if (!Context->PostProcessing) {
        Log("PreProcessing");

        Error = ERROR_DI_POSTPROCESSING_REQUIRED; 
    } else {
        Log("PostProcessing (%08x)",
            Context->InstallResult);

        if (Context->InstallResult == NO_ERROR) {
            RemoveVbdDevices();
            RemoveUnplugClass("VBD");
            RequestReboot(DeviceInfoSet, DeviceInfoData);
        }

        Error = Context->InstallResult;
    }

    return Error;
}

static FORCEINLINE DWORD
DifInstallDevice(
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    SP_DRVINFO_DATA         DriverInfoData;
    BOOLEAN                 DriverInfoAvailable;

    DriverInfoData.cbSize = sizeof (DriverInfoData);
    DriverInfoAvailable = SetupDiGetSelectedDriver(DeviceInfoSet,
                                                    DeviceInfoData,
                                                    &DriverInfoData) ?
                            TRUE :
                            FALSE;

    // If there is no driver information then the NULL driver is being
    // installed. Treat this as we would a DIF_REMOVE.
    if (DriverInfoAvailable)
        return DifInstall(DeviceInfoSet, DeviceInfoData, Context);
    else
        return DifRemove(DeviceInfoSet, DeviceInfoData, Context);
}

DWORD CALLBACK
Entry(
    IN  DI_FUNCTION                 Function,
    IN  HDEVINFO                    DeviceInfoSet,
    IN  PSP_DEVINFO_DATA            DeviceInfoData,
    IN  PCOINSTALLER_CONTEXT_DATA   Context
    )
{
    DWORD                           Error;

    switch (Function) {
    case DIF_INSTALLDEVICE:
        Error = DifInstallDevice(DeviceInfoSet, DeviceInfoData, Context);
        break;

    case DIF_REMOVE:
        Error = DifRemove(DeviceInfoSet, DeviceInfoData, Context);
        break;
    
    default:
        if (!Context->PostProcessing) {
            Log("%s PreProcessing",
                FunctionName(Function));

            Error = NO_ERROR;
        } else {
            Log("%s PostProcessing (%08x)",
                FunctionName(Function),
                Context->InstallResult);

            Error = Context->InstallResult;
        }
        break;
    }

    return Error;
}

DWORD CALLBACK
Version(
    IN  HWND        Window,
    IN  HINSTANCE   Module,
    IN  PTCHAR      Buffer,
    IN  INT         Reserved
    )
{
    UNREFERENCED_PARAMETER(Window);
    UNREFERENCED_PARAMETER(Module);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Reserved);

    Log("%s %s",
        __DATE__,
        __TIME__);

    return NO_ERROR;
}

static FORCEINLINE const CHAR *
ReasonName(
    IN  DWORD       Reason
    )
{
#define _NAME(_Reason)          \
        case DLL_ ## _Reason:   \
            return #_Reason;

    switch (Reason) {
    _NAME(PROCESS_ATTACH);
    _NAME(PROCESS_DETACH);
    _NAME(THREAD_ATTACH);
    _NAME(THREAD_DETACH);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _NAME
}

BOOL WINAPI
DllMain(
    IN  HINSTANCE   Module,
    IN  DWORD       Reason,
    IN  PVOID       Reserved
    )
{
    UNREFERENCED_PARAMETER(Module);
    UNREFERENCED_PARAMETER(Reserved);

    Log("%s", ReasonName(Reason));

    return TRUE;
}
