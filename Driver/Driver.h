#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <fwpmk.h>
#include <fwpsk.h>

#define _KERNEL_MODE 1
#include "../Shared/Ioctl.h"

#define DRIVER_TAG 'pfwW'

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD EvtDriverDeviceAdd;
EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;

extern HANDLE g_EngineHandle;
extern UINT32 g_CalloutId;
extern UINT64 g_FilterId;

// Fonctions WFP
NTSTATUS WfpRegisterCallouts(PDEVICE_OBJECT DeviceObject);
void WfpUnregisterCallouts(void);

// Gestion des règles de filtrage
NTSTATUS RuleListInit(VOID);
VOID RuleListCleanup(VOID);
NTSTATUS RuleAdd(const IPSCAN_RULE* rule);
NTSTATUS RuleRemove(const IPSCAN_RULE* rule);
VOID RuleClearAll(VOID);
BOOLEAN RuleShouldBlock(UINT32 remoteIp, UINT64 processId);
UINT32 RuleGetCount(VOID);

// Gestion des logs de connexion
VOID LogInit(VOID);
VOID LogAddEntry(UINT64 pid, UINT32 localIp, UINT32 remoteIp, UINT16 localPort, UINT16 remotePort, UINT8 proto, BOOLEAN blocked);
UINT32 LogGetBatch(PIPSCAN_LOG_BATCH batch);
VOID StatusGet(PIPSCAN_STATUS status);
