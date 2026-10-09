#pragma once

#ifdef _KERNEL_MODE
#include <wdm.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#define DEVICE_NAME     L"\\Device\\IpScanConnect"
#define SYM_LINK_NAME   L"\\DosDevices\\IpScanConnect"
#define USER_DEVICE_PATH L"\\\\.\\IpScanConnect"

#define IOCTL_IPSCAN_ADD_RULE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IPSCAN_GET_LOGS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IPSCAN_REMOVE_RULE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IPSCAN_CLEAR_RULES   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IPSCAN_GET_STATUS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _IPSCAN_RULE {
    UINT32 targetIp;    // IPv4 in network byte order (or host byte order), 0 = ignore IP
    UINT32 targetPid;   // Process ID, 0 = ignore PID
    BOOLEAN block;      // TRUE = Block, FALSE = Allow
    UINT8 direction;    // 0 = Both, 1 = Inbound, 2 = Outbound
} IPSCAN_RULE, *PIPSCAN_RULE;

typedef struct _IPSCAN_LOG_ENTRY {
    LARGE_INTEGER timestamp;
    UINT64 processId;
    UINT32 localIp;
    UINT32 remoteIp;
    UINT16 localPort;
    UINT16 remotePort;
    UINT8 protocol;     // 6 = TCP, 17 = UDP
    BOOLEAN blocked;    // TRUE if connection was blocked
} IPSCAN_LOG_ENTRY, *PIPSCAN_LOG_ENTRY;

#define MAX_LOG_BATCH 32

typedef struct _IPSCAN_LOG_BATCH {
    UINT32 count;
    IPSCAN_LOG_ENTRY entries[MAX_LOG_BATCH];
} IPSCAN_LOG_BATCH, *PIPSCAN_LOG_BATCH;

typedef struct _IPSCAN_STATUS {
    UINT32 activeRuleCount;
    UINT32 totalLoggedConnections;
    UINT32 totalBlockedConnections;
    BOOLEAN isCalloutRegistered;
} IPSCAN_STATUS, *PIPSCAN_STATUS;
