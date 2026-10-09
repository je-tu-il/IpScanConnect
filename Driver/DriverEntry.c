#include "Driver.h"

HANDLE g_EngineHandle = NULL;

// GUID du filtre: {4E95F6A1-7B32-411B-A08C-8F4321A65432}
DEFINE_GUID(WFP_MONITOR_FILTER_GUID, 0x4e95f6a1, 0x7b32, 0x411b, 0xa0, 0x8c, 0x8f, 0x43, 0x21, 0xa6, 0x54, 0x32);
DEFINE_GUID(WFP_CALLOUT_GUID, 0x2d85d757, 0xc0e0, 0x441f, 0x95, 0x96, 0x7d, 0x5d, 0xa6, 0x90, 0xee, 0x8e);

NTSTATUS WfpRegisterFilterAndCalloutBfe(VOID)
{
    if (g_EngineHandle == NULL) return STATUS_INVALID_HANDLE;

    FWPM_CALLOUT0 mCallout = { 0 };
    mCallout.calloutKey = WFP_CALLOUT_GUID;
    mCallout.displayData.name = L"IpScanConnect Callout";
    mCallout.displayData.description = L"Monitors and blocks outbound IPv4 connections";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    NTSTATUS status = FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != 0xC002002CL /* FWP_E_ALREADY_EXISTS */) {
        KdPrint(("WFP: Echec FwpmCalloutAdd0: 0x%X\n", status));
        return status;
    }

    FWPM_FILTER0 mFilter = { 0 };
    mFilter.filterKey = WFP_MONITOR_FILTER_GUID;
    mFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    mFilter.displayData.name = L"IpScanConnect Filter";
    mFilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    mFilter.action.calloutKey = WFP_CALLOUT_GUID;
    mFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    mFilter.weight.type = FWP_UINT8;
    mFilter.weight.uint8 = 0xF;

    status = FwpmFilterAdd0(g_EngineHandle, &mFilter, NULL, &g_FilterId);
    if (!NT_SUCCESS(status) && status != 0xC002002CL) {
        KdPrint(("WFP: Echec FwpmFilterAdd0: 0x%X\n", status));
        return status;
    }

    KdPrint(("WFP: Callout et Filtre BFE ajoutes avec succes.\n"));
    return STATUS_SUCCESS;
}

VOID EvtDriverUnload(_In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);
    KdPrint(("WFP: Dechargement du driver IpScanConnect...\n"));

    WfpUnregisterCallouts();

    if (g_EngineHandle != NULL) {
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
    }

    RuleListCleanup();
    KdPrint(("WFP: Driver decharge proprement.\n"));
}

NTSTATUS EvtDriverDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
    UNREFERENCED_PARAMETER(Driver);
    WDFDEVICE device;
    NTSTATUS status;

    DECLARE_CONST_UNICODE_STRING(ntDeviceName, DEVICE_NAME);
    status = WdfDeviceInitAssignName(DeviceInit, &ntDeviceName);
    if (!NT_SUCCESS(status)) return status;

    status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) return status;

    DECLARE_CONST_UNICODE_STRING(dosDeviceName, SYM_LINK_NAME);
    status = WdfDeviceCreateSymbolicLink(device, &dosDeviceName);
    if (!NT_SUCCESS(status)) return status;

    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

    WDFQUEUE queue;
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) return status;

    status = WfpRegisterCallouts(WdfDeviceWdmGetDeviceObject(device));
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: Echec WfpRegisterCallouts: 0x%X\n", status));
        return status;
    }

    // Associer le callout au filtre dans le Base Filtering Engine
    status = WfpRegisterFilterAndCalloutBfe();

    return status;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;
    WDFDRIVER driver;

    KdPrint(("WFP: Initialisation IpScanConnect Driver...\n"));

    RuleListInit();
    LogInit();

    WDF_DRIVER_CONFIG_INIT(&config, EvtDriverDeviceAdd);
    config.EvtDriverUnload = EvtDriverUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if (!NT_SUCCESS(status)) return status;

    FWPM_SESSION0 session = { 0 };
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("WFP: Echec FwpmEngineOpen0: 0x%X\n", status));
    }

    return status;
}
