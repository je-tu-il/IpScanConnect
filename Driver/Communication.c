#include "Driver.h"

VOID EvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode)
{
    UNREFERENCED_PARAMETER(Queue);
    NTSTATUS status = STATUS_SUCCESS;
    size_t bytesReturned = 0;

    switch (IoControlCode)
    {
    case IOCTL_IPSCAN_ADD_RULE:
    {
        if (InputBufferLength < sizeof(IPSCAN_RULE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PIPSCAN_RULE rule = NULL;
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(IPSCAN_RULE), (PVOID*)&rule, NULL);
        if (NT_SUCCESS(status) && rule != NULL) {
            status = RuleAdd(rule);
            if (NT_SUCCESS(status)) {
                bytesReturned = sizeof(IPSCAN_RULE);
            }
        }
        break;
    }
    case IOCTL_IPSCAN_REMOVE_RULE:
    {
        if (InputBufferLength < sizeof(IPSCAN_RULE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PIPSCAN_RULE rule = NULL;
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(IPSCAN_RULE), (PVOID*)&rule, NULL);
        if (NT_SUCCESS(status) && rule != NULL) {
            status = RuleRemove(rule);
            if (NT_SUCCESS(status)) {
                bytesReturned = sizeof(IPSCAN_RULE);
            }
        }
        break;
    }
    case IOCTL_IPSCAN_CLEAR_RULES:
    {
        RuleClearAll();
        status = STATUS_SUCCESS;
        bytesReturned = 0;
        break;
    }
    case IOCTL_IPSCAN_GET_LOGS:
    {
        if (OutputBufferLength < sizeof(IPSCAN_LOG_BATCH)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PIPSCAN_LOG_BATCH batch = NULL;
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(IPSCAN_LOG_BATCH), (PVOID*)&batch, NULL);
        if (NT_SUCCESS(status) && batch != NULL) {
            LogGetBatch(batch);
            bytesReturned = sizeof(IPSCAN_LOG_BATCH);
        }
        break;
    }
    case IOCTL_IPSCAN_GET_STATUS:
    {
        if (OutputBufferLength < sizeof(IPSCAN_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PIPSCAN_STATUS outStatus = NULL;
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(IPSCAN_STATUS), (PVOID*)&outStatus, NULL);
        if (NT_SUCCESS(status) && outStatus != NULL) {
            StatusGet(outStatus);
            bytesReturned = sizeof(IPSCAN_STATUS);
        }
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}
