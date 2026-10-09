#include "Driver.h"

// GUID: {2D85D757-C0E0-441F-9596-7D5DA690EE8E}
DEFINE_GUID(WFP_MONITOR_CALLOUT_GUID, 0x2d85d757, 0xc0e0, 0x441f, 0x95, 0x96, 0x7d, 0x5d, 0xa6, 0x90, 0xee, 0x8e);

UINT32 g_CalloutId = 0;
UINT64 g_FilterId = 0;

// Structure interne pour stocker une règle dans la liste
typedef struct _RULE_NODE {
    LIST_ENTRY listEntry;
    IPSCAN_RULE rule;
} RULE_NODE, *PRULE_NODE;

static LIST_ENTRY g_RuleList;
static KSPIN_LOCK g_RuleLock;
static UINT32 g_RuleCount = 0;

// Ring buffer de télémétrie
#define MAX_RING_LOGS 256
static IPSCAN_LOG_ENTRY g_LogRing[MAX_RING_LOGS];
static ULONG g_LogHead = 0;
static ULONG g_LogTail = 0;
static ULONG g_LogCount = 0;
static KSPIN_LOCK g_LogLock;
static UINT32 g_TotalLogged = 0;
static UINT32 g_TotalBlocked = 0;

// Initialisation de la liste de règles
NTSTATUS RuleListInit(VOID)
{
    InitializeListHead(&g_RuleList);
    KeInitializeSpinLock(&g_RuleLock);
    g_RuleCount = 0;
    return STATUS_SUCCESS;
}

// Nettoyage de la liste de règles
VOID RuleListCleanup(VOID)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RuleLock, &oldIrql);

    while (!IsListEmpty(&g_RuleList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_RuleList);
        PRULE_NODE node = CONTAINING_RECORD(entry, RULE_NODE, listEntry);
        ExFreePoolWithTag(node, DRIVER_TAG);
    }
    g_RuleCount = 0;

    KeReleaseSpinLock(&g_RuleLock, oldIrql);
}

// Ajouter une règle
NTSTATUS RuleAdd(const IPSCAN_RULE* rule)
{
    if (rule == NULL) return STATUS_INVALID_PARAMETER;

    PRULE_NODE node = (PRULE_NODE)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(RULE_NODE), DRIVER_TAG);
    if (node == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(node, sizeof(RULE_NODE));
    node->rule = *rule;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RuleLock, &oldIrql);

    InsertTailList(&g_RuleList, &node->listEntry);
    g_RuleCount++;

    KeReleaseSpinLock(&g_RuleLock, oldIrql);

    KdPrint(("WFP: Regle ajoutee - IP: 0x%08X, PID: %u, Block: %d (Total: %u)\n",
        rule->targetIp, rule->targetPid, rule->block, g_RuleCount));

    return STATUS_SUCCESS;
}

// Supprimer une règle
NTSTATUS RuleRemove(const IPSCAN_RULE* rule)
{
    if (rule == NULL) return STATUS_INVALID_PARAMETER;

    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&g_RuleLock, &oldIrql);

    PLIST_ENTRY curr = g_RuleList.Flink;
    while (curr != &g_RuleList) {
        PRULE_NODE node = CONTAINING_RECORD(curr, RULE_NODE, listEntry);
        PLIST_ENTRY next = curr->Flink;

        if (node->rule.targetIp == rule->targetIp && node->rule.targetPid == rule->targetPid) {
            RemoveEntryList(curr);
            ExFreePoolWithTag(node, DRIVER_TAG);
            if (g_RuleCount > 0) g_RuleCount--;
            found = TRUE;
            break;
        }
        curr = next;
    }

    KeReleaseSpinLock(&g_RuleLock, oldIrql);
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// Supprimer toutes les règles
VOID RuleClearAll(VOID)
{
    RuleListCleanup();
    KdPrint(("WFP: Toutes les regles ont ete effacees.\n"));
}

// Vérifier si une connexion doit être bloquée
BOOLEAN RuleShouldBlock(UINT32 remoteIp, UINT64 processId)
{
    BOOLEAN block = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RuleLock, &oldIrql);

    PLIST_ENTRY curr = g_RuleList.Flink;
    while (curr != &g_RuleList) {
        PRULE_NODE node = CONTAINING_RECORD(curr, RULE_NODE, listEntry);
        
        BOOLEAN ipMatch = (node->rule.targetIp != 0 && node->rule.targetIp == remoteIp);
        BOOLEAN pidMatch = (node->rule.targetPid != 0 && node->rule.targetPid == (UINT32)processId);

        if (ipMatch || pidMatch) {
            if (node->rule.block) {
                block = TRUE;
                break;
            }
        }
        curr = curr->Flink;
    }

    KeReleaseSpinLock(&g_RuleLock, oldIrql);
    return block;
}

UINT32 RuleGetCount(VOID)
{
    return g_RuleCount;
}

// Initialisation des logs
VOID LogInit(VOID)
{
    KeInitializeSpinLock(&g_LogLock);
    g_LogHead = 0;
    g_LogTail = 0;
    g_LogCount = 0;
    g_TotalLogged = 0;
    g_TotalBlocked = 0;
}

// Ajouter une entrée de log dans le ring buffer
VOID LogAddEntry(UINT64 pid, UINT32 localIp, UINT32 remoteIp, UINT16 localPort, UINT16 remotePort, UINT8 proto, BOOLEAN blocked)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_LogLock, &oldIrql);

    LARGE_INTEGER sysTime;
    KeQuerySystemTime(&sysTime);

    IPSCAN_LOG_ENTRY* entry = &g_LogRing[g_LogHead];
    entry->timestamp = sysTime;
    entry->processId = pid;
    entry->localIp = localIp;
    entry->remoteIp = remoteIp;
    entry->localPort = localPort;
    entry->remotePort = remotePort;
    entry->protocol = proto;
    entry->blocked = blocked;

    g_LogHead = (g_LogHead + 1) % MAX_RING_LOGS;
    if (g_LogCount < MAX_RING_LOGS) {
        g_LogCount++;
    } else {
        g_LogTail = (g_LogTail + 1) % MAX_RING_LOGS; // Écrase la plus ancienne
    }

    g_TotalLogged++;
    if (blocked) {
        g_TotalBlocked++;
    }

    KeReleaseSpinLock(&g_LogLock, oldIrql);
}

// Récupérer un lot de logs pour le mode utilisateur
UINT32 LogGetBatch(PIPSCAN_LOG_BATCH batch)
{
    if (batch == NULL) return 0;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_LogLock, &oldIrql);

    UINT32 extracted = 0;
    while (g_LogCount > 0 && extracted < MAX_LOG_BATCH) {
        batch->entries[extracted] = g_LogRing[g_LogTail];
        g_LogTail = (g_LogTail + 1) % MAX_RING_LOGS;
        g_LogCount--;
        extracted++;
    }
    batch->count = extracted;

    KeReleaseSpinLock(&g_LogLock, oldIrql);
    return extracted;
}

VOID StatusGet(PIPSCAN_STATUS status)
{
    if (status == NULL) return;
    status->activeRuleCount = g_RuleCount;
    status->totalLoggedConnections = g_TotalLogged;
    status->totalBlockedConnections = g_TotalBlocked;
    status->isCalloutRegistered = (g_CalloutId != 0);
}

// Callback de classification WFP
void NTAPI CalloutClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER3* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) return;

    UINT32 localIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
    UINT32 remoteIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    UINT16 localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
    UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;

    UINT64 processId = 0;
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = inMetaValues->processId;
    }

    BOOLEAN bShouldBlock = RuleShouldBlock(remoteIp, processId);

    if (bShouldBlock) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_CLEAR_ACTION_RIGHT;
        LogAddEntry(processId, localIp, remoteIp, localPort, remotePort, 6, TRUE);
        KdPrint(("WFP: [BLOQUE] PID %llu vers IP %u.%u.%u.%u:%u\n",
            processId,
            (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
            remotePort));
    } else {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        LogAddEntry(processId, localIp, remoteIp, localPort, remotePort, 6, FALSE);
    }
}

NTSTATUS NTAPI CalloutNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ const FWPS_FILTER3* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

void NTAPI CalloutFlowDeleteFn(_In_ UINT16 layerId, _In_ UINT32 calloutId, _In_ UINT64 flowContext)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}

NTSTATUS WfpRegisterCallouts(PDEVICE_OBJECT DeviceObject)
{
    FWPS_CALLOUT0 sCallout = { 0 };

    sCallout.calloutKey = WFP_MONITOR_CALLOUT_GUID;
    sCallout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN0)CalloutClassifyFn;
    sCallout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN0)CalloutNotifyFn;
    sCallout.flowDeleteFn = (FWPS_CALLOUT_FLOW_DELETE_FN0)CalloutFlowDeleteFn;

    return FwpsCalloutRegister0(DeviceObject, &sCallout, &g_CalloutId);
}

void WfpUnregisterCallouts(void)
{
    if (g_CalloutId != 0) {
        FwpsCalloutUnregisterById0(g_CalloutId);
        g_CalloutId = 0;
    }
}
