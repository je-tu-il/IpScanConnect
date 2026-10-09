#include <windows.h>
#include <iostream>
#include "../Shared/Ioctl.h"

#pragma comment(lib, "Fwpuclnt.lib")

int main() {
    std::cout << "=== Test Client C++ IpScanConnect Driver ===\n";

    HANDLE hDevice = CreateFileW(USER_DEVICE_PATH, 
        GENERIC_READ | GENERIC_WRITE, 
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        std::cerr << "[ERREUR] Impossible d'ouvrir le peripherique " << "\\\\.\\IpScanConnect" << " (Code: " << err << ")\n";
        std::cerr << "-> Verifiez que le driver IpScanConnect.sys est compile et demarre (sc start IpScanConnect).\n";
        return 1;
    }

    std::cout << "[OK] Peripherique ouvert avec succes.\n";

    // 1. Test IOCTL_IPSCAN_GET_STATUS
    IPSCAN_STATUS status = { 0 };
    DWORD bytesReturned = 0;
    if (DeviceIoControl(hDevice, IOCTL_IPSCAN_GET_STATUS, NULL, 0, &status, sizeof(status), &bytesReturned, NULL)) {
        std::cout << "[STATUS] Regles actives: " << status.activeRuleCount
                  << ", Total connexions: " << status.totalLoggedConnections
                  << ", Bloquees: " << status.totalBlockedConnections
                  << ", Callout actif: " << (status.isCalloutRegistered ? "OUI" : "NON") << "\n";
    }

    // 2. Test IOCTL_IPSCAN_ADD_RULE (192.168.1.50)
    IPSCAN_RULE rule = { 0 };
    rule.targetIp = 0xC0A80132; // 192.168.1.50
    rule.targetPid = 0;         // Toutes les apps vers cette IP
    rule.block = TRUE;
    rule.direction = 0;

    if (DeviceIoControl(hDevice, IOCTL_IPSCAN_ADD_RULE, &rule, sizeof(rule), NULL, 0, &bytesReturned, NULL)) {
        std::cout << "[OK] Regle de blocage IP 192.168.1.50 ajoutee dans le noyau.\n";
    }

    // 3. Test IOCTL_IPSCAN_GET_LOGS
    IPSCAN_LOG_BATCH batch = { 0 };
    if (DeviceIoControl(hDevice, IOCTL_IPSCAN_GET_LOGS, NULL, 0, &batch, sizeof(batch), &bytesReturned, NULL)) {
        std::cout << "[LOGS] " << batch.count << " evenements recuperes depuis le noyau.\n";
    }

    CloseHandle(hDevice);
    std::cout << "[FIN] Test termine avec succes.\n";
    return 0;
}
