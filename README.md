# 🛡️ IpScanConnect - Moniteur Réseau & Pare-feu Sécurisé

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6?logo=windows&logoColor=white)](#)
[![Framework](https://img.shields.io/badge/.NET%20Framework-4.8-512BD4?logo=dotnet&logoColor=white)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build](https://img.shields.io/badge/Build-Passing-brightgreen)](#)

**IpScanConnect** est un outil haute performance pour Windows permettant d'identifier en temps réel **qui est connecté à quoi** (applications, PIDs, adresses IP, ports, domaines) et de **bloquer instantanément toute IP suspecte ou application**.

Conçu pour fonctionner de manière fluide et autonome, sans risque de plantage (BSOD) et sans dépendance complexe.

---

## 🚀 Installation & Utilisation

Deux packages d'installation propres sont mis à disposition dans le dossier [`Release/`](file:///e:/Reste/PROJET_PERSO/IpScanConnect/Release/) et sur les **Releases GitHub** :

### Option 1 : Installateur Windows Complet (Recommandé)
1. Téléchargez et lancez **`IpScanConnect_Setup_v1.0.exe`**.
2. L'assistant graphique vous permet de choisir votre dossier de destination (`C:\Program Files\IpScanConnect` par défaut).
3. Il crée automatiquement :
   - Un raccourci sur le **Bureau**
   - Un raccourci dans le **Menu Démarrer**
   - Une entrée dans les **Applications et Fonctionnalités** de Windows pour une désinstallation propre à tout moment.

### Option 2 : Version Portable (Sans Installation)
1. Téléchargez et décompressez **`IpScanConnect_v1.0_Portable.zip`**.
2. Double-cliquez directement sur **`IpScanConnect.exe`** pour l'utiliser immédiatement sans aucune installation requise (les droits Administrateur sont automatiquement demandés).

---

## 🌟 Fonctionnalités Principales

### 1. 🌐 "Qui est connecté à quoi" (Catégories Développables & Clarté Maximale)
Au lieu d'un tableau infini de 100 lignes mélangées, l'interface regroupe les connexions sous forme de **catégories pliables / dépliables** :
- **📦 Vue par Application** :
  - Chaque application active (ex: `brave.exe`, `discord.exe`, `steam.exe`...) apparaît sous forme de carte propre.
  - Affiche son icône, son nom, son PID, son chemin, et le nombre de flux (ex: `12 flux (8 actifs)`).
  - Bouton direct **🚫 Bloquer l'App** sur chaque carte d'application.
  - Développez l'application en un clic pour voir la liste de ses connexions vers l'extérieur.
- **📁 Vue par Type Général** :
  - **🌐 Applications Utilisateur** : Vos logiciels en cours d'exécution (déployés par défaut pour visibilité directe).
  - **⚙️ Système & Windows** : Processus système de fond (repliés par défaut pour ne pas noyer l'écran).
  - **📡 Services en Écoute** : Ports ouverts locaux en attente de connexion (repliés par défaut).
  - **🛑 Éléments Bloqués** : Flux et applications actuellement sous restriction.
- **Boutons Rapides** :
  - `➕ Déplier tout` / `➖ Replier tout` en 1 clic.
  - Barre de recherche instantanée : tapez une app, une IP, un port ou un domaine pour filtrer et auto-déplier les résultats.

### 2. 🛑 Blocage & Filtrage Puissant
- **Sur chaque connexion (Menu Clic Droit ou Barre Rapide)** :
  - 🛑 **Bloquer cette IP** : Bloque immédiatement tout flux entrant et sortant vers cette IP au niveau du noyau, et réinitialise les connexions actives vers celle-ci.
  - 🚫 **Bloquer cette Application (.exe)** : Interdit tout accès réseau (entrant et sortant) pour l'application sélectionnée.
  - ❌ **Fermer cette connexion (Reset TCP)** : Réinitialise instantanément le socket réseau (`SetTcpEntry`) sans fermer l'application.
  - 💀 **Terminer le processus** : Arrête l'application suspecte si nécessaire.
  - 📂 **Ouvrir l'emplacement** : Ouvre le dossier de l'exécutable dans l'Explorateur de fichiers.
  - 📋 **Copier IP / Chemin** : Copie dans le presse-papiers en un clic.

### 3. 🛡️ Gestionnaire de Règles Dédié (Onglet "Règles")
- Affiche la liste de toutes les règles actives créées par IpScanConnect.
- **+ Bloquer une IP manuellement** : Entrez une adresse IPv4 cible à interdire.
- **+ Bloquer une Application (.exe)** : Parcourez vos disques pour choisir n'importe quel fichier `.exe` à isoler d'Internet.
- **Débloquer la sélection** : Supprime la règle en 1 clic et rétablit le trafic.
- **🧹 Tout Débloquer** : Réinitialise toutes les règles de filtrage en 1 clic.

### 4. 📜 Historique & Journalisation
- Suivi chronologique des événements (connexions détectées, blocages, fermetures de sockets).
- Exportation facile en fichier texte pour analyse.

---

## ⚙️ Architecture & Moteur Hybride

IpScanConnect intègre une architecture à deux niveaux :

```mermaid
graph TD
    UI[Interface Graphique WPF (IpScanConnect.exe)]
    
    subgraph "Moteur Utilisateur & Hybride"
        Monitor[NetworkMonitorService - iphlpapi.dll]
        Blocker[BlockRuleService - WFP / Firewall COM]
        DriverClient[KernelDriverClient - \\.\IpScanConnect]
    end

    subgraph "Noyau Windows (Kernel-Mode)"
        NativeWFP[Windows Filtering Platform WFP Natif]
        CustomDriver[Driver WFP Callout - IpScanConnect.sys]
    end

    UI --> Monitor
    UI --> Blocker
    Blocker --> NativeWFP
    Blocker --> DriverClient
    DriverClient -.->|Si chargé| CustomDriver
```

1. **Mode Natif WFP Windows (Par Défaut)** :
   - Fonctionne immédiatement sur votre système Windows sans aucune installation supplémentaire.
   - Utilise l'API Windows Filtering Platform (WFP) native via `HNetCfg.FwPolicy2` et `netsh`.
   - **Avantages** : Zéro risque de crash ou BSOD, persistant au redémarrage, filtrage au niveau paquet dans le noyau réseau de Windows.

2. **Mode Driver Kernel Dédié (`Driver/IpScanConnect.sys`)** :
   - Le code du driver WFP Callout complet et sécurisé se trouve dans le dossier `Driver/` (`Callout.c`, `Communication.c`, `DriverEntry.c`).
   - Gère une liste de règles chaînée en mémoire non paginée (`NonPagedPoolNx`) avec spinlocks `KSPIN_LOCK`.
   - Classification WFP sur la couche ALE Connect (`FWPM_LAYER_ALE_AUTH_CONNECT_V4`).
   - Tampon circulaire de télémétrie noyau accessible via IOCTL.
   - Si vous compilez et démarrez le pilote dans une machine virtuelle de test (`bcdedit /set testsigning on`), `IpScanConnect.exe` le détecte automatiquement et lui transmet les règles via IOCTL.

---

## 📁 Structure des Fichiers

| Fichier / Dossier | Rôle |
| :--- | :--- |
| **`IpScanConnect.exe`** | L'exécutable complet prêt à l'emploi (interface moderne WPF x64). |
| **`App/`** | Code source complet C# / WPF du client graphique et des services. |
| **`Shared/Ioctl.h`** | Définitions communes des IOCTLs et structures noyau/utilisateur. |
| **`Driver/`** | Code source en C du pilote noyau WFP Callout (`Callout.c`, `Communication.c`, etc.). |
| **`Service/ServiceHelper.cpp`** | Outil console C++ pour tester les IOCTLs du pilote. |

---

## 🛠️ Recompiler le Projet

Pour recompiler l'application à partir des sources :
```cmd
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" App\IpScanConnect.csproj /p:Configuration=Release /p:Platform=x64
```
L'exécutable généré sera automatiquement placé dans `bin\IpScanConnect.exe`.
