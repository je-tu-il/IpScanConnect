using System;
using System.Collections.Generic;
using System.IO;
using System.Web.Script.Serialization;
using IpScanConnect.Models;

namespace IpScanConnect.Services
{
    public class SettingsService
    {
        private readonly string _settingsPath;
        private readonly object _lock = new object();
        private AppSettings _current;

        public SettingsService()
            : this(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "IpScanConnect",
                "settings.json"))
        {
        }

        public SettingsService(string customPath)
        {
            _settingsPath = customPath;
            Load();
        }

        public AppSettings Current
        {
            get { return _current; }
        }

        public void Load()
        {
            lock (_lock)
            {
                try
                {
                    if (File.Exists(_settingsPath))
                    {
                        string json = File.ReadAllText(_settingsPath);
                        JavaScriptSerializer ser = new JavaScriptSerializer();
                        AppSettings loaded = ser.Deserialize<AppSettings>(json);
                        if (loaded != null)
                        {
                            if (loaded.KnownApps == null) loaded.KnownApps = new List<string>();
                            if (loaded.SandboxedFolders == null) loaded.SandboxedFolders = new List<string>();
                            if (loaded.RedirectRules == null) loaded.RedirectRules = new List<RedirectRule>();
                            if (string.IsNullOrEmpty(loaded.GeminiModel)) loaded.GeminiModel = "gemini-2.5-flash";
                            if (string.IsNullOrEmpty(loaded.AiProvider)) loaded.AiProvider = "OxionAi";
                            if (string.IsNullOrEmpty(loaded.AiBaseUrl)) loaded.AiBaseUrl = "https://oxionai.com/v1";
                            if (string.IsNullOrEmpty(loaded.AiModel)) loaded.AiModel = "gpt-4o-mini";

                            // Migration automatique de clé existante
                            if (string.IsNullOrEmpty(loaded.AiApiKey) && !string.IsNullOrEmpty(loaded.GeminiApiKey))
                            {
                                loaded.AiApiKey = loaded.GeminiApiKey;
                                string trimmed = loaded.GeminiApiKey.Trim();
                                if (trimmed.StartsWith("cc_", StringComparison.OrdinalIgnoreCase) ||
                                    trimmed.StartsWith("ox_", StringComparison.OrdinalIgnoreCase) ||
                                    trimmed.StartsWith("sk-", StringComparison.OrdinalIgnoreCase))
                                {
                                    loaded.AiProvider = "OxionAi";
                                    loaded.AiModel = "gpt-4o-mini";
                                }
                                else if (trimmed.StartsWith("AIza", StringComparison.Ordinal))
                                {
                                    loaded.AiProvider = "Gemini";
                                    loaded.AiModel = string.IsNullOrEmpty(loaded.GeminiModel) ? "gemini-2.5-flash" : loaded.GeminiModel;
                                }
                            }

                            _current = loaded;
                            return;
                        }
                    }
                }
                catch { }

                _current = new AppSettings();
            }
        }

        public void Save()
        {
            lock (_lock)
            {
                try
                {
                    string dir = Path.GetDirectoryName(_settingsPath);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    {
                        Directory.CreateDirectory(dir);
                    }

                    if (_current != null)
                    {
                        if (string.IsNullOrEmpty(_current.GeminiApiKey) && !string.IsNullOrEmpty(_current.AiApiKey))
                            _current.GeminiApiKey = _current.AiApiKey;
                        if (string.IsNullOrEmpty(_current.GeminiModel) && !string.IsNullOrEmpty(_current.AiModel))
                            _current.GeminiModel = _current.AiModel;
                    }

                    JavaScriptSerializer ser = new JavaScriptSerializer();
                    string json = ser.Serialize(_current);
                    File.WriteAllText(_settingsPath, json);
                }
                catch { }
            }
        }

        public bool IsKnownApp(string identifier)
        {
            if (string.IsNullOrEmpty(identifier)) return true;
            lock (_lock)
            {
                foreach (string known in _current.KnownApps)
                {
                    if (string.Equals(known, identifier, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            return false;
        }

        public void MarkAppAsKnown(string identifier)
        {
            if (string.IsNullOrEmpty(identifier)) return;
            lock (_lock)
            {
                foreach (string known in _current.KnownApps)
                {
                    if (string.Equals(known, identifier, StringComparison.OrdinalIgnoreCase))
                        return;
                }
                _current.KnownApps.Add(identifier);
                Save();
            }
        }

        public void MarkAppsAsKnownBatch(IEnumerable<string> identifiers)
        {
            if (identifiers == null) return;
            bool changed = false;
            lock (_lock)
            {
                HashSet<string> existing = new HashSet<string>(_current.KnownApps, StringComparer.OrdinalIgnoreCase);
                foreach (string id in identifiers)
                {
                    if (!string.IsNullOrEmpty(id) && existing.Add(id))
                    {
                        _current.KnownApps.Add(id);
                        changed = true;
                    }
                }
                if (changed) Save();
            }
        }

        public void ClearKnownApps()
        {
            lock (_lock)
            {
                _current.KnownApps.Clear();
                Save();
            }
        }

        public void AddSandboxedFolder(string folderPath)
        {
            if (string.IsNullOrEmpty(folderPath)) return;
            lock (_lock)
            {
                foreach (string f in _current.SandboxedFolders)
                {
                    if (string.Equals(f, folderPath, StringComparison.OrdinalIgnoreCase))
                        return;
                }
                _current.SandboxedFolders.Add(folderPath);
                Save();
            }
        }

        public void RemoveSandboxedFolder(string folderPath)
        {
            if (string.IsNullOrEmpty(folderPath)) return;
            lock (_lock)
            {
                int removed = _current.SandboxedFolders.RemoveAll(f => string.Equals(f, folderPath, StringComparison.OrdinalIgnoreCase));
                if (removed > 0) Save();
            }
        }
    }
}
