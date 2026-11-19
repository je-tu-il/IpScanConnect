using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using IpScanConnect.Models;

namespace IpScanConnect.Services
{
    public class GeminiAiService
    {
        private static readonly HttpClient _httpClient = CreateHttpClient();

        private static HttpClient CreateHttpClient()
        {
            try
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12 | (SecurityProtocolType)3072;
            }
            catch { }

            HttpClient client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(45);
            return client;
        }

        public static string BuildAppTelemetrySummary(ProcessGroup group)
        {
            if (group == null) return "";
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Application : " + (group.ProcessName ?? "Inconnue"));
            sb.AppendLine("PID : " + group.ProcessId);
            sb.AppendLine("Chemin exécutable : " + (string.IsNullOrEmpty(group.ProcessPath) ? "N/A" : group.ProcessPath));
            sb.AppendLine("Catégorie : " + (group.Category ?? "Inconnue"));
            if (!string.IsNullOrEmpty(group.WindowsServices))
                sb.AppendLine("Services Windows associés : " + group.WindowsServices);
            sb.AppendLine("Statut pare-feu actuel : " + (group.IsBlocked ? "BLOQUÉ" : "Autorisé"));
            sb.AppendLine(string.Format("Connexions : {0} total ({1} établies, {2} Internet, {3} locales)",
                group.TotalCount, group.ActiveCount, group.InternetCount, group.LocalCount));
            sb.AppendLine(string.Format("Volume mesuré : Envoyé = {0} ({1}/s), Reçu = {2} ({3}/s)",
                NetworkConnection.FormatBytes(group.TotalBytesSent),
                NetworkConnection.FormatBytes((long)group.SendRateBps),
                NetworkConnection.FormatBytes(group.TotalBytesReceived),
                NetworkConnection.FormatBytes((long)group.ReceiveRateBps)));

            if (group.AllConnections != null && group.AllConnections.Count > 0)
            {
                List<int> localPorts = group.AllConnections.Where(c => c.LocalPort > 0).Select(c => c.LocalPort).Distinct().OrderBy(p => p).Take(20).ToList();
                List<int> remotePorts = group.AllConnections.Where(c => c.RemotePort > 0).Select(c => c.RemotePort).Distinct().OrderBy(p => p).Take(20).ToList();
                sb.AppendLine("Ports locaux utilisés : " + (localPorts.Count > 0 ? string.Join(", ", localPorts.Select(p => p.ToString()).ToArray()) : "Aucun"));
                sb.AppendLine("Ports distants utilisés : " + (remotePorts.Count > 0 ? string.Join(", ", remotePorts.Select(p => p.ToString()).ToArray()) : "Aucun"));

                sb.AppendLine("Détail des connexions / ouvertures (max 25) :");
                foreach (NetworkConnection c in group.AllConnections.Take(25))
                {
                    sb.AppendLine(string.Format("- [{0}] {1} Local={2} -> Distant={3} ({4}) | État={5} | ↑{6} ↓{7}",
                        c.ConnectionScope,
                        c.ProtocolDisplay,
                        c.LocalDisplay,
                        c.RemoteDisplay,
                        string.IsNullOrEmpty(c.RemoteHost) ? "-" : c.RemoteHost,
                        c.State,
                        NetworkConnection.FormatBytes(c.BytesSent),
                        NetworkConnection.FormatBytes(c.BytesReceived)));
                }
            }

            return sb.ToString();
        }

        public static string BuildGlobalTelemetrySummary(IList<ProcessGroup> appGroups, IList<NetworkConnection> allConnections, int blockedRulesCount)
        {
            StringBuilder sb = new StringBuilder();
            int totalConns = allConnections != null ? allConnections.Count : 0;
            int internetConns = allConnections != null ? allConnections.Count(c => c.IsInternet) : 0;
            int localConns = totalConns - internetConns;
            long totalSent = allConnections != null ? allConnections.Sum(c => c.BytesSent) : 0;
            long totalRecv = allConnections != null ? allConnections.Sum(c => c.BytesReceived) : 0;

            sb.AppendLine(string.Format("Instantanné réseau complet du PC ({0:yyyy-MM-dd HH:mm:ss}) :", DateTime.Now));
            sb.AppendLine(string.Format("- Applications actives : {0}", appGroups != null ? appGroups.Count : 0));
            sb.AppendLine(string.Format("- Connexions totales : {0} ({1} Internet réelles, {2} locales/écoute)", totalConns, internetConns, localConns));
            sb.AppendLine(string.Format("- Règles de blocage actives : {0}", blockedRulesCount));
            sb.AppendLine(string.Format("- Trafic TCP mesuré : Envoyé={0}, Reçu={1}",
                NetworkConnection.FormatBytes(totalSent),
                NetworkConnection.FormatBytes(totalRecv)));

            if (appGroups != null)
            {
                sb.AppendLine("Applications principales (triées par trafic et connexions, top 30) :");
                foreach (ProcessGroup g in appGroups
                    .OrderByDescending(x => x.InternetCount)
                    .ThenByDescending(x => x.TotalTrafficBytes)
                    .ThenByDescending(x => x.TotalCount)
                    .Take(30))
                {
                    string topHosts = "";
                    if (g.AllConnections != null)
                    {
                        var hosts = g.AllConnections
                            .Where(c => c.IsInternet)
                            .Select(c => string.IsNullOrEmpty(c.RemoteHost) ? c.RemoteAddress : c.RemoteHost)
                            .Distinct()
                            .Take(4)
                            .ToArray();
                        topHosts = string.Join(", ", hosts);
                    }

                    sb.AppendLine(string.Format("- {0} ({1}) | Chemin={2} | Flux={3} (Internet={4}, Local={5}) | Débit={6} | {7} | Hôtes={8}",
                        g.ProcessName,
                        g.Category,
                        string.IsNullOrEmpty(g.ProcessPath) ? "N/A" : g.ProcessPath,
                        g.TotalCount,
                        g.InternetCount,
                        g.LocalCount,
                        g.ThroughputSummary,
                        g.PortsPreview,
                        string.IsNullOrEmpty(topHosts) ? "Local uniquement" : topHosts));
                }
            }

            return sb.ToString();
        }

        public static string DetectProvider(string apiKey, string defaultProvider = "OxionAi")
        {
            if (string.IsNullOrWhiteSpace(apiKey)) return defaultProvider;
            string trimmed = apiKey.Trim();
            if (trimmed.StartsWith("AIza", StringComparison.Ordinal))
                return "Gemini";
            if (trimmed.StartsWith("cc_", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("ox_", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("sk-", StringComparison.OrdinalIgnoreCase))
                return "OxionAi";
            return defaultProvider;
        }

        public Task<GeminiAnalysisResult> AnalyzeAppAsync(string apiKey, string model, ProcessGroup group)
        {
            string provider = DetectProvider(apiKey, "OxionAi");
            string defaultModel = string.Equals(provider, "Gemini", StringComparison.OrdinalIgnoreCase) ? "gemini-2.5-flash" : "gpt-4o-mini";
            return AnalyzeAppAsync(apiKey, string.IsNullOrEmpty(model) ? defaultModel : model, group, provider, "https://oxionai.com/v1");
        }

        public async Task<GeminiAnalysisResult> AnalyzeAppAsync(string apiKey, string model, ProcessGroup group, string provider, string baseUrl)
        {
            string telemetry = BuildAppTelemetrySummary(group);
            string prompt =
                "Tu es un expert en cybersécurité réseau Windows. Analyse les données télémétriques ci-dessous d'une application observée sur le PC de l'utilisateur.\n" +
                "Réponds STRICTEMENT en JSON valide (sans texte hors JSON, sans balises markdown ```) avec exactement ces 5 clés en français :\n" +
                "{\n" +
                "  \"risk_level\": \"Faible | Modéré | Élevé\",\n" +
                "  \"summary\": \"Synthèse courte en 1-2 phrases\",\n" +
                "  \"what_it_does\": \"Explication claire de ce que fait cette application et pourquoi elle ouvre ces ports/connexions\",\n" +
                "  \"utility\": \"Son utilité réelle pour Windows ou l'utilisateur\",\n" +
                "  \"risks\": \"Risques potentiels (confidentialité, télémétrie, ports ouverts, surface d'attaque, destinations suspectes)\",\n" +
                "  \"cut_internet_impact\": \"Ce qui se passe concrètement si l'utilisateur bloque son accès Internet\"\n" +
                "}\n\n" +
                "Données observées :\n" + telemetry;

            return await SendPromptAsync(apiKey, model, group.ProcessName, "Application", prompt, provider, baseUrl);
        }

        public Task<GeminiAnalysisResult> AnalyzeGlobalTrafficAsync(string apiKey, string model, IList<ProcessGroup> appGroups, IList<NetworkConnection> allConnections, int blockedRulesCount)
        {
            string provider = DetectProvider(apiKey, "OxionAi");
            string defaultModel = string.Equals(provider, "Gemini", StringComparison.OrdinalIgnoreCase) ? "gemini-2.5-flash" : "gpt-4o-mini";
            return AnalyzeGlobalTrafficAsync(apiKey, string.IsNullOrEmpty(model) ? defaultModel : model, appGroups, allConnections, blockedRulesCount, provider, "https://oxionai.com/v1");
        }

        public async Task<GeminiAnalysisResult> AnalyzeGlobalTrafficAsync(string apiKey, string model, IList<ProcessGroup> appGroups, IList<NetworkConnection> allConnections, int blockedRulesCount, string provider, string baseUrl)
        {
            string telemetry = BuildGlobalTelemetrySummary(appGroups, allConnections, blockedRulesCount);
            string prompt =
                "Tu es un expert en cybersécurité réseau Windows. Analyse l'ensemble du trafic réseau actuel du PC ci-dessous.\n" +
                "Réponds STRICTEMENT en JSON valide (sans texte hors JSON, sans balises markdown ```) avec exactement ces 6 clés en français :\n" +
                "{\n" +
                "  \"risk_level\": \"Faible | Modéré | Élevé\",\n" +
                "  \"summary\": \"Bilan global en 2-3 phrases de la santé réseau du PC\",\n" +
                "  \"what_it_does\": \"Explication globale de ce qui communique actuellement sur ce PC (navigateurs, services Windows, processus en arrière-plan, ports ouverts)\",\n" +
                "  \"utility\": \"Les flux légitimes/indispensables vs accessoires\",\n" +
                "  \"risks\": \"Anomalies éventuelles, ports en écoute exposés, processus suspects ou gourmands en bande passante\",\n" +
                "  \"cut_internet_impact\": \"Recommandations concrètes : quelles apps/ports on peut couper sans casser Windows vs ce qu'il faut laisser passer\"\n" +
                "}\n\n" +
                "Télémétrie du PC :\n" + telemetry;

            return await SendPromptAsync(apiKey, model, "Trafic Global du PC", "PC Global", prompt, provider, baseUrl);
        }

        public async Task<string> TestApiKeyAsync(string apiKey, string provider, string model, string baseUrl)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                throw new InvalidOperationException("Veuillez renseigner une clé API avant de tester.");

            bool isGemini = string.Equals(provider, "Gemini", StringComparison.OrdinalIgnoreCase);
            if (isGemini)
            {
                string chosenModel = string.IsNullOrWhiteSpace(model) ? "gemini-2.5-flash" : model.Trim();
                string url = string.Format(
                    "https://generativelanguage.googleapis.com/v1beta/models/{0}:generateContent?key={1}",
                    Uri.EscapeDataString(chosenModel),
                    Uri.EscapeDataString(apiKey.Trim()));

                JavaScriptSerializer ser = new JavaScriptSerializer();
                Dictionary<string, object> payload = new Dictionary<string, object>();
                payload["contents"] = new object[]
                {
                    new Dictionary<string, object>
                    {
                        { "parts", new object[] { new Dictionary<string, object> { { "text", "Ping. Réponds par un seul mot: OK." } } } }
                    }
                };

                string bodyJson = ser.Serialize(payload);
                using (HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, url))
                {
                    req.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");
                    using (HttpResponseMessage resp = await _httpClient.SendAsync(req))
                    {
                        string respText = await resp.Content.ReadAsStringAsync();
                        if (!resp.IsSuccessStatusCode)
                        {
                            string errMsg = ExtractGeminiError(respText, (int)resp.StatusCode);
                            throw new InvalidOperationException(errMsg);
                        }
                        return "Connexion réussie à Google Gemini (" + chosenModel + ").";
                    }
                }
            }
            else
            {
                string chosenModel = string.IsNullOrWhiteSpace(model) ? "gpt-4o-mini" : model.Trim();
                string root = string.IsNullOrWhiteSpace(baseUrl) ? "https://oxionai.com/v1" : baseUrl.Trim().TrimEnd('/');
                string url = root + "/chat/completions";

                JavaScriptSerializer ser = new JavaScriptSerializer();
                Dictionary<string, object> payload = new Dictionary<string, object>();
                payload["model"] = chosenModel;
                payload["messages"] = new object[]
                {
                    new Dictionary<string, object>
                    {
                        { "role", "user" },
                        { "content", "Ping. Réponds par OK." }
                    }
                };

                string bodyJson = ser.Serialize(payload);
                using (HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, url))
                {
                    req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiKey.Trim());
                    req.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");

                    using (HttpResponseMessage resp = await _httpClient.SendAsync(req))
                    {
                        string respText = await resp.Content.ReadAsStringAsync();
                        if (!resp.IsSuccessStatusCode)
                        {
                            string errMsg = ExtractOpenAiError(respText, (int)resp.StatusCode, provider ?? "Oxion AI");
                            throw new InvalidOperationException(errMsg);
                        }
                        return "Connexion réussie à " + (provider ?? "Oxion AI") + " (" + chosenModel + ").";
                    }
                }
            }
        }

        private async Task<GeminiAnalysisResult> SendPromptAsync(string apiKey, string model, string targetName, string scope, string prompt, string provider, string baseUrl)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                throw new InvalidOperationException("Veuillez d'abord renseigner votre clé API (" + (provider ?? "Oxion AI") + ").");

            bool isGemini = string.Equals(provider, "Gemini", StringComparison.OrdinalIgnoreCase);
            if (isGemini)
            {
                return await SendGeminiPromptAsync(apiKey, model, targetName, scope, prompt);
            }
            return await SendOxionAiPromptAsync(apiKey, model, targetName, scope, prompt, baseUrl, provider ?? "Oxion AI");
        }

        private async Task<GeminiAnalysisResult> SendOxionAiPromptAsync(string apiKey, string model, string targetName, string scope, string prompt, string baseUrl, string providerName)
        {
            string chosenModel = string.IsNullOrWhiteSpace(model) ? "gpt-4o-mini" : model.Trim();
            string root = string.IsNullOrWhiteSpace(baseUrl) ? "https://oxionai.com/v1" : baseUrl.Trim().TrimEnd('/');
            string url = root + "/chat/completions";

            JavaScriptSerializer ser = new JavaScriptSerializer();
            Dictionary<string, object> payload = new Dictionary<string, object>();
            payload["model"] = chosenModel;
            payload["temperature"] = 0.2;
            payload["messages"] = new object[]
            {
                new Dictionary<string, object>
                {
                    { "role", "system" },
                    { "content", "Tu es un expert en cybersécurité réseau Windows. Réponds STRICTEMENT en JSON valide (sans texte hors JSON, sans balises markdown) avec les clés demandées en français." }
                },
                new Dictionary<string, object>
                {
                    { "role", "user" },
                    { "content", prompt }
                }
            };

            string bodyJson = ser.Serialize(payload);
            using (HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, url))
            {
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiKey.Trim());
                req.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");

                using (HttpResponseMessage resp = await _httpClient.SendAsync(req))
                {
                    string respText = await resp.Content.ReadAsStringAsync();
                    if (!resp.IsSuccessStatusCode)
                    {
                        string errMsg = ExtractOpenAiError(respText, (int)resp.StatusCode, providerName);
                        throw new InvalidOperationException(errMsg);
                    }

                    string modelText = ExtractOpenAiText(respText);
                    return ParseAnalysisResult(targetName, scope, modelText);
                }
            }
        }

        private async Task<GeminiAnalysisResult> SendGeminiPromptAsync(string apiKey, string model, string targetName, string scope, string prompt)
        {
            string chosenModel = string.IsNullOrWhiteSpace(model) ? "gemini-2.5-flash" : model.Trim();
            string url = string.Format(
                "https://generativelanguage.googleapis.com/v1beta/models/{0}:generateContent?key={1}",
                Uri.EscapeDataString(chosenModel),
                Uri.EscapeDataString(apiKey.Trim()));

            JavaScriptSerializer ser = new JavaScriptSerializer();
            Dictionary<string, object> payload = new Dictionary<string, object>();
            payload["contents"] = new object[]
            {
                new Dictionary<string, object>
                {
                    { "parts", new object[] { new Dictionary<string, object> { { "text", prompt } } } }
                }
            };
            payload["generationConfig"] = new Dictionary<string, object>
            {
                { "temperature", 0.2 },
                { "responseMimeType", "application/json" }
            };

            string bodyJson = ser.Serialize(payload);
            using (HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, url))
            {
                req.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");
                using (HttpResponseMessage resp = await _httpClient.SendAsync(req))
                {
                    string respText = await resp.Content.ReadAsStringAsync();
                    if (!resp.IsSuccessStatusCode)
                    {
                        string errMsg = ExtractGeminiError(respText, (int)resp.StatusCode);
                        throw new InvalidOperationException(errMsg);
                    }

                    string modelText = ExtractCandidateText(respText);
                    return ParseAnalysisResult(targetName, scope, modelText);
                }
            }
        }

        private static string ExtractOpenAiError(string json, int statusCode, string providerName)
        {
            try
            {
                JavaScriptSerializer ser = new JavaScriptSerializer();
                Dictionary<string, object> root = ser.Deserialize<Dictionary<string, object>>(json);
                if (root != null && root.ContainsKey("error"))
                {
                    Dictionary<string, object> err = root["error"] as Dictionary<string, object>;
                    if (err != null && err.ContainsKey("message"))
                    {
                        return string.Format("Erreur {0} ({1}) : {2}", providerName, statusCode, err["message"]);
                    }
                    if (root["error"] is string)
                    {
                        return string.Format("Erreur {0} ({1}) : {2}", providerName, statusCode, root["error"]);
                    }
                }
            }
            catch { }
            return string.Format("Erreur HTTP {0} lors de l'appel {1}.", statusCode, providerName);
        }

        private static string ExtractGeminiError(string json, int statusCode)
        {
            try
            {
                JavaScriptSerializer ser = new JavaScriptSerializer();
                Dictionary<string, object> root = ser.Deserialize<Dictionary<string, object>>(json);
                if (root != null && root.ContainsKey("error"))
                {
                    Dictionary<string, object> err = root["error"] as Dictionary<string, object>;
                    if (err != null && err.ContainsKey("message"))
                        return string.Format("Erreur Gemini ({0}) : {1}", statusCode, err["message"]);
                }
            }
            catch { }
            return string.Format("Erreur HTTP {0} lors de l'appel Gemini.", statusCode);
        }

        public static string ExtractOpenAiText(string apiResponseJson)
        {
            if (string.IsNullOrWhiteSpace(apiResponseJson)) return "";
            try
            {
                JavaScriptSerializer ser = new JavaScriptSerializer();
                Dictionary<string, object> root = ser.Deserialize<Dictionary<string, object>>(apiResponseJson);
                if (root != null && root.ContainsKey("choices"))
                {
                    object[] choices = root["choices"] as object[];
                    if (choices == null)
                    {
                        System.Collections.ArrayList list = root["choices"] as System.Collections.ArrayList;
                        if (list != null && list.Count > 0)
                        {
                            choices = new object[list.Count];
                            list.CopyTo(choices);
                        }
                    }

                    if (choices != null && choices.Length > 0)
                    {
                        Dictionary<string, object> c0 = choices[0] as Dictionary<string, object>;
                        if (c0 != null)
                        {
                            if (c0.ContainsKey("message"))
                            {
                                Dictionary<string, object> msg = c0["message"] as Dictionary<string, object>;
                                if (msg != null && msg.ContainsKey("content") && msg["content"] != null)
                                    return msg["content"].ToString();
                            }
                            else if (c0.ContainsKey("text") && c0["text"] != null)
                            {
                                return c0["text"].ToString();
                            }
                        }
                    }
                }
            }
            catch { }
            return apiResponseJson;
        }

        public static string ExtractText(string apiResponseJson)
        {
            if (string.IsNullOrWhiteSpace(apiResponseJson)) return "";
            if (apiResponseJson.Contains("\"choices\""))
                return ExtractOpenAiText(apiResponseJson);
            if (apiResponseJson.Contains("\"candidates\""))
                return ExtractCandidateText(apiResponseJson);
            return apiResponseJson;
        }

        public static string ExtractCandidateText(string apiResponseJson)
        {
            JavaScriptSerializer ser = new JavaScriptSerializer();
            Dictionary<string, object> root = ser.Deserialize<Dictionary<string, object>>(apiResponseJson);
            if (root != null && root.ContainsKey("candidates"))
            {
                object[] candidates = root["candidates"] as object[];
                if (candidates == null)
                {
                    System.Collections.ArrayList list = root["candidates"] as System.Collections.ArrayList;
                    if (list != null && list.Count > 0) candidates = new object[] { list[0] };
                }

                if (candidates != null && candidates.Length > 0)
                {
                    Dictionary<string, object> cand = candidates[0] as Dictionary<string, object>;
                    if (cand != null && cand.ContainsKey("content"))
                    {
                        Dictionary<string, object> content = cand["content"] as Dictionary<string, object>;
                        if (content != null && content.ContainsKey("parts"))
                        {
                            System.Collections.ArrayList parts = content["parts"] as System.Collections.ArrayList;
                            if (parts != null && parts.Count > 0)
                            {
                                Dictionary<string, object> part0 = parts[0] as Dictionary<string, object>;
                                if (part0 != null && part0.ContainsKey("text"))
                                    return part0["text"] != null ? part0["text"].ToString() : "";
                            }
                        }
                    }
                }
            }
            return apiResponseJson;
        }

        public static GeminiAnalysisResult ParseAnalysisResult(string targetName, string scope, string rawText)
        {
            GeminiAnalysisResult result = new GeminiAnalysisResult
            {
                TargetName = targetName,
                Scope = scope,
                AnalyzedAt = DateTime.Now,
                RawResponse = rawText ?? ""
            };

            string cleaned = (rawText ?? "").Trim();
            if (cleaned.StartsWith("```json", StringComparison.OrdinalIgnoreCase))
                cleaned = cleaned.Substring(7).Trim();
            else if (cleaned.StartsWith("```"))
                cleaned = cleaned.Substring(3).Trim();

            if (cleaned.EndsWith("```"))
                cleaned = cleaned.Substring(0, cleaned.Length - 3).Trim();

            int startBrace = cleaned.IndexOf('{');
            int endBrace = cleaned.LastIndexOf('}');
            if (startBrace >= 0 && endBrace > startBrace)
            {
                cleaned = cleaned.Substring(startBrace, endBrace - startBrace + 1);
            }

            try
            {
                JavaScriptSerializer ser = new JavaScriptSerializer();
                Dictionary<string, object> dict = ser.Deserialize<Dictionary<string, object>>(cleaned);
                if (dict != null)
                {
                    result.RiskLevel = GetStr(dict, "risk_level", "Analysé");
                    result.Summary = GetStr(dict, "summary", "");
                    result.WhatItDoes = GetStr(dict, "what_it_does", "");
                    result.Utility = GetStr(dict, "utility", "");
                    result.Risks = GetStr(dict, "risks", "");
                    result.CutInternetImpact = GetStr(dict, "cut_internet_impact", "");

                    if (!string.IsNullOrEmpty(result.WhatItDoes) || !string.IsNullOrEmpty(result.Risks))
                        return result;
                }
            }
            catch { }

            // Repli propre si le modèle a répondu en texte libre
            result.RiskLevel = "Info";
            result.Summary = "Analyse textuelle brute reçue.";
            result.WhatItDoes = rawText;
            result.Utility = "Voir le détail dans 'Ce que fait l'application'.";
            result.Risks = "Non structuré dans la réponse brute.";
            result.CutInternetImpact = "Non structuré dans la réponse brute.";
            return result;
        }

        private static string GetStr(Dictionary<string, object> dict, string key, string fallback)
        {
            object val;
            if (dict.TryGetValue(key, out val) && val != null)
                return val.ToString().Trim();
            return fallback;
        }
    }
}
