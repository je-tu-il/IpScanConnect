using System;

namespace IpScanConnect.Models
{
    public class GeminiAnalysisResult
    {
        public string TargetName { get; set; }
        public string Scope { get; set; } // "Application" ou "PC Global"
        public DateTime AnalyzedAt { get; set; }
        public string RiskLevel { get; set; }
        public string Summary { get; set; }
        public string WhatItDoes { get; set; }
        public string Utility { get; set; }
        public string Risks { get; set; }
        public string CutInternetImpact { get; set; }
        public string RawResponse { get; set; }

        public string HeaderDisplay
        {
            get
            {
                return string.Format("[{0}] {1} — {2} ({3})",
                    AnalyzedAt.ToString("HH:mm:ss"),
                    Scope,
                    TargetName,
                    string.IsNullOrEmpty(RiskLevel) ? "Analysé" : RiskLevel);
            }
        }
    }
}
