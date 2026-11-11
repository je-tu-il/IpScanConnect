using System;
using System.Windows;
using System.Windows.Media;
using IpScanConnect.Models;

namespace IpScanConnect
{
    public partial class AiAnalysisWindow : Window
    {
        public AiAnalysisWindow(string targetName)
        {
            InitializeComponent();
            TxtTitle.Text = "✨ Gemini IA — " + targetName;
        }

        public void SetResult(GeminiAnalysisResult result)
        {
            ProgressLoading.Visibility = Visibility.Collapsed;
            PanelSections.Visibility = Visibility.Visible;

            if (result == null) return;

            TxtTitle.Text = "✨ Gemini IA — " + result.TargetName;
            TxtSummary.Text = string.IsNullOrEmpty(result.Summary) ? "Analyse terminée." : result.Summary;
            TxtWhatItDoes.Text = string.IsNullOrEmpty(result.WhatItDoes) ? "Non précisé." : result.WhatItDoes;
            TxtUtility.Text = string.IsNullOrEmpty(result.Utility) ? "Non précisé." : result.Utility;
            TxtRisks.Text = string.IsNullOrEmpty(result.Risks) ? "Aucun risque majeur signalé." : result.Risks;
            TxtCutImpact.Text = string.IsNullOrEmpty(result.CutInternetImpact) ? "Non précisé." : result.CutInternetImpact;

            string level = (result.RiskLevel ?? "Analysé").Trim();
            TxtRiskLevel.Text = level;

            string low = level.ToLowerInvariant();
            if (low.Contains("élev") || low.Contains("elev") || low.Contains("haut") || low.Contains("crit"))
            {
                RiskBadge.Background = new SolidColorBrush(Color.FromRgb(69, 10, 10));
                RiskBadge.BorderBrush = new SolidColorBrush(Color.FromRgb(239, 68, 68));
                TxtRiskLevel.Foreground = new SolidColorBrush(Color.FromRgb(252, 165, 165));
            }
            else if (low.Contains("mod") || low.Contains("moy"))
            {
                RiskBadge.Background = new SolidColorBrush(Color.FromRgb(69, 26, 3));
                RiskBadge.BorderBrush = new SolidColorBrush(Color.FromRgb(245, 158, 11));
                TxtRiskLevel.Foreground = new SolidColorBrush(Color.FromRgb(253, 230, 138));
            }
            else
            {
                RiskBadge.Background = new SolidColorBrush(Color.FromRgb(6, 78, 59));
                RiskBadge.BorderBrush = new SolidColorBrush(Color.FromRgb(16, 185, 129));
                TxtRiskLevel.Foreground = new SolidColorBrush(Color.FromRgb(110, 231, 183));
            }
        }

        public void SetError(string message)
        {
            ProgressLoading.Visibility = Visibility.Collapsed;
            PanelSections.Visibility = Visibility.Visible;
            TxtRiskLevel.Text = "❌ Erreur";
            RiskBadge.Background = new SolidColorBrush(Color.FromRgb(69, 10, 10));
            RiskBadge.BorderBrush = new SolidColorBrush(Color.FromRgb(239, 68, 68));
            TxtRiskLevel.Foreground = new SolidColorBrush(Color.FromRgb(252, 165, 165));
            TxtSummary.Text = message;
            TxtWhatItDoes.Text = message;
            TxtUtility.Text = "Vérifiez votre clé API Gemini et votre connexion Internet.";
            TxtRisks.Text = "-";
            TxtCutImpact.Text = "-";
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
