using System;
using System.Collections.Generic;
using System.Text;
using PTTBM.Models;
using PTTBM.Models.Rules;

namespace PTTBM.Collectors.Rules
{
    /// <summary>
    /// PTTBM.PRIV.001
    ///
    /// High-impact token privileges marker.
    ///
    /// Goal:
    /// - Surface processes whose effective token carries privileges that materially expand impact
    ///   once code execution or logic control is achieved (memory-safety bug, plugin abuse, IPC misuse,
    ///   confused-deputy paths, etc.).
    ///
    /// Design:
    /// - Fact-first: privilege presence and privilege state (Enabled / EnabledByDefault / Present / Removed)
    ///   are derived directly from token attributes.
    /// - Conservative severity: "Enabled" is the primary driver. "Present-only" is a weaker signal,
    ///   especially on High/System tokens where many privileges may be present by design.
    /// - No role claims: does not claim exploitation. It flags review targets and provides investigation guidance.
    /// </summary>
    internal sealed class HighImpactPrivilegesRule : IProcessRule
    {
        public string RuleId => "PTTBM.PRIV.001";
        public string Title => "High-impact token privileges present";
        public FindingCategory Category => FindingCategory.Privileges;

        // Default baseline for a privileges marker; severity is computed per instance.
        public FindingSeverity BaselineSeverity => FindingSeverity.Medium;

        // "Critical" privileges: widely recognized as enabling powerful primitives when enabled.
        private static readonly HashSet<string> CriticalPrivileges = new(StringComparer.OrdinalIgnoreCase)
        {
            "SeDebugPrivilege",
            "SeTcbPrivilege",
            "SeCreateTokenPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeImpersonatePrivilege",
            "SeLoadDriverPrivilege",
            "SeSecurityPrivilege",
            "SeSystemEnvironmentPrivilege"
        };

        // "Significant" privileges: meaningful security implications; may bypass typical access intent.
        private static readonly HashSet<string> SignificantPrivileges = new(StringComparer.OrdinalIgnoreCase)
        {
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeManageVolumePrivilege",
            "SeCreateGlobalPrivilege",
            "SeRelabelPrivilege"
        };

        public IEnumerable<ProcessFinding> Evaluate(ProcessSnapshot s, RuleContext ctx)
        {
            if (s is null || ctx is null)
                yield break;

            var token = s.Token;
            var privs = token.Privileges;

            // If privileges are not observable, this rule does not emit a finding.
            if (privs is null || privs.Count == 0)
                yield break;

            var matches = CollectHighImpactPrivileges(privs);
            if (matches.Count == 0)
                yield break;

            // Group privileges by state for better readability and more accurate reasoning.
            var groups = GroupByState(matches);

            // Severity is driven primarily by enabled state (realistic triage).
            var severity = ComputeSeverity(token, groups);

            var evidence = BuildEvidence(s, groups);
            var recommendation = BuildRecommendation(s, groups);

            var tags = new List<string> { "high-impact-privilege" };

            // Facts-only: no correlation in this rule.
            var relatedPids = Array.Empty<int>();

            var conceptRefs = new List<string>
            {
                "docs/concepts/tokens-and-privileges.md"
            };

            var nextSteps = new List<InvestigationStep>
            {
                new(
                    "Validate necessity",
                    "Confirm the privilege set is required for the process role. If not, reduce privileges (least privilege, service hardening, token filtering) or isolate privileged operations into a constrained helper."
                ),
                new(
                    "Determine enablement behavior",
                    "Identify whether privileges are enabled by default or enabled only during specific operations (AdjustTokenPrivileges). Review those code paths and their input validation/authorization."
                ),
                new(
                    "Intersect with reachable surfaces",
                    "Map how untrusted inputs reach privileged operations (IPC endpoints, file/registry handoffs, plugins/extensions, network parsers). High-impact privileges amplify the consequences of bugs in those surfaces."
                )
            };

            yield return FindingFactory.Create(
                rule: this,
                snapshot: s,
                severity: severity,
                titleSuffix: BuildTitleSuffix(groups),
                evidence: evidence,
                recommendation: recommendation,
                tags: tags,
                relatedPids: relatedPids,
                conceptRefs: conceptRefs,
                nextSteps: nextSteps
            );
        }

        // =========================
        // Collection / grouping
        // =========================

        private static List<PrivMatch> CollectHighImpactPrivileges(IReadOnlyList<TokenPrivilegeInfo> privs)
        {
            var matches = new List<PrivMatch>(capacity: 8);

            foreach (var p in privs)
            {
                var name = p.Name;
                if (string.IsNullOrWhiteSpace(name))
                    continue;

                if (!CriticalPrivileges.Contains(name) && !SignificantPrivileges.Contains(name))
                    continue;

                var tier = CriticalPrivileges.Contains(name) ? PrivTier.Critical : PrivTier.Significant;

                var state = new PrivState(
                    IsEnabled: p.IsEnabled,
                    IsEnabledByDefault: p.IsEnabledByDefault,
                    IsRemoved: p.IsRemoved
                );

                matches.Add(new PrivMatch(name, tier, state));
            }

            return matches;
        }

        private static PrivGroups GroupByState(List<PrivMatch> matches)
        {
            // Stable ordering: critical first, then significant; within each state, alphabetical.
            static IEnumerable<PrivMatch> Order(IEnumerable<PrivMatch> xs) =>
                xs.OrderByDescending(m => m.Tier == PrivTier.Critical)
                  .ThenBy(m => m.Name, StringComparer.OrdinalIgnoreCase);

            var enabled = Order(matches.Where(m => m.State.IsEnabled)).ToList();
            var defaultEnabled = Order(matches.Where(m => !m.State.IsEnabled && m.State.IsEnabledByDefault)).ToList();
            var removed = Order(matches.Where(m => m.State.IsRemoved)).ToList();
            var presentOnly = Order(matches.Where(m => !m.State.IsEnabled && !m.State.IsEnabledByDefault && !m.State.IsRemoved)).ToList();

            return new PrivGroups(enabled, defaultEnabled, presentOnly, removed, matches);
        }

        // =========================
        // Severity model (realistic, conservative)
        // =========================

        private static FindingSeverity ComputeSeverity(TokenInfo token, PrivGroups g)
        {
            bool enabledCritical = g.Enabled.Any(m => m.Tier == PrivTier.Critical);
            bool enabledSignificant = g.Enabled.Any(m => m.Tier == PrivTier.Significant);

            bool defaultCritical = g.DefaultEnabled.Any(m => m.Tier == PrivTier.Critical);
            bool defaultSignificant = g.DefaultEnabled.Any(m => m.Tier == PrivTier.Significant);

            bool anyCriticalPresentOnly = g.PresentOnly.Any(m => m.Tier == PrivTier.Critical);
            bool anySignificantPresentOnly = g.PresentOnly.Any(m => m.Tier == PrivTier.Significant);

            // Enabled is the strongest practical signal (most direct leverage).
            if (enabledCritical)
                return FindingSeverity.High;

            // Default-enabled suggests frequent activation; still meaningful.
            if (defaultCritical)
                return FindingSeverity.Medium;

            // Enabled significant privileges can be impactful (e.g., Backup/Restore semantics).
            if (enabledSignificant)
                return FindingSeverity.Medium;

            // For High/System tokens, many privileges may be present-only by design.
            // Treat present-only as Low severity, but still a useful marker for research prioritization.
            if (token.IntegrityLevel == IntegrityLevel.High || token.IntegrityLevel == IntegrityLevel.System)
            {
                if (anyCriticalPresentOnly || anySignificantPresentOnly || defaultSignificant)
                    return FindingSeverity.Low;

                return FindingSeverity.Low;
            }

            // For Medium integrity user processes, present-only critical privileges are uncommon and worth review,
            // but still weaker than enabled/default-enabled.
            if (token.IntegrityLevel == IntegrityLevel.Medium)
            {
                if (anyCriticalPresentOnly)
                    return FindingSeverity.Medium;

                if (anySignificantPresentOnly || defaultSignificant)
                    return FindingSeverity.Low;

                return FindingSeverity.Low;
            }

            // For Low integrity processes, any high-impact privilege is unusual; treat as Medium.
            if (token.IntegrityLevel == IntegrityLevel.Low)
            {
                if (anyCriticalPresentOnly || anySignificantPresentOnly || defaultSignificant)
                    return FindingSeverity.Medium;

                return FindingSeverity.Low;
            }

            // Unknown integrity: conservative default.
            if (anyCriticalPresentOnly || defaultCritical || enabledSignificant || defaultSignificant)
                return FindingSeverity.Medium;

            return FindingSeverity.Low;
        }

        private static string BuildTitleSuffix(PrivGroups g)
        {
            int enabled = g.Enabled.Count;
            int def = g.DefaultEnabled.Count;
            int present = g.PresentOnly.Count;

            // Keep suffix short and stable.
            return $"enabled={enabled}, default={def}, present={present}";
        }

        // =========================
        // Evidence / recommendation (clear, non-alarmist)
        // =========================

        private static string BuildEvidence(ProcessSnapshot s, PrivGroups g)
        {
            var t = s.Token;

            var sb = new StringBuilder(768);

            sb.Append($"IL={t.IntegrityLevel}; ");
            sb.Append($"User={RuleHelpers.Safe(t.UserName)}; ");
            sb.Append($"ElevationType={t.ElevationType}; ");
            sb.Append($"IsElevated={RuleHelpers.Safe(t.IsElevated?.ToString())}; ");
            sb.Append($"AppContainer={RuleHelpers.Safe(t.IsAppContainer?.ToString())}; ");
            sb.Append($"Restricted={RuleHelpers.Safe(t.IsRestricted?.ToString())}; ");

            // Evidence should emphasize enabled/default-enabled, and then summarize the rest.
            sb.Append("Enabled=[");
            sb.Append(string.Join(", ", g.Enabled.Select(m => m.Name)));
            sb.Append("]; ");

            sb.Append("DefaultEnabled=[");
            sb.Append(string.Join(", ", g.DefaultEnabled.Select(m => m.Name)));
            sb.Append("]; ");

            sb.Append($"PresentOnlyCount={g.PresentOnly.Count}; ");
            sb.Append($"RemovedCount={g.Removed.Count}");

            return sb.ToString();
        }

        private static string BuildRecommendation(ProcessSnapshot s, PrivGroups g)
        {
            var t = s.Token;
            var sb = new StringBuilder(2200);

            sb.AppendLine("High-impact privileges were observed on the process token.");
            sb.AppendLine("Token privileges define OS capabilities that can materially change the impact of a vulnerability or a logic flaw once control is achieved.");
            sb.AppendLine();

            sb.AppendLine("Interpretation notes:");
            sb.AppendLine("- Enabled privileges are the strongest practical signal (immediate leverage).");
            sb.AppendLine("- Present-only privileges may be expected on elevated/system tokens; treat them as blast-radius indicators unless you can show they are enabled or reachable via specific code paths.");
            if (t.IntegrityLevel == IntegrityLevel.High || t.IntegrityLevel == IntegrityLevel.System)
            {
                sb.AppendLine("- This token runs at High/System integrity; many privileges can be present by design. Focus on enabled/default-enabled privileges and on reachable input surfaces.");
            }
            sb.AppendLine();

            sb.AppendLine("Observed privileges by state:");
            WriteGroup(sb, "Enabled", g.Enabled);
            WriteGroup(sb, "EnabledByDefault (but not currently enabled)", g.DefaultEnabled);
            WriteGroup(sb, "Present (not enabled)", g.PresentOnly);
            if (g.Removed.Count > 0)
                WriteGroup(sb, "Removed", g.Removed);

            sb.AppendLine();
            sb.AppendLine("Investigation guidance (practical):");
            sb.AppendLine("1) Validate necessity: confirm each enabled/default-enabled privilege is required for the component role.");
            sb.AppendLine("2) Determine activation: identify where privileges are enabled (AdjustTokenPrivileges) and what inputs influence those paths.");
            sb.AppendLine("3) Intersect with surfaces: enumerate IPC endpoints and indirect handoffs; prioritize review/fuzzing where untrusted input reaches privileged operations.");
            sb.AppendLine("4) Validate enforcement: authorization, identity binding, canonicalization, and TOCTOU-safe checks at use sites.");

            // Focus notes only for privileges that are actually enabled/default-enabled; keep it actionable and not noisy.
            var highLeverage = g.Enabled.Concat(g.DefaultEnabled).ToList();
            if (highLeverage.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("High-leverage notes (based on enabled/default-enabled privileges):");

                if (highLeverage.Any(m => m.Name.Equals("SeImpersonatePrivilege", StringComparison.OrdinalIgnoreCase)))
                {
                    sb.AppendLine("- SeImpersonatePrivilege: increases the value of server-side impersonation flows (named pipes/RPC/COM). Verify strict client identity binding and authorization before acting on caller-provided inputs.");
                }

                if (highLeverage.Any(m => m.Name.Equals("SeDebugPrivilege", StringComparison.OrdinalIgnoreCase)))
                {
                    sb.AppendLine("- SeDebugPrivilege: enables broad process access. If the process accepts untrusted inputs, validate it cannot be influenced to open/modify sensitive processes or handles.");
                }

                if (highLeverage.Any(m => m.Name.Equals("SeLoadDriverPrivilege", StringComparison.OrdinalIgnoreCase)))
                {
                    sb.AppendLine("- SeLoadDriverPrivilege: driver loading is a high-impact primitive. Ensure the process cannot be influenced to load attacker-controlled drivers or paths.");
                }

                if (highLeverage.Any(m =>
                        m.Name.Equals("SeBackupPrivilege", StringComparison.OrdinalIgnoreCase) ||
                        m.Name.Equals("SeRestorePrivilege", StringComparison.OrdinalIgnoreCase)))
                {
                    sb.AppendLine("- SeBackupPrivilege / SeRestorePrivilege: can bypass typical file ACL intent via backup/restore semantics. Harden path canonicalization and TOCTOU controls around any privileged file operations.");
                }

                if (highLeverage.Any(m => m.Name.Equals("SeTakeOwnershipPrivilege", StringComparison.OrdinalIgnoreCase)))
                {
                    sb.AppendLine("- SeTakeOwnershipPrivilege: can take ownership of securable objects. Confirm the process cannot be driven to take ownership of attacker-chosen targets.");
                }
            }

            sb.AppendLine();
            sb.AppendLine("Token context:");
            sb.AppendLine($"- IntegrityLevel: {t.IntegrityLevel}");
            sb.AppendLine($"- ElevationType: {t.ElevationType} (IsElevated={RuleHelpers.Safe(t.IsElevated?.ToString())})");
            sb.AppendLine($"- AppContainer: {RuleHelpers.Safe(t.IsAppContainer?.ToString())}, Restricted: {RuleHelpers.Safe(t.IsRestricted?.ToString())}");

            return sb.ToString().TrimEnd();
        }

        private static void WriteGroup(StringBuilder sb, string title, IReadOnlyList<PrivMatch> items)
        {
            sb.AppendLine($"- {title}:");

            if (items.Count == 0)
            {
                sb.AppendLine("  - <empty>");
                return;
            }

            foreach (var m in items)
            {
                sb.AppendLine($"  - {m.Name} ({m.Tier})");
            }
        }

        // =========================
        // Internal types
        // =========================

        private enum PrivTier
        {
            Significant = 1,
            Critical = 2
        }

        private sealed record PrivMatch(
            string Name,
            PrivTier Tier,
            PrivState State);

        private sealed record PrivState(
            bool IsEnabled,
            bool IsEnabledByDefault,
            bool IsRemoved);

        private sealed record PrivGroups(
            IReadOnlyList<PrivMatch> Enabled,
            IReadOnlyList<PrivMatch> DefaultEnabled,
            IReadOnlyList<PrivMatch> PresentOnly,
            IReadOnlyList<PrivMatch> Removed,
            IReadOnlyList<PrivMatch> All);
    }
}
