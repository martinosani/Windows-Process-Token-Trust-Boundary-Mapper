using System;
using System.Collections.Generic;
using System.Linq;
using WTBM.Core;
using WTBM.Domain.Findings;
using WTBM.Domain.Processes;
using WTBM.Rules.Abstractions;
using WTBM.Rules.Engine;

namespace WTBM.Rules.Markers
{
    internal sealed class HighImpactPrivilegeProcessesRule : IRule
    {
        // Single source of truth:
        // presence in this map == privilege is in scope
        private static readonly IReadOnlyDictionary<string, int> PrivilegeWeights =
            new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                // "System integrity / trusted computing base" style privileges
                ["SeTcbPrivilege"] = 20,
                ["SeLoadDriverPrivilege"] = 20,
                ["SeAssignPrimaryTokenPrivilege"] = 15,

                // Common escalation chain enablers / impact multipliers
                ["SeDebugPrivilege"] = 10,
                ["SeImpersonatePrivilege"] = 10,

                // File/registry write semantics that amplify confused-deputy / TOCTOU classes
                ["SeRestorePrivilege"] = 5,
                ["SeBackupPrivilege"] = 5
            };

        // Docs live alongside the tool. Keep refs stable and portable.
        // Convention: "/doc/<filename>.md" (future docs can be appended without changing callers).
        private static readonly IReadOnlyList<string> ConceptRefsBase = new[]
        {
            "/doc/Windows Access Token Security.md",
            "/doc/Windows IPC Security (Inter-Process Communication).md"
        };

        public string RuleId => "PTTBM.PRIV.001";
        public string Title => "High-impact privileges assigned";
        public string Description => "Identifies processes holding privileges that materially increase trust-boundary risk when combined with reachable IPC surfaces.";
        public RuleKind Kind => RuleKind.Marker;
        public FindingCategory Category => FindingCategory.Privileges;

        public IEnumerable<Finding> Evaluate(RuleContext context)
        {
            if (context is null)
                yield break;

            foreach (var snapshot in context.Snapshots)
            {
                var process = snapshot.Process;
                var token = snapshot.Token;

                if (token?.Privileges is null || token.Privileges.Count == 0)
                    continue;

                // Enabled in token right now (active risk amplifier).
                var enabled = token.Privileges
                    .Where(p =>
                        p.IsEnabled &&
                        !string.IsNullOrWhiteSpace(p.Name) &&
                        PrivilegeWeights.ContainsKey(p.Name!))
                    .Select(p => p.Name!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                // Present but not enabled (latent capability; still relevant for design review).
                var presentDisabled = token.Privileges
                    .Where(p =>
                        !p.IsEnabled &&
                        !p.IsRemoved &&
                        !string.IsNullOrWhiteSpace(p.Name) &&
                        PrivilegeWeights.ContainsKey(p.Name!))
                    .Select(p => p.Name!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (enabled.Count == 0 && presentDisabled.Count == 0)
                    continue;

                // Helpful tags derived from context (do not overfit scoring to them).
                var exposureTags = BuildExposureTags(token);

                if (enabled.Count > 0)
                {
                    var score = ComputePrivilegeScore(
                        privileges: enabled,
                        enabled: true,
                        token: token,
                        process: process,
                        stats: context.PrivilegeStats);

                    yield return FindingFactory.Create(
                        rule: this,
                        severity: FindingSeverity.Info,
                        titleSuffix: string.Join(", ", enabled),

                        subjectType: FindingSubjectType.Process,
                        subjectId: process.Pid.ToString(),
                        subjectDisplayName: process.Name,

                        evidence: $"Enabled high-impact privileges: {string.Join(", ", enabled)}",
                        recommendation: BuildRecommendationEnabled(token, enabled),

                        tags: new[] { "high-impact-privilege", "priv-enabled" }
                            .Concat(exposureTags)
                            .ToArray(),

                        relatedPids: Array.Empty<int>(),
                        conceptRefs: ConceptRefsBase,
                        nextSteps: BuildNextSteps(token, enabled, enabled: true),

                        scoreOverride: score
                    );
                }

                if (presentDisabled.Count > 0)
                {
                    var score = ComputePrivilegeScore(
                        privileges: presentDisabled,
                        enabled: false,
                        token: token,
                        process: process,
                        stats: context.PrivilegeStats);

                    yield return FindingFactory.Create(
                        rule: this,
                        severity: FindingSeverity.Info,
                        titleSuffix: string.Join(", ", presentDisabled),

                        subjectType: FindingSubjectType.Process,
                        subjectId: process.Pid.ToString(),
                        subjectDisplayName: process.Name,

                        evidence: $"High-impact privileges present but disabled: {string.Join(", ", presentDisabled)}",
                        recommendation: BuildRecommendationPresentDisabled(token, presentDisabled),

                        tags: new[] { "high-impact-privilege", "priv-present-disabled" }
                            .Concat(exposureTags)
                            .ToArray(),

                        relatedPids: Array.Empty<int>(),
                        conceptRefs: ConceptRefsBase,
                        nextSteps: BuildNextSteps(token, presentDisabled, enabled: false),

                        scoreOverride: score
                    );
                }
            }
        }

        private static IReadOnlyList<string> BuildExposureTags(TokenInfo token)
        {
            var tags = new List<string>(capacity: 4);

            if (token.IsLocalSystem == true && token.SessionId is int s && s > 0)
                tags.Add("interactive-system");

            if (token.SessionId is int sess)
            {
                if (sess == 0) tags.Add("session-0");
                else tags.Add("session-user");
            }

            if (token.IsAppContainer == true) tags.Add("appcontainer");
            if (token.IsRestricted == true) tags.Add("restricted-token");

            return tags;
        }

        private static int ComputePrivilegeScore(
            IReadOnlyList<string> privileges,
            bool enabled,
            TokenInfo token,
            ProcessRecord process,
            PrivilegeStats stats)
        {
            // Baseline for Info marker (triage-oriented)
            var baseScore = 15;

            // Rarity-weighted authority sum
            double weighted = 0;
            var maxWeightedComponent = 0.0;

            foreach (var name in privileges)
            {
                if (!PrivilegeWeights.TryGetValue(name, out var w))
                    continue;

                // Default multiplier if stats have no data (e.g. TotalTokens==0)
                var m = 1.0;
                if (stats is not null && stats.TryGetMultiplier(name, out var mm))
                    m = mm;

                var component = w * m;
                weighted += component;

                if (component > maxWeightedComponent)
                    maxWeightedComponent = component;
            }

            var score = baseScore + (int)Math.Round(weighted);

            // Outlier nudge: one very strong (and rare) privilege should surface early.
            if (maxWeightedComponent >= 20.0)
                score += 5;

            // Exposure hint (tie-breaker): interactive SYSTEM tends to have more IPC adjacency.
            if (token.IsLocalSystem == true && token.SessionId is int sess && sess > 0)
                score += 5;

            // Disabled privileges are latent: penalize strongly and cap.
            if (!enabled)
            {
                score = (int)Math.Round(score * 0.45);
                score = Math.Min(score, 30);
                score = Math.Max(score, 10);
            }

            if (IsCoreWindowsProcess(process))
            {
                score -= 5;
            }

            if (IsThirdPartySystemService(process, token))
            {
                score += 5;
            }

            return Math.Min(100, Math.Max(0, score));
        }

        private static bool IsCoreWindowsProcess(ProcessRecord process)
        {
            if (process is null)
                return false;

            var name = process.Name;
            if (string.IsNullOrWhiteSpace(name))
                return false;

            // Minimal allowlist – volutamente conservativa
            switch (name.ToLowerInvariant())
            {
                case "svchost.exe":
                case "services.exe":
                case "lsass.exe":
                case "smss.exe":
                case "wininit.exe":
                case "winlogon.exe":
                    return true;
            }

            if (string.IsNullOrWhiteSpace(process.ImagePath))
                return false;

            var path = process.ImagePath;

            // Core OS location heuristic
            return path.StartsWith(@"C:\Windows\System32\", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(@"C:\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsThirdPartySystemService(ProcessRecord process, TokenInfo token)
        {
            if (process is null || token is null)
                return false;

            if (token.IsLocalSystem != true)
                return false;

            if (string.IsNullOrWhiteSpace(process.ImagePath))
                return false;

            var path = process.ImagePath;

            return path.StartsWith(@"C:\Program Files\", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(@"C:\Program Files (x86)\", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(@"C:\ProgramData\", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(@"C:\Windows\System32\DriverStore\", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(@"C:\Program Files\WindowsApps\", StringComparison.OrdinalIgnoreCase);
        }

        private static string BuildRecommendationEnabled(TokenInfo token, IReadOnlyList<string> enabledPrivileges)
        {
            var lines = new List<string>();

            lines.Add("Treat this as a trust-boundary risk amplifier, not a vulnerability by itself.");
            lines.Add("Prioritize review of any reachable IPC surfaces exposed by this process, because privilege + reachability is where real escalation chains appear.");

            lines.Add("");
            lines.Add("Operational hardening:");
            lines.Add("- Remove or avoid granting privileges that are not strictly required for steady-state operation (principle of least privilege).");
            lines.Add("- If the process is a service, verify the service account and assigned privileges are intentional and minimal.");
            lines.Add("- Prefer designs where high-trust components impersonate the client for access checks, and only perform privileged actions after explicit authorization (avoid confused-deputy behavior).");
            lines.Add("- If IPC is required, tighten endpoint ACLs (named pipe/RPC/COM) so that only intended callers and trust tiers can reach it.");

            // Add targeted hints based on what we saw (keep it short but useful).
            if (enabledPrivileges.Contains("SeImpersonatePrivilege", StringComparer.OrdinalIgnoreCase))
            {
                lines.Add("");
                lines.Add("Privilege-specific notes (SeImpersonatePrivilege):");
                lines.Add("- Explicitly validate caller identity and trust tier before performing privileged actions.");
                lines.Add("- If the server impersonates, ensure the privileged action is performed under the correct token (no accidental use of server token).");
            }

            if (enabledPrivileges.Contains("SeDebugPrivilege", StringComparer.OrdinalIgnoreCase))
            {
                lines.Add("");
                lines.Add("Privilege-specific notes (SeDebugPrivilege):");
                lines.Add("- Consider the impact on handle access and process inspection; any IPC that results in 'open process' style operations becomes higher risk.");
            }

            if (enabledPrivileges.Contains("SeLoadDriverPrivilege", StringComparer.OrdinalIgnoreCase))
            {
                lines.Add("");
                lines.Add("Privilege-specific notes (SeLoadDriverPrivilege):");
                lines.Add("- Audit any paths that accept file names, registry keys, or configuration that influences driver/service loading behavior.");
            }

            if (token.IsLocalSystem == true && token.SessionId is int s && s > 0)
            {
                lines.Add("");
                lines.Add("Exposure hint:");
                lines.Add("- This is SYSTEM in an interactive session; treat it as potentially more reachable via COM/UI/IPC adjacency (validate reachability explicitly).");
            }

            return string.Join(Environment.NewLine, lines);
        }

        private static string BuildRecommendationPresentDisabled(TokenInfo token, IReadOnlyList<string> presentDisabledPrivileges)
        {
            var lines = new List<string>();

            lines.Add("These privileges are currently disabled, so they are not an active boundary amplifier.");
            lines.Add("However, their presence can still matter for trust-boundary analysis (on-demand enablement paths, component reuse, or misconfiguration).");

            lines.Add("");
            lines.Add("Operational hardening:");
            lines.Add("- If the privilege is not required for any code path, remove it from the assigned privilege set (or redesign to avoid requiring it).");
            lines.Add("- Confirm the privilege cannot be enabled indirectly by untrusted input paths (e.g., broker requests that trigger privileged actions).");
            lines.Add("- Use this finding to decide where deeper IPC mapping is worth time, but keep priority below enabled cases.");

            if (token.IsLocalSystem == true && token.SessionId is int s && s > 0)
            {
                lines.Add("");
                lines.Add("Exposure hint:");
                lines.Add("- Interactive SYSTEM context can increase reachable surface; validate IPC reachability before assuming low risk.");
            }

            return string.Join(Environment.NewLine, lines);
        }

        private static IReadOnlyList<InvestigationStep> BuildNextSteps(TokenInfo token, IReadOnlyList<string> privilegeNames, bool enabled)
        {
            // Keep steps actionable and aligned with the tool’s direction:
            // map reachability and authority, then look for confused-deputy / unsafe privileged operations.

            var steps = new List<InvestigationStep>(capacity: 6);

            steps.Add(new InvestigationStep(
                Title: "Map candidate broker surfaces (IPC inventory)",
                Description:
                    "Enumerate IPC endpoints exposed by the subject process (start with named pipes; later expand to RPC/COM). " +
                    "Capture endpoint names and security descriptors to reason about reachability from Medium/Low/AppContainer callers."
            ));

            steps.Add(new InvestigationStep(
                Title: "Validate reachability by trust tier",
                Description:
                    "For each discovered endpoint, evaluate whether a caller at Medium IL, Low IL, or AppContainer can connect/open it based on the endpoint DACL and token restrictions. " +
                    "Treat 'reachable + high authority' as the primary triage signal for deeper analysis."
            ));

            steps.Add(new InvestigationStep(
                Title: "Determine server-side impersonation and authorization model",
                Description:
                    "When an endpoint is reachable, identify whether the server impersonates the client, and where authorization decisions occur. " +
                    "Look specifically for patterns where the server performs privileged actions using its own token based on client-controlled input (confused deputy)."
            ));

            steps.Add(new InvestigationStep(
                Title: "Track privileged action classes influenced by requests",
                Description:
                    "Focus on operations commonly involved in LPE/sandbox-escape chains: file writes/moves, registry writes, service/task configuration, token/process operations, and security descriptor changes. " +
                    "Document any client-controlled paths/object names and verify canonicalization + use-site checks."
            ));

            if (privilegeNames.Contains("SeImpersonatePrivilege", StringComparer.OrdinalIgnoreCase))
            {
                steps.Add(new InvestigationStep(
                    Title: "Prioritize impersonation-related call paths",
                    Description:
                        "If reachable IPC exists, examine whether the server uses impersonation APIs correctly (e.g., binds identity to request, re-checks at use-site). " +
                        "Misuse here often creates high-value trust boundary mistakes even without memory corruption."
                ));
            }

            if (!enabled)
            {
                steps.Add(new InvestigationStep(
                    Title: "Assess on-demand enablement paths",
                    Description:
                        "Since the privileges are disabled, check whether the component enables them during specific operations. " +
                        "If so, focus analysis on the request types or code paths that trigger enablement and whether those paths are reachable from lower-trust callers."
                ));
            }

            return steps;
        }
    }
}
