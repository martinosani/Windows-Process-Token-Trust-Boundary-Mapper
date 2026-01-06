using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.CommandLine.Parsing;
using System.Diagnostics;
using System.Text;
using WTBM.Collectors.IPC;
using WTBM.Core;
using WTBM.Domain.Findings;
using WTBM.Domain.IPC;
using WTBM.Rules.Abstractions;
using WTBM.Rules.Engine;

namespace WTBM.Rules.Markers
{
    internal sealed class HighAuthorityNamedPipeInventoryRule : IRule
    {
        public string RuleId => "PTTBM.PRIV.002";
        public string Title => "Named pipe inventory for high-authority processes";
        public string Description =>
            "Enumerates named pipes exposed by high-authority processes and reports their presence and security metadata. " +
            "This rule provides visibility into IPC surfaces without assessing cross-boundary access or exploitability.";
        public RuleKind Kind => RuleKind.Marker;
        public FindingCategory Category => FindingCategory.IPC;

        public IEnumerable<Finding> Evaluate(RuleContext context)
        {
            if (context is null)
                yield break;

            var findings = context.GetRule("PTTBM.PRIV.001").Evaluate(context);
            var npe = new NamedPipeExtractor();

            foreach (var finding in findings)
            {
                int pid = int.Parse(finding.SubjectId);

                var pipes = npe.GetNamedPipesFromProcessHandles(pid).ToList();

                if (pipes.Count == 0)
                    continue;

                Logger.LogDebug(String.Format("[PID:{0}] Found {1} named pipes", pid, pipes.Count));

                var evidence = BuildEvidence(pid, finding.SubjectDisplayName, pipes);

                yield return FindingFactory.Create(
                    rule: this,
                    severity: FindingSeverity.Info,
                    titleSuffix: $"PID {pid}",

                    subjectType: FindingSubjectType.Process,
                    subjectId: pid.ToString(),
                    subjectDisplayName: finding.SubjectDisplayName,

                    evidence: evidence,
                    recommendation: "Use this inventory as input for follow-up checks: identify pipes that are reachable from lower integrity contexts and review their security descriptors and expected callers.",

                    tags: new List<string> { "inventory", "named-pipes", "high-authority" },
                    relatedPids: Array.Empty<int>(),
                    conceptRefs: Array.Empty<string>(),
                    nextSteps: Array.Empty<InvestigationStep>(),

                    // keySuffix not needed for one finding per process
                    keySuffix: null
                );
            }
        }

        private static string BuildEvidence(int pid, string? processName, IReadOnlyList<NamedPipeEndpoint> pipes)
        {
            var sb = new StringBuilder(capacity: 4096);

            // ---- Header ------------------------------------------------------------
            sb.AppendLine("High-authority process named pipe inventory");
            sb.AppendLine();

            sb.AppendLine("Process:");
            sb.AppendLine($"- PID: {pid}");

            if (!string.IsNullOrWhiteSpace(processName))
                sb.AppendLine($"- Name: {processName}");

            sb.AppendLine();

            sb.AppendLine($"Pipes (total: {pipes.Count}):");
            sb.AppendLine();

            // Defensive: stable ordering improves diffability and readability
            foreach (var pipe in pipes
                .OrderBy(p => p.Pipe?.NtPath ?? p.Pipe?.ToString() ?? string.Empty,
                         StringComparer.OrdinalIgnoreCase))
            {
                // ---- Pipe identity -------------------------------------------------
                var pipeName = pipe.Pipe?.ToString() ?? "<unknown>";
                sb.AppendLine($"- {pipeName}");

                // ---- Security descriptor (best-effort) ----------------------------
                var sec = pipe.Security;

                if (sec == null)
                {
                    sb.AppendLine("  Security: <not available>");
                    sb.AppendLine();
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(sec.Error))
                {
                    // Explicitly surface collection/parsing errors without breaking output
                    sb.AppendLine($"  Security: <error>");
                    sb.AppendLine($"    Reason: {sec.Error}");
                    sb.AppendLine();
                    continue;
                }

                // ---- Owner ---------------------------------------------------------
                var ownerName = !string.IsNullOrWhiteSpace(sec.OwnerName)
                    ? sec.OwnerName
                    : "<unknown>";

                var ownerSid = !string.IsNullOrWhiteSpace(sec.OwnerSid)
                    ? sec.OwnerSid
                    : "<unknown>";

                sb.AppendLine($"  Owner: {ownerName} ({ownerSid})");

                // ---- Parsed SDDL summary ------------------------------------------
                var summary = sec.SddlSummary;
                if (summary == null)
                {
                    sb.AppendLine("  Security Descriptor:");
                    sb.AppendLine("    Parsed: no (raw SDDL only)");
                    sb.AppendLine();
                    continue;
                }

                sb.AppendLine("  Security Descriptor:");

                sb.AppendLine($"    DACL present: {(summary.HasDacl ? "yes" : "no")}");
                sb.AppendLine($"    SACL present: {(summary.HasSacl ? "yes" : "no")}");

                // ---- Mandatory Integrity Label ------------------------------------
                if (summary.MandatoryIntegrityRid.HasValue)
                {
                    sb.AppendLine(
                        $"    Mandatory Integrity: 0x{summary.MandatoryIntegrityRid.Value:X}");
                }
                else
                {
                    sb.AppendLine("    Mandatory Integrity: <not specified>");
                }

                // ---- Reachability placeholder (explicitly non-evaluated) ----------
                // Keep this explicit to avoid misinterpretation by readers.
                sb.AppendLine("    Reachability: not evaluated (static inventory only)");

                // ---- Tags (high-signal, compact) ----------------------------------
                if (summary.Tags != null && summary.Tags.Count > 0)
                {
                    sb.AppendLine($"    Tags: [{string.Join(", ", summary.Tags)}]");
                }

                // ---- Optional: high-signal ACEs -----------------------------------
                // Only print ACEs if they exist and add explanatory value.
                if (summary.DaclAces != null && summary.DaclAces.Count > 0)
                {
                    sb.AppendLine("    Relevant DACL entries:");

                    foreach (var ace in summary.DaclAces)
                    {
                        var aceName = !string.IsNullOrWhiteSpace(ace.Name)
                            ? ace.Name
                            : ace.Sid;

                        sb.AppendLine(
                            $"      - {ace.Type} {aceName} " +
                            $"[{ace.AccessText}] Flags={ace.Flags}");
                    }
                }

                sb.AppendLine();
            }

            return sb.ToString();
        }
    }
}
