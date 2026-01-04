using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Core;
using WTBM.Domain.Findings;
using WTBM.Domain.IPC;
using WTBM.Domain.Processes;
using WTBM.Rules.Abstractions;

namespace WTBM.Rules.Engine
{
    internal static class RuleEngine
    {
        public static List<Finding> EvaluateAll(
            IReadOnlyList<ProcessSnapshot> snapshots,
            IReadOnlyList<NamedPipeEndpoint> namedPipes,
            IReadOnlyList<IRule> rules)
        {
            if (snapshots is null) throw new ArgumentNullException(nameof(snapshots));
            if (rules is null) throw new ArgumentNullException(nameof(rules));

            var ctx = new RuleContext(snapshots, namedPipes);

            var results = new List<Finding>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var r in rules)
            {
                IEnumerable<Finding> produced;
                try
                {
                    produced = r.Evaluate(ctx);
                }
                catch (Exception ex)
                {
                    // Best-effort: a rule should never break the run.
                    results.Add(new Finding(
                        r.RuleId,
                        r.Title,
                        FindingSeverity.Info,
                        FindingCategory.Visibility,
                        FindingSubjectType.Boundary,
                        "WTBM.ENGINE.001",
                        $"Rule failed: {r.RuleId}",
                        0,
                        ex.GetType().Name,
                        "Inspect logs / enable verbose diagnostics.",
                        Array.Empty<string>(),
                        Array.Empty<int>(),
                        Array.Empty<string>(),
                        Array.Empty<InvestigationStep>(),
                        $"WTBM.ENGINE.001:{r.RuleId}"));
                    continue;
                }

                foreach (var f in produced)
                {
                    if (string.IsNullOrWhiteSpace(f.Key))
                        continue;

                    if (seen.Add(f.Key))
                        results.Add(f);
                }
            }

            // Stable ordering for output: score desc, severity desc, category, subject type, subject name/id
            return results
                .OrderByDescending(f => f.Score)
                .ThenByDescending(f => f.Severity)
                .ThenBy(f => f.Category)
                .ThenBy(f => f.SubjectType)
                .ThenBy(f => f.SubjectDisplayName ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                .ThenBy(f => f.SubjectId, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }
}
