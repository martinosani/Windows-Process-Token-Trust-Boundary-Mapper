using System;
using System.Collections.Generic;
using System.Linq;
using WTBM.Domain.Findings;
using WTBM.Domain.IPC;
using WTBM.Domain.Processes;

namespace WTBM.Output.Terminal
{

    internal static class FindingsConsoleWriter
    {
        public static void WriteSummary(IEnumerable<Finding> findings, IReadOnlyList<ProcessSnapshot> snapshots, int max = 50)
        {
            if (findings is null) throw new ArgumentNullException(nameof(findings));
            if (snapshots is null) throw new ArgumentNullException(nameof(snapshots));
            if (max <= 0) max = 50;

            var snapshotIndex = BuildSnapshotIndex(snapshots);
            var coverage = ComputeCoverageMetrics(snapshots);

            WriteCoverage(coverage);

            var findingList = findings.ToList();
            if (findingList.Count == 0)
            {
                Console.WriteLine("=== Findings (summary) ===");
                Console.WriteLine("No findings.");
                Console.WriteLine();
                return;
            }

            // 1) Grouped view (reduces noise, article-friendly)
            WriteGroupedSummary(findingList, snapshotIndex);

            // 2) Detailed table (top N)
            WriteDetailedSummary(findingList, snapshotIndex, max);

            Console.WriteLine();
            Console.WriteLine($"Total findings: {findingList.Count}");
            Console.WriteLine();
        }



        public static void Explain(Finding finding, IReadOnlyList<ProcessSnapshot> snapshots)
        {
            if (finding is null) throw new ArgumentNullException(nameof(finding));
            if (snapshots is null) throw new ArgumentNullException(nameof(snapshots));

            var snapshotIndex = BuildSnapshotIndex(snapshots);
            snapshotIndex.TryGetValue(GetPidFromFinding(finding), out var snap);

            Console.WriteLine($"=== Finding: {finding.RuleId} ===");
            Console.WriteLine($"Title        : {finding.Title}");
            Console.WriteLine($"Severity     : {finding.Severity}");
            Console.WriteLine($"Score        : {finding.Score}");
            Console.WriteLine($"Category     : {finding.Category}");
            Console.WriteLine($"Subject type : {finding.SubjectType}");
            Console.WriteLine($"Subject      : {FormatSubject(finding, snap)}");
            Console.WriteLine($"Key          : {finding.Key}");
            Console.WriteLine();

            if (snap is not null && finding.SubjectType == FindingSubjectType.Process)
            {
                WriteProcessContext(snap);
                Console.WriteLine();
            }

            Console.WriteLine("Evidence:");
            Console.WriteLine(IndentBlock(finding.Evidence, "  "));
            Console.WriteLine();

            Console.WriteLine("Recommendation:");
            Console.WriteLine(IndentBlock(finding.Recommendation, "  "));
            Console.WriteLine();

            if (finding.RelatedPids.Count > 0)
            {
                Console.WriteLine("Related PIDs:");
                Console.WriteLine($"  {string.Join(", ", finding.RelatedPids)}");
                Console.WriteLine();
            }

            if (finding.ConceptRefs.Count > 0)
            {
                Console.WriteLine("Concept references:");
                foreach (var c in finding.ConceptRefs)
                    Console.WriteLine($"  - {c}");
                Console.WriteLine();
            }

            if (finding.NextSteps.Count > 0)
            {
                Console.WriteLine("Next steps:");
                foreach (var step in finding.NextSteps)
                {
                    Console.WriteLine($"  - {step.Title}");
                    Console.WriteLine($"    {step.Description}");
                }
                Console.WriteLine();
            }

            if (finding.Tags.Count > 0)
            {
                Console.WriteLine("Tags:");
                Console.WriteLine($"  {string.Join(", ", finding.Tags)}");
                Console.WriteLine();
            }
        }

        // ----------------------------
        // Grouped summary
        // ----------------------------

        private static void WriteGroupedSummary(IReadOnlyList<Finding> findings, IReadOnlyDictionary<int, ProcessSnapshot> snapshotIndex)
        {
            Console.WriteLine("=== Findings (grouped) ===");
            Console.WriteLine("Count  Score~  Category        RuleId            Process                       User               IL     Sess  EvidenceKind");
            Console.WriteLine("-----  ------  --------------  ----------------  ---------------------------  -----------------  -----  ----  ----------------");

            var groups = findings
                .Select(f => CreateGroupProjection(f, snapshotIndex))
                .GroupBy(x => x.Key)
                .Select(g =>
                {
                    var items = g.ToList();
                    // "Score~" is the max score in group (useful)
                    var scoreApprox = items.Max(i => i.Score);
                    return new GroupRow(
                        Count: items.Count,
                        ScoreApprox: scoreApprox,
                        Category: items[0].Category,
                        RuleId: items[0].RuleId,
                        Process: items[0].ProcessName,
                        User: items[0].UserBucket ?? "###",
                        IL: items[0].IL,
                        Sess: items[0].Session,
                        EvidenceKind: items[0].EvidenceKind,
                        PidSamples: items.Select(i => i.Pid).Where(p => p > 0).Distinct().OrderBy(p => p).Take(6).ToList()
                    );
                })
                .OrderByDescending(r => r.ScoreApprox)
                .ThenByDescending(r => r.Count)
                .ThenBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase)
                .ThenBy(r => r.Process, StringComparer.OrdinalIgnoreCase)
                .Take(25) // keep grouped section concise
                .ToList();

            foreach (var r in groups)
            {
                var pidHint = r.PidSamples.Count > 0 ? $" [{string.Join(",", r.PidSamples)}]" : string.Empty;
                var username = string.IsNullOrEmpty(r.User) ? "###" : r.User;

                Console.WriteLine(
                    $"{r.Count,5}  " +
                    $"{r.ScoreApprox,6}  " +
                    $"{r.Category,-14}  " +
                    $"{r.RuleId,-16}  " +
                    $"{TrimTo(r.Process, 27),-27}  " +
                    $"{TrimTo(username, 17),-17}  " +
                    $"{r.IL,-5}  " +
                    $"{r.Sess,4}  " +
                    $"{TrimTo(r.EvidenceKind + pidHint, 16)}");
            }

            Console.WriteLine();
        }

        private sealed record GroupKey(
            string RuleId,
            FindingCategory Category,
            string ProcessName,
            string UserBucket,
            string IL,
            string Session,
            string EvidenceKind
        );

        private sealed record GroupProjection(
            GroupKey Key,
            string RuleId,
            FindingCategory Category,
            string ProcessName,
            string UserBucket,
            string IL,
            string Session,
            string EvidenceKind,
            int Score,
            int Pid
        );

        private sealed record GroupRow(
            int Count,
            int ScoreApprox,
            FindingCategory Category,
            string RuleId,
            string Process,
            string User,
            string IL,
            string Sess,
            string EvidenceKind,
            IReadOnlyList<int> PidSamples
        );

        private static GroupProjection CreateGroupProjection(Finding f, IReadOnlyDictionary<int, ProcessSnapshot> snapshotIndex)
        {
            var pid = GetPidFromFinding(f);
            snapshotIndex.TryGetValue(pid, out var snap);

            var processName = (snap?.Process.Name ?? f.SubjectDisplayName ?? f.SubjectId ?? "Subject").Trim();
            var user = snap is null ? "" : RenderUserBucket(snap.Token);
            var il = snap is null ? "" : RenderIntegrityLevel(snap.Token.IntegrityLevel);
            var session = snap is null ? "" : ((snap.Token.SessionId ?? snap.Process.SessionId)?.ToString() ?? "");

            var evidenceKind = ClassifyEvidenceKind(f);

            var key = new GroupKey(
                RuleId: f.RuleId,
                Category: f.Category,
                ProcessName: processName,
                UserBucket: user,
                IL: il,
                Session: session,
                EvidenceKind: evidenceKind
            );

            return new GroupProjection(
                Key: key,
                RuleId: f.RuleId,
                Category: f.Category,
                ProcessName: processName,
                UserBucket: user,
                IL: il,
                Session: session,
                EvidenceKind: evidenceKind,
                Score: f.Score,
                Pid: pid
            );
        }

        private static string ClassifyEvidenceKind(Finding f)
        {
            // Prefer tags (stable), fallback to evidence text
            if (f.Tags.Contains("priv-enabled", StringComparer.OrdinalIgnoreCase))
                return "Enabled";
            if (f.Tags.Contains("priv-present-disabled", StringComparer.OrdinalIgnoreCase))
                return "PresentDisabled";

            var first = FirstLine(f.Evidence);
            if (first.StartsWith("Enabled ", StringComparison.OrdinalIgnoreCase))
                return "Enabled";
            if (first.Contains("present but disabled", StringComparison.OrdinalIgnoreCase))
                return "PresentDisabled";

            return "Other";
        }

        // ----------------------------
        // Detailed summary
        // ----------------------------

        private static void WriteDetailedSummary(IReadOnlyList<Finding> findings, IReadOnlyDictionary<int, ProcessSnapshot> snapshotIndex, int max)
        {
            Console.WriteLine("=== Findings (detailed) ===");
            Console.WriteLine("Severity  Score  Category        RuleId            Subject                         User               IL     Sess  Evidence                      Path");
            Console.WriteLine("-------  -----  --------------  ----------------  ------------------------------  -----------------  -----  ----  ----------------------------  ------------------------------");

            foreach (var f in findings.Take(max))
            {
                var pid = GetPidFromFinding(f);
                snapshotIndex.TryGetValue(pid, out var snap);

                var subject = TrimTo(FormatSubject(f, snap), 30);

                var (user, il, sess, path) = GetAuthorityColumns(f, snap);
                user = TrimTo(user, 17);
                path = TrimTo(path ?? string.Empty, 30);

                var evidenceShort = TrimTo(FirstLine(f.Evidence), 28);

                Console.WriteLine(
                    $"{f.Severity,-7}  " +
                    $"{f.Score,5}  " +
                    $"{f.Category,-14}  " +
                    $"{f.RuleId,-16}  " +
                    $"{subject,-30}  " +
                    $"{user,-17}  " +
                    $"{il,-5}  " +
                    $"{sess,4}  " +
                    $"{evidenceShort,-28}  " +
                    $"{path,-30}");
            }

            Console.WriteLine();
        }

        // ----------------------------
        // Coverage metrics
        // ----------------------------

        private static void WriteCoverage(CoverageMetrics metrics)
        {
            Console.WriteLine("=== Coverage (token collection) ===");
            Console.WriteLine($"Processes enumerated : {metrics.ProcessesEnumerated}");
            Console.WriteLine($"Token collected OK   : {metrics.TokenCollectedOk}");
            Console.WriteLine($"Token failed         : {metrics.TokenFailed}");

            if (metrics.FailuresByReason.Count > 0)
            {
                Console.WriteLine("Failures by reason:");
                foreach (var kv in metrics.FailuresByReason.OrderByDescending(k => k.Value))
                    Console.WriteLine($"  - {kv.Key}: {kv.Value}");
            }

            Console.WriteLine();
        }

        private static CoverageMetrics ComputeCoverageMetrics(IReadOnlyList<ProcessSnapshot> snapshots)
        {
            var enumerated = snapshots.Count;
            var ok = 0;
            var failed = 0;

            var byReason = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            foreach (var s in snapshots)
            {
                var tokenError = s.Token.CollectionError;
                if (string.IsNullOrWhiteSpace(tokenError))
                {
                    ok++;
                    continue;
                }

                failed++;
                var reason = NormalizeReason(tokenError);

                byReason.TryGetValue(reason, out var cur);
                byReason[reason] = cur + 1;
            }

            return new CoverageMetrics(enumerated, ok, failed, byReason);
        }

        private static string NormalizeReason(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return "Unknown";

            raw = raw.Trim();

            if (raw.Contains("AccessDenied", StringComparison.OrdinalIgnoreCase))
                return "AccessDenied";

            if (raw.Contains("Protected", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("PPL", StringComparison.OrdinalIgnoreCase))
                return "PPL/Protected";

            if (raw.Contains("InvalidParameter", StringComparison.OrdinalIgnoreCase))
                return "InvalidParameter";

            if (raw.Contains("NotFound", StringComparison.OrdinalIgnoreCase))
                return "NotFound";

            return raw;
        }

        private sealed record CoverageMetrics(
            int ProcessesEnumerated,
            int TokenCollectedOk,
            int TokenFailed,
            IReadOnlyDictionary<string, int> FailuresByReason
        );

        // ----------------------------
        // Snapshot indexing / subject formatting
        // ----------------------------

        private static IReadOnlyDictionary<int, ProcessSnapshot> BuildSnapshotIndex(IReadOnlyList<ProcessSnapshot> snapshots)
        {
            var dict = new Dictionary<int, ProcessSnapshot>(capacity: snapshots.Count);
            foreach (var s in snapshots)
                dict[s.Process.Pid] = s;

            return dict;
        }

        private static int GetPidFromFinding(Finding f)
        {
            if (f.SubjectType != FindingSubjectType.Process)
                return -1;

            return int.TryParse(f.SubjectId, out var pid) ? pid : -1;
        }

        private static (string user, string il, string sess, string? path) GetAuthorityColumns(Finding f, ProcessSnapshot? snap)
        {
            if (f.SubjectType != FindingSubjectType.Process || snap is null)
                return (string.Empty, string.Empty, string.Empty, null);

            var token = snap.Token;
            var proc = snap.Process;

            var username = RenderUserBucket(token);
            var usernameDisplayValue = string.IsNullOrEmpty(username) ? "###" : username;

            var il = RenderIntegrityLevel(token.IntegrityLevel);

            var session = token.SessionId ?? proc.SessionId;
            var sess = session?.ToString() ?? "";

            return (usernameDisplayValue, il, sess, proc.ImagePath);
        }

        private static string RenderUserBucket(TokenInfo token)
        {
            if (token.IsLocalSystem == true) return "SYSTEM";
            if (token.IsLocalService == true) return "LOCAL SERVICE";
            if (token.IsNetworkService == true) return "NETWORK SERVICE";
            return token.UserName ?? "";
        }

        private static string RenderIntegrityLevel(IntegrityLevel il) => il switch
        {
            IntegrityLevel.Untrusted => "Untr",
            IntegrityLevel.Low => "Low",
            IntegrityLevel.Medium => "Med",
            IntegrityLevel.High => "High",
            IntegrityLevel.System => "Sys",
            IntegrityLevel.Protected => "PPL",
            _ => "Unk"
        };

        private static string FormatSubject(Finding f, ProcessSnapshot? snap)
        {
            return f.SubjectType switch
            {
                FindingSubjectType.Process => FormatProcessSubject(f, snap),
                _ => f.SubjectDisplayName ?? f.SubjectId
            };
        }

        private static string FormatProcessSubject(Finding f, ProcessSnapshot? snap)
        {
            var name = snap?.Process.Name ?? f.SubjectDisplayName ?? "Process";
            return $"{name} (PID {f.SubjectId})";
        }

        private static void WriteProcessContext(ProcessSnapshot snap)
        {
            var token = snap.Token;
            var proc = snap.Process;

            var userBucket = RenderUserBucket(token);
            var il = RenderIntegrityLevel(token.IntegrityLevel);
            var sess = (token.SessionId ?? proc.SessionId)?.ToString() ?? "Unknown";

            Console.WriteLine("Process context:");
            Console.WriteLine($"  Name      : {proc.Name}");
            Console.WriteLine($"  PID/PPID   : {proc.Pid} / {proc.Ppid}");
            Console.WriteLine($"  User       : {userBucket}");
            Console.WriteLine($"  UserSid    : {token.UserSid ?? "Unknown"}");
            Console.WriteLine($"  IL         : {token.IntegrityLevel} ({il})");
            Console.WriteLine($"  Session    : {sess}");
            Console.WriteLine($"  ImagePath  : {proc.ImagePath ?? "Unknown"}");

            if (!string.IsNullOrWhiteSpace(token.CollectionError))
                Console.WriteLine($"  TokenError : {token.CollectionError}");

            if (!string.IsNullOrWhiteSpace(proc.CollectionError))
                Console.WriteLine($"  ProcError  : {proc.CollectionError}");
        }

        // ----------------------------
        // Text helpers
        // ----------------------------

        private static string FirstLine(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return string.Empty;

            return text.Replace("\r\n", "\n").Split('\n')[0].Trim();
        }

        private static string TrimTo(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return s;
            if (s.Length <= max) return s;
            return s.Substring(0, max - 1) + "...";
        }

        private static string IndentBlock(string? text, string indent)
        {
            if (string.IsNullOrWhiteSpace(text))
                return string.Empty;

            var lines = text.Replace("\r\n", "\n").Split('\n');
            return string.Join(Environment.NewLine, lines.Select(l => indent + l));

        }
    }
}
