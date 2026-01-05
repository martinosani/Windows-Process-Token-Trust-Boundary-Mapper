using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Domain.Processes;
using WTBM.Output.Abstractions;

namespace WTBM.Renders.OutputWriter
{
    /// <summary>
    /// Console implementation of <see cref="IOutputWriter"/> that prints a one-line-per-process
    /// triage-friendly view. The output is deterministic and resilient: per-item rendering issues
    /// do not stop the run.
    /// </summary>
    internal static class ProcessSnapshotConsoleSummaryWriter
    {
        private static int MaxColumnWidth = 48;

        private static bool IncludeFlags = true;

        private static bool IncludeNotes = true;

        private static SummaryVerbosity Verbosity = SummaryVerbosity.Normal;

        internal enum SummaryVerbosity
        {
            Minimal = 0,
            Normal = 1,
            Verbose = 2
        }

        public static void WriteSummary(IEnumerable<ProcessSnapshot> snapshots)
        {
            if (snapshots is null) throw new ArgumentNullException(nameof(snapshots));

            // Materialize once to avoid multiple enumeration and to allow stable sorting.
            var list = snapshots as IList<ProcessSnapshot> ?? snapshots.ToList();

            // Stable triage ordering: session, integrity (desc), name, pid.
            var ordered = list
                .OrderBy(s => s.Process.SessionId ?? int.MaxValue)
                .ThenByDescending(s => SeverityRankFromIntegrity(s.EffectiveIntegrityLevel))
                .ThenBy(s => s.Process.Name ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                .ThenBy(s => s.Process.Pid)
                .ToList();

            // Build a column layout based on verbosity/options.
            var layout = BuildLayout();

            WriteHeader(layout);

            foreach (var s in ordered)
            {
                try
                {
                    WriteRow(layout, s);
                }
                catch
                {
                    // Best-effort rendering: if a single row fails, print a degraded row.
                    // TODO: hook in real logging later.
                    WriteRowFallback(layout, s);
                }
            }

            Console.WriteLine();
            Console.WriteLine($"Total processes: {ordered.Count}");
        }

        // =========================
        // Layout
        // =========================

        private sealed record Col(string Header, int Width, Func<ProcessSnapshot, string> Value);

        private sealed class Layout
        {
            public required IReadOnlyList<Col> Columns { get; init; }
            public required string Separator { get; init; }
        }

        private static Layout BuildLayout()
        {
            // Fixed widths for stable scanning; only variable columns are truncated by MaxColumnWidth.
            // Keep the output predictable and diff-friendly.
            var max = MaxColumnWidth;

            int NameW = ClampWidth(24, max);
            int UserW = ClampWidth(28, max);
            int OwnerW = ClampWidth(28, max);
            int NotesW = ClampWidth(48, max);

            var cols = new List<Col>
        {
            new("PID",      6, s => s.Process.Pid.ToString()),
            new("PPID",     6, s => s.Process.Ppid.ToString()),
            new("Sess",     4, s => FormatNullableInt(s.Process.SessionId)),
            new("IL",       6, s => FormatIntegrity(s.EffectiveIntegrityLevel)),
            new("Name",  NameW, s => Safe(s.Process.Name)),
        };

            if (Verbosity >= SummaryVerbosity.Normal)
            {
                cols.Add(new Col("User", UserW, s => FormatIdentity(s.Token.UserName, s.Token.UserSid)));
            }

            if (Verbosity >= SummaryVerbosity.Verbose)
            {
                cols.Add(new Col("Owner", OwnerW, s => FormatIdentity(s.Token.OwnerName, s.Token.OwnerSid)));
                cols.Add(new Col("Type", 10, s => FormatTokenType(s.Token)));
                cols.Add(new Col("UAC", 10, s => FormatUac(s.Token)));
                cols.Add(new Col("AC", 3, s => Bool01(s.Token.IsAppContainer)));
                cols.Add(new Col("R", 2, s => Bool01(s.Token.IsRestricted)));
            }

            if (IncludeFlags)
            {
                cols.Add(new Col("Flags", 18, s => BuildFlags(s.Token)));
            }

            if (IncludeNotes)
            {
                cols.Add(new Col("Notes", NotesW, s => BuildNotes(s)));
            }

            return new Layout
            {
                Columns = cols,
                Separator = "  "
            };
        }

        private static void WriteHeader(Layout layout)
        {
            // Header
            var sb = new StringBuilder();
            for (int i = 0; i < layout.Columns.Count; i++)
            {
                var c = layout.Columns[i];
                if (i > 0) sb.Append(layout.Separator);
                sb.Append(PadRight(c.Header, c.Width));
            }
            Console.WriteLine(sb.ToString());

            // Underline
            sb.Clear();
            for (int i = 0; i < layout.Columns.Count; i++)
            {
                var c = layout.Columns[i];
                if (i > 0) sb.Append(layout.Separator);
                sb.Append(new string('-', Math.Min(c.Width, Math.Max(3, c.Header.Length))));
                sb.Append(new string(' ', Math.Max(0, c.Width - Math.Min(c.Width, Math.Max(3, c.Header.Length)))));
            }
            Console.WriteLine(sb.ToString());
        }

        private static void WriteRow(Layout layout, ProcessSnapshot s)
        {
            var sb = new StringBuilder();

            for (int i = 0; i < layout.Columns.Count; i++)
            {
                var c = layout.Columns[i];
                if (i > 0) sb.Append(layout.Separator);

                var raw = c.Value(s) ?? string.Empty;
                var val = Truncate(raw, c.Width);

                // Right-align numeric fields to improve scanning.
                if (IsNumericColumn(c.Header))
                    sb.Append(PadLeft(val, c.Width));
                else
                    sb.Append(PadRight(val, c.Width));
            }

            Console.WriteLine(sb.ToString());
        }

        private static void WriteRowFallback(Layout layout, ProcessSnapshot s)
        {
            // Minimal degraded row. Do not throw.
            var name = Safe(s.Process.Name);
            name = Truncate(name, layout.Columns.FirstOrDefault(c => c.Header == "Name")?.Width ?? 24);

            Console.WriteLine(
                $"{PadLeft(s.Process.Pid.ToString(), 6)}  {PadLeft(s.Process.Ppid.ToString(), 6)}  " +
                $"{PadRight(FormatNullableInt(s.Process.SessionId), 4)}  {PadRight(FormatIntegrity(s.EffectiveIntegrityLevel), 6)}  " +
                $"{PadRight(name, 24)}  <rendering error>");
        }

        // =========================
        // Formatting helpers
        // =========================

        private static string Safe(string? s) => string.IsNullOrWhiteSpace(s) ? "?" : s;

        private static string FormatNullableInt(int? v) => v.HasValue ? v.Value.ToString() : "?";

        private static string FormatIntegrity(IntegrityLevel il)
            => il == IntegrityLevel.Unknown ? "Unknown" : il.ToString();

        private static int SeverityRankFromIntegrity(IntegrityLevel il) => il switch
        {
            IntegrityLevel.System => 5,
            IntegrityLevel.High => 4,
            IntegrityLevel.Medium => 3,
            IntegrityLevel.Low => 2,
            IntegrityLevel.Untrusted => 1,
            _ => 0
        };

        private static string Bool01(bool? v) => v switch { true => "Y", false => "N", _ => "?" };

        private static string FormatIdentity(string? name, string? sid)
        {
            // For triage, show the name if available; fallback to SID; otherwise show placeholder.
            if (!string.IsNullOrWhiteSpace(name)) return name!;
            if (!string.IsNullOrWhiteSpace(sid)) return sid!;
            return "<not observable>";
        }

        private static string FormatTokenType(TokenInfo t)
        {
            if (t.TokenType == TokenType.Unknown) return "?";
            if (t.TokenType == TokenType.Impersonation)
                return t.ImpersonationLevel is null ? "Impersonation(?)" : $"Impersonation({t.ImpersonationLevel})";
            return t.TokenType.ToString();
        }

        private static string FormatUac(TokenInfo t)
        {
            // Compact, human-scannable UAC summary.
            // Examples:
            //   Limited
            //   Full
            //   Default
            //   ?  (unknown)
            var et = t.ElevationType == TokenElevationType.Unknown ? "?" : t.ElevationType.ToString();
            var elev = t.IsElevated switch { true => "E", false => "L", _ => "?" }; // Elevated vs Limited
            return $"{et}/{elev}";
        }

        private static string BuildFlags(TokenInfo t)
        {
            // Compact flags column. Keep stable ordering and avoid noise.
            // Flags are intended for scanning, not for full explanation.
            var flags = new List<string>(8);

            // Trust tier / sandboxing
            if (t.IntegrityLevel == IntegrityLevel.Low) flags.Add("LowIL");
            if (t.IsAppContainer == true) flags.Add("AC");
            if (t.IsRestricted == true) flags.Add("R");

            // UAC / boundary markers
            if (t.HasLinkedToken == true) flags.Add("Linked");
            if (t.HasUIAccess == true) flags.Add("UIA");

            // Identity anchors (high-signal derived flags)
            if (t.IsLocalSystem == true) flags.Add("SYSTEM");
            else if (t.IsLocalService == true) flags.Add("LS");
            else if (t.IsNetworkService == true) flags.Add("NS");

            // Privilege leverage hint (if present)
            if (t.Privileges is not null && t.Privileges.Count > 0)
            {
                // Do not list privileges here; just a hint that the token has more than trivial privileges.
                // A dedicated "findings" view should handle high-impact privilege enumeration.
                flags.Add("Privs");
            }

            var joined = flags.Count == 0 ? "-" : string.Join(",", flags);

            // Respect MaxColumnWidth: flags are already small, but clamp anyway.
            return Truncate(joined, MaxColumnWidth);
        }

        private static string BuildNotes(ProcessSnapshot s)
        {
            // Notes are intended to capture visibility boundaries and collection issues without flooding output.
            // Prefer process/token CollectionError when present. Avoid printing large warning lists in summary mode.
            var parts = new List<string>(3);

            if (!string.IsNullOrWhiteSpace(s.Process.CollectionError))
                parts.Add($"proc:{s.Process.CollectionError}");

            if (!string.IsNullOrWhiteSpace(s.Token.CollectionError))
                parts.Add($"tok:{s.Token.CollectionError}");

            if (Verbosity == SummaryVerbosity.Verbose && s.Token.CollectionWarnings is not null && s.Token.CollectionWarnings.Count > 0)
                parts.Add($"warn:{s.Token.CollectionWarnings.Count}");

            var joined = parts.Count == 0 ? "-" : string.Join(" ", parts);
            return Truncate(joined, MaxColumnWidth);
        }

        // =========================
        // String/width utilities
        // =========================

        private static int ClampWidth(int desired, int? max)
            => max.HasValue ? Math.Min(desired, max.Value) : desired;

        private static string Truncate(string s, int width)
        {
            if (width <= 0) return string.Empty;
            if (s.Length <= width) return s;

            // Reserve 1 char for ellipsis.
            if (width == 1) return "…";
            return s.Substring(0, width - 1) + "…";
        }

        private static string PadRight(string s, int width)
            => s.Length >= width ? s : s.PadRight(width);

        private static string PadLeft(string s, int width)
            => s.Length >= width ? s : s.PadLeft(width);

        private static bool IsNumericColumn(string header)
            => header.Equals("PID", StringComparison.OrdinalIgnoreCase)
            || header.Equals("PPID", StringComparison.OrdinalIgnoreCase)
            || header.Equals("Sess", StringComparison.OrdinalIgnoreCase);
    }
}
