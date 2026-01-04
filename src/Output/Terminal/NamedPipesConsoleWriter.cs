using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using WTBM.Collectors.IPC;
using WTBM.Domain.IPC;

namespace WTBM.Output.Terminal
{
    /// <summary>
    /// Console renderer for named pipe inventory + collected security descriptor data.
    /// This class is intentionally non-interpretive: it prints what it receives (plus
    /// safe derivations from SDDL such as Owner display name).
    /// </summary>
    internal static class NamedPipesConsoleWriter
    {
        public static void WriteSummary(
            IReadOnlyList<NamedPipeRef> pipes,
            IReadOnlyList<NamedPipeSecurityInfo> securityInfos,
            int max = 80)
        {
            if (pipes is null) throw new ArgumentNullException(nameof(pipes));
            if (securityInfos is null) throw new ArgumentNullException(nameof(securityInfos));
            if (max <= 0) max = 1;

            Console.WriteLine("=== Named Pipes (summary) ===");

            // If the caller provides aligned lists, we can safely zip by index.
            if (pipes.Count == securityInfos.Count)
            {
                Console.WriteLine("Name                           Path                           Owner                SD   MIL   DACL  SDDL  Error");
                Console.WriteLine("----------------------------  -----------------------------  -------------------  ---  ----  ----  ----  ------------------------------");

                var rows = pipes
                    .Select((p, i) => new { Pipe = p, Sec = securityInfos[i] })
                    .OrderBy(x => x.Pipe.Name, StringComparer.OrdinalIgnoreCase)
                    .Take(max);

                foreach (var row in rows)
                {
                    var pipe = row.Pipe;
                    var sec = row.Sec;

                    var sdOk = string.IsNullOrWhiteSpace(sec.Error);
                    var hasMil = sec.MandatoryLabel is not null;
                    var hasDacl = sec.Dacl is { Count: > 0 };
                    var hasSddl = !string.IsNullOrWhiteSpace(sec.Sddl);

                    var path = ResolvePipePath(pipe);
                    var owner = TryGetOwnerFromSddl(sec.Sddl) ?? "-";

                    Console.WriteLine(
                        $"{TrimTo(pipe.Name, 28),-28}  " +
                        $"{TrimTo(path, 29),-29}  " +
                        $"{TrimTo(owner, 19),-19}  " +
                        $"{FmtBool(sdOk),-3}  " +
                        $"{FmtBool(hasMil),-4}  " +
                        $"{FmtBool(hasDacl),-4}  " +
                        $"{FmtBool(hasSddl),-4}  " +
                        $"{TrimTo(sec.Error ?? string.Empty, 30)}");
                }

                Console.WriteLine();
                Console.WriteLine($"Shown: {Math.Min(max, pipes.Count)} / {pipes.Count}");
                return;
            }

            // Otherwise: do not invent correlations. Render separately.
            Console.WriteLine($"Note: pipes.Count ({pipes.Count}) != securityInfos.Count ({securityInfos.Count}). Rendering separately.");
            Console.WriteLine();

            WritePipeList(pipes, max);
            Console.WriteLine();
            WriteSecurityList(securityInfos, max);
        }

        public static void Explain(NamedPipeRef pipe, NamedPipeSecurityInfo sec)
        {
            if (pipe is null) throw new ArgumentNullException(nameof(pipe));
            if (sec is null) throw new ArgumentNullException(nameof(sec));

            var path = ResolvePipePath(pipe);
            var owner = TryGetOwnerFromSddl(sec.Sddl);

            Console.WriteLine("=== Named Pipe (detail) ===");
            Console.WriteLine($"Name : {pipe.Name}");
            Console.WriteLine($"Path : {path}");
            if (!string.IsNullOrWhiteSpace(owner))
                Console.WriteLine($"Owner: {owner}");
            Console.WriteLine();

            Console.WriteLine("Security descriptor:");
            Console.WriteLine($"  Status : {(string.IsNullOrWhiteSpace(sec.Error) ? "OK" : "FAILED")}");
            if (!string.IsNullOrWhiteSpace(sec.Error))
                Console.WriteLine($"  Error  : {sec.Error}");

            Console.WriteLine($"  Has SDDL : {FmtBool(!string.IsNullOrWhiteSpace(sec.Sddl))}");
            if (!string.IsNullOrWhiteSpace(sec.Sddl))
                Console.WriteLine($"  SDDL     : {sec.Sddl}");

            Console.WriteLine();

            Console.WriteLine("DACL (collected):");
            if (sec.Dacl is null || sec.Dacl.Count == 0)
            {
                Console.WriteLine("  <none>");
            }
            else
            {
                foreach (var ace in sec.Dacl)
                    Console.WriteLine($"  - {FormatAce(ace)}");
            }

            Console.WriteLine();

            Console.WriteLine("Mandatory Integrity Label (MIL):");
            if (sec.MandatoryLabel is null)
            {
                Console.WriteLine("  <none>");
            }
            else
            {
                Console.WriteLine($"  SID    : {sec.MandatoryLabel.Sid}");
                if (!string.IsNullOrWhiteSpace(sec.MandatoryLabel.Principal))
                    Console.WriteLine($"  Name   : {sec.MandatoryLabel.Principal}");
                if (!string.IsNullOrWhiteSpace(sec.MandatoryLabel.Policy))
                    Console.WriteLine($"  Policy : {sec.MandatoryLabel.Policy}");
            }

            Console.WriteLine();
        }

        private static void WritePipeList(IReadOnlyList<NamedPipeRef> pipes, int max)
        {
            Console.WriteLine("=== Pipes (enumerated) ===");
            Console.WriteLine("Name                           Path");
            Console.WriteLine("----------------------------  -----------------------------");

            foreach (var p in pipes.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).Take(max))
            {
                var path = ResolvePipePath(p);
                Console.WriteLine($"{TrimTo(p.Name, 28),-28}  {TrimTo(path, 29)}");
            }

            Console.WriteLine();
            Console.WriteLine($"Shown: {Math.Min(max, pipes.Count)} / {pipes.Count}");
        }

        private static void WriteSecurityList(IReadOnlyList<NamedPipeSecurityInfo> infos, int max)
        {
            Console.WriteLine("=== Security infos (collected) ===");
            Console.WriteLine("Idx  SD   MIL   DACL  SDDL  Owner                Error");
            Console.WriteLine("---  ---  ----  ----  ----  -------------------  ------------------------------");

            foreach (var row in infos.Take(max).Select((s, i) => new { Sec = s, Index = i }))
            {
                var sec = row.Sec;

                var sdOk = string.IsNullOrWhiteSpace(sec.Error);
                var hasMil = sec.MandatoryLabel is not null;
                var hasDacl = sec.Dacl is { Count: > 0 };
                var hasSddl = !string.IsNullOrWhiteSpace(sec.Sddl);
                var owner = TryGetOwnerFromSddl(sec.Sddl) ?? "-";

                Console.WriteLine(
                    $"{row.Index,3}  " +
                    $"{FmtBool(sdOk),-3}  " +
                    $"{FmtBool(hasMil),-4}  " +
                    $"{FmtBool(hasDacl),-4}  " +
                    $"{FmtBool(hasSddl),-4}  " +
                    $"{TrimTo(owner, 19),-19}  " +
                    $"{TrimTo(sec.Error ?? string.Empty, 30)}");
            }

            Console.WriteLine();
            Console.WriteLine($"Shown: {Math.Min(max, infos.Count)} / {infos.Count}");
        }

        private static string ResolvePipePath(NamedPipeRef pipe)
        {
            if (!string.IsNullOrWhiteSpace(pipe.NtPath))
                return pipe.NtPath;

            if (!string.IsNullOrWhiteSpace(pipe.Win32Path))
                return pipe.Win32Path;

            return "-";
        }

        private static string? TryGetOwnerFromSddl(string? sddl)
        {
            if (string.IsNullOrWhiteSpace(sddl))
                return null;

            try
            {
                var raw = new RawSecurityDescriptor(sddl);
                var ownerSid = raw.Owner;
                if (ownerSid is null)
                    return null;

                var sidValue = ownerSid.Value ?? string.Empty;
                var ownerName = TryTranslateSid(ownerSid);

                return string.IsNullOrWhiteSpace(ownerName)
                    ? sidValue
                    : ownerName;
            }
            catch
            {
                // Best-effort: malformed/partial SDDL should not break output.
                return null;
            }
        }

        private static string? TryTranslateSid(SecurityIdentifier sid)
        {
            try
            {
                return sid.Translate(typeof(NTAccount)).Value;
            }
            catch
            {
                return null;
            }
        }

        private static string FmtBool(bool value) => value ? "Yes" : "No";

        private static string TrimTo(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return "-";
            if (s.Length <= max) return s;
            return s.Substring(0, max - 1) + "...";
        }

        private static string FormatAce(AceInfo ace)
        {
            var principal = string.IsNullOrWhiteSpace(ace.Principal)
                ? ace.Sid
                : $"{ace.Principal} ({ace.Sid})";

            var rights = string.IsNullOrWhiteSpace(ace.Rights)
                ? "-"
                : ace.Rights;

            var condition = string.IsNullOrWhiteSpace(ace.Condition)
                ? string.Empty
                : $"  If({ace.Condition})";

            return $"{ace.AceType,-10}  {principal,-45}  Rights={rights}{condition}";
        }
    }
}
