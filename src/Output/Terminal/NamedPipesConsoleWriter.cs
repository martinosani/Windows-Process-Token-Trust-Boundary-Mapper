using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using WTBM.Domain.IPC;

namespace WTBM.Output.Terminal
{
    internal static class NamedPipesConsoleWriter
    {
        // Keep widths centralized to guarantee alignment between header, separator and rows.
        private const int W_NAME = 30;
        private const int W_PATH = 29;
        private const int W_OWNER = 29;

        private const int W_SD = 3;
        private const int W_SUM = 3;
        private const int W_DACL = 4;
        private const int W_SACL = 4;
        private const int W_MIL = 6;
        private const int W_TAGS = 20;
        private const int W_ERROR = 30;

        private const string SEP = "  ";

        /// <summary>
        /// Writes a concise, research-grade summary of named pipes and their security metadata.
        /// This method is intentionally read-only and performs no analysis or correlation.
        /// </summary>
        public static void WriteSummary(IReadOnlyList<NamedPipeEndpoint> endpoints)
        {
            if (endpoints is null)
                throw new ArgumentNullException(nameof(endpoints));

            Console.WriteLine();
            Console.WriteLine("=== Named Pipes (summary) ===");
            Console.WriteLine();

            WriteHeader();

            foreach (var ep in endpoints
                .OrderBy(e => e.Pipe?.Name ?? string.Empty, StringComparer.OrdinalIgnoreCase))
            {
                var pipe = ep.Pipe;
                var sec = ep.Security;

                // Pipe identity (best-effort).
                string name = String.Format("[PID:{0}]", ep.ServerPid);
                if (pipe != null)
                {
                    name = String.Format("{0}:{1}", name, pipe.Name);
                }
                else
                {
                    name = String.Format("{0}:\"<unknown>\"", name);
                }

                string path =
                    !string.IsNullOrWhiteSpace(pipe?.Win32Path) ? pipe!.Win32Path :
                    !string.IsNullOrWhiteSpace(pipe?.NtPath) ? pipe!.NtPath :
                    "<unknown>";

                // Security status (best-effort).
                bool hasSd = sec is not null && string.IsNullOrWhiteSpace(sec.Error);
                bool hasSummary = sec?.SddlSummary is not null;
                bool hasDacl = sec?.SddlSummary?.HasDacl == true;
                bool hasSacl = sec?.SddlSummary?.HasSacl == true;

                // MIL is optional and typically absent if you did not retrieve SACL.
                string mil = sec?.SddlSummary?.MandatoryIntegrityRid is int rid
                    ? $"0x{rid:X}"
                    : "-";

                string owner =
                    !string.IsNullOrWhiteSpace(sec?.OwnerName) ? sec!.OwnerName :
                    !string.IsNullOrWhiteSpace(sec?.OwnerSid) ? sec!.OwnerSid :
                    "<unknown>";

                // Tags: prefer summary tags; fall back to endpoint tags.
                IReadOnlyList<string>? tagsList =
                    sec?.SddlSummary?.Tags?.Count > 0 ? sec.SddlSummary.Tags :
                    ep.Tags?.Count > 0 ? ep.Tags :
                    null;

                string tags = (tagsList is null || tagsList.Count == 0)
                    ? "-"
                    : string.Join("|", tagsList.Take(4)); // small cap to keep table readable

                // Error: SD error first, then server query error (if any).
                string error =
                    !string.IsNullOrWhiteSpace(sec?.Error) ? sec!.Error :
                    !string.IsNullOrWhiteSpace(ep.ServerQueryError) ? ep.ServerQueryError :
                    string.Empty;

                // Render row with strict fixed-width columns.
                var row = new StringBuilder(capacity: 256);

                row.Append(Fix(name, W_NAME)).Append(SEP)
                   .Append(Fix(path, W_PATH)).Append(SEP)
                   .Append(Fix(owner, W_OWNER)).Append(SEP)
                   .Append(Fix(Flag(hasSd), W_SD)).Append(SEP)
                   .Append(Fix(Flag(hasSummary), W_SUM)).Append(SEP)
                   .Append(Fix(Flag(hasDacl), W_DACL)).Append(SEP)
                   .Append(Fix(Flag(hasSacl), W_SACL)).Append(SEP)
                   .Append(Fix(mil, W_MIL)).Append(SEP)
                   .Append(Fix(tags, W_TAGS)).Append(SEP)
                   .Append(Fix(error, W_ERROR));

                Console.WriteLine(row.ToString());
            }

            Console.WriteLine();
            Console.WriteLine($"Total pipes: {endpoints.Count}");
        }

        private static void WriteHeader()
        {
            // Header
            var header = new StringBuilder();
            header.Append(Fix("Name", W_NAME)).Append(SEP)
                  .Append(Fix("Path", W_PATH)).Append(SEP)
                  .Append(Fix("Owner", W_OWNER)).Append(SEP)
                  .Append(Fix("SD", W_SD)).Append(SEP)
                  .Append(Fix("SUM", W_SUM)).Append(SEP)
                  .Append(Fix("DACL", W_DACL)).Append(SEP)
                  .Append(Fix("SACL", W_SACL)).Append(SEP)
                  .Append(Fix("MIL", W_MIL)).Append(SEP)
                  .Append(Fix("Tags", W_TAGS)).Append(SEP)
                  .Append(Fix("Error", W_ERROR));

            Console.WriteLine(header.ToString());

            // Separator (same widths, using ASCII '-' for consistent terminal rendering)
            var sep = new StringBuilder();
            sep.Append(new string('-', W_NAME)).Append(SEP)
               .Append(new string('-', W_PATH)).Append(SEP)
               .Append(new string('-', W_OWNER)).Append(SEP)
               .Append(new string('-', W_SD)).Append(SEP)
               .Append(new string('-', W_SUM)).Append(SEP)
               .Append(new string('-', W_DACL)).Append(SEP)
               .Append(new string('-', W_SACL)).Append(SEP)
               .Append(new string('-', W_MIL)).Append(SEP)
               .Append(new string('-', W_TAGS)).Append(SEP)
               .Append(new string('-', W_ERROR));

            Console.WriteLine(sep.ToString());
        }

        private static string Flag(bool value) => value ? "Y" : "-";

        /// <summary>
        /// Fits a string into an exact column width (truncate or pad-right).
        /// Uses ASCII "..." to avoid console rendering width inconsistencies.
        /// </summary>
        private static string Fix(string? s, int width)
        {
            s ??= string.Empty;

            if (width <= 0)
                return string.Empty;

            if (s.Length == width)
                return s;

            if (s.Length < width)
                return s.PadRight(width);

            // Truncate + ASCII ellipsis for stable monospace rendering.
            if (width <= 3)
                return s.Substring(0, width);

            return s.Substring(0, width - 3) + "...";
        }
    }
}
