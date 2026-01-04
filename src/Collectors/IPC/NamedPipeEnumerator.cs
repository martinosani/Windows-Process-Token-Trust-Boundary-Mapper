using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using WTBM.Domain.IPC;

namespace WTBM.Collectors.IPC
{
    /// <summary>
    /// Enumerates named pipe endpoints currently exposed by the system and enriches them with
    /// security information (SDDL/DACL/Mandatory Label) using <see cref="NamedPipeSecurityCollector"/>.
    ///
    /// Design goals:
    /// - Single-call API for research workflows: Enumerate() returns NamedPipeEndpoint objects.
    /// - Best-effort: routine failures must not break the run (pipes are ephemeral).
    /// - Stable output: deterministic ordering and deduplication by pipe name.
    /// - Controlled parallelism for security collection.
    /// </summary>
    internal sealed class NamedPipeEnumerator
    {
        private const string PipeRootWin32 = @"\\.\pipe\";
        private const string PipeGlobWin32 = @"\\.\pipe\*";
        private const string PipeRootNt = @"\Device\NamedPipe\";

        private readonly NamedPipeSecurityCollector _securityCollector;
        private readonly int _maxDegreeOfParallelism;

        /// <summary>
        /// Creates an enumerator with default security collector and conservative concurrency.
        /// </summary>
        public NamedPipeEnumerator()
            : this(new NamedPipeSecurityCollector(), maxDegreeOfParallelism: 6)
        {
        }

        /// <summary>
        /// Creates an enumerator with a provided security collector and throttling configuration.
        /// </summary>
        public NamedPipeEnumerator(NamedPipeSecurityCollector securityCollector, int maxDegreeOfParallelism = 6)
        {
            _securityCollector = securityCollector ?? throw new ArgumentNullException(nameof(securityCollector));
            _maxDegreeOfParallelism = Math.Clamp(maxDegreeOfParallelism, 1, 64);
        }

        /// <summary>
        /// Enumerates named pipes and returns security-enriched endpoints.
        /// This method is best-effort and never throws for routine enumeration/collection errors.
        /// </summary>
        public IReadOnlyList<NamedPipeEndpoint> Enumerate()
        {
            try
            {
                return EnumerateCore();
            }
            catch
            {
                // Best-effort: never let the run fail due to unexpected exceptions.
                return Array.Empty<NamedPipeEndpoint>();
            }
        }

        private IReadOnlyList<NamedPipeEndpoint> EnumerateCore()
        {
            var pipes = EnumeratePipeRefsCore();
            if (pipes.Count == 0)
                return Array.Empty<NamedPipeEndpoint>();

            // Security enrichment can be slow; do it with bounded parallelism.
            var endpoints = EnrichWithSecurity(pipes);

            // Stable ordering: by pipe name (case-insensitive).
            return endpoints
                .OrderBy(e => e.Pipe.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        /// <summary>
        /// Enumerates pipe names from \\.\pipe\* and returns normalized references with Win32+NT paths.
        /// Best-effort and resilient to race conditions.
        /// </summary>
        private static IReadOnlyList<NamedPipeRef> EnumeratePipeRefsCore()
        {
            var results = new List<NamedPipeRef>(capacity: 256);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var findHandle = FindFirstFileW(PipeGlobWin32, out var data);
            if (findHandle == INVALID_HANDLE_VALUE)
            {
                // Typical failures are rare here, but we keep it best-effort.
                return Array.Empty<NamedPipeRef>();
            }

            try
            {
                while (true)
                {
                    var name = NormalizePipeName(data.cFileName);
                    if (!string.IsNullOrEmpty(name) && seen.Add(name))
                    {
                        results.Add(new NamedPipeRef(
                            Name: name,
                            Win32Path: PipeRootWin32 + name,
                            NtPath: PipeRootNt + name
                        ));
                    }

                    if (!FindNextFileW(findHandle, out data))
                    {
                        var err = Marshal.GetLastWin32Error();
                        if (err == ERROR_NO_MORE_FILES)
                            break;

                        // Any other error: stop enumeration (best-effort).
                        break;
                    }
                }
            }
            finally
            {
                FindClose(findHandle);
            }

            return results
                .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        /// <summary>
        /// Security enrichment stage. Each pipe becomes a NamedPipeEndpoint with Security list populated.
        /// Best-effort per item: failures are captured in NamedPipeSecurityInfo.Error.
        /// </summary>
        private IReadOnlyList<NamedPipeEndpoint> EnrichWithSecurity(IReadOnlyList<NamedPipeRef> pipes)
        {
            // Materialize endpoints into an array for stable indexing.
            var endpoints = new NamedPipeEndpoint[pipes.Count];

            // Semaphore-based throttling to avoid overloading the system.
            using var gate = new SemaphoreSlim(_maxDegreeOfParallelism, _maxDegreeOfParallelism);

            var tasks = new List<Task>(pipes.Count);

            for (var i = 0; i < pipes.Count; i++)
            {
                var index = i;
                var pipe = pipes[index];

                tasks.Add(Task.Run(async () =>
                {
                    await gate.WaitAsync().ConfigureAwait(false);
                    try
                    {
                        // Your NamedPipeSecurityCollector should be best-effort already.
                        // Here we also guard in case it throws unexpectedly.
                        NamedPipeSecurityInfo info;
                        try
                        {
                            // This assumes your collector exposes a method that can take both paths/name.
                            // If your current method signature differs, adapt ONLY this call site.
                            info = _securityCollector.TryCollect(pipe);
                        }
                        catch (Exception ex)
                        {
                            info = new NamedPipeSecurityInfo
                            {
                                Error = $"SecurityCollectorException:{ex.GetType().Name}"
                            };
                        }

                        endpoints[index] = new NamedPipeEndpoint
                        {
                            Pipe = pipe,
                            Security =  info, // currently one record per pipe
                            // Reachability/Attribution will be computed by later stages.
                        };
                    }
                    finally
                    {
                        gate.Release();
                    }
                }));
            }

            try
            {
                Task.WaitAll(tasks.ToArray());
            }
            catch
            {
                // Best-effort: even if some tasks faulted, we still return what we have.
            }

            // Fill any missing slots defensively (should be rare).
            for (var i = 0; i < endpoints.Length; i++)
            {
                if (endpoints[i] is null)
                {
                    endpoints[i] = new NamedPipeEndpoint
                    {
                        Pipe = pipes[i],
                        Security = new NamedPipeSecurityInfo { Error = "SecurityCollection:UnknownFailure" }
                    };
                }
            }

            return endpoints;
        }

        private static string NormalizePipeName(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return string.Empty;

            var name = raw.Trim().TrimStart('\\', '/');

            if (name is "." or "..")
                return string.Empty;

            // Pipes are leaf names under \\.\pipe\; avoid path separators breaking concatenation.
            if (name.IndexOfAny(new[] { '\\', '/' }) >= 0)
                name = name.Replace('\\', '_').Replace('/', '_');

            return name;
        }

        private const int ERROR_NO_MORE_FILES = 18;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        // =========================
        // P/Invoke
        // =========================

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr FindFirstFileW(
            string lpFileName,
            out WIN32_FIND_DATAW lpFindFileData);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool FindNextFileW(
            IntPtr hFindFile,
            out WIN32_FIND_DATAW lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FindClose(IntPtr hFindFile);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WIN32_FIND_DATAW
        {
            public uint dwFileAttributes;
            public FILETIME ftCreationTime;
            public FILETIME ftLastAccessTime;
            public FILETIME ftLastWriteTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint dwReserved0;
            public uint dwReserved1;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string cFileName;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            public string cAlternateFileName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }
    }

    internal sealed record NamedPipeRef(string Name, string Win32Path, string NtPath);
}
