using System;
using System.Collections.Generic;
using System.Text;
using static WTBM.NtNative.Win32Security;

namespace WTBM.Domain.IPC
{
    internal sealed class NamedPipeEndpoint
    {
        public NamedPipeRef Pipe { get; init; } = default!;

        // Security
        public SecurityDescriptorInfo Security {  get; init; }

        // Reachability
        public bool? ReachableFromMedium { get; init; }
        public bool? ReachableFromLow { get; init; }
        public bool? ReachableFromAppContainer { get; init; }
        public string ReachabilityConfidence { get; init; } = "Low";
        public string? ReachabilityNotes { get; init; }

        // Attribution
        public int? ServerPid { get; init; }
        public IReadOnlyList<int>? CandidateServerPids { get; init; }
        public string? ServerQueryError { get; init; }

        // Tags / derived flags
        public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
    }

    
}
