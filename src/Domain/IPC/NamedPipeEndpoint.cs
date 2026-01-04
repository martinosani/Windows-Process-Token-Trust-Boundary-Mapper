using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Collectors.IPC;

namespace WTBM.Domain.IPC
{
    internal sealed class NamedPipeEndpoint
    {
        public NamedPipeRef Pipe { get; init; } = default!;

        // Security
        public NamedPipeSecurityInfo Security {  get; init; }

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

    internal sealed class AceInfo
    {
        public string Sid { get; init; } = string.Empty;
        public string? Principal { get; init; }           // best-effort name
        public string Rights { get; init; } = string.Empty; // es: "RW" or specific pipe rights
        public string AceType { get; init; } = string.Empty; // ALLOW/DENY
        public string? Condition { get; init; }           // per conditional ACE (rare, ma esiste)
    }
}
