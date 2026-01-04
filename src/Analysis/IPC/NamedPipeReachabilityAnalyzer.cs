using System;
using System.Collections.Generic;
using System.Text;

namespace WTBM.Analysis.IPC
{
    internal sealed class NamedPipeReachabilityResult
    {
        public bool? ReachableFromMedium { get; init; }
        public bool? ReachableFromLow { get; init; }          // requires mandatory label or low-confidence
        public bool? ReachableFromAppContainer { get; init; }
        public string Confidence { get; init; } = "Low";      // Low/Medium/High
        public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
        public string? Notes { get; init; }                  // explainability (one-liners)
    }
}
