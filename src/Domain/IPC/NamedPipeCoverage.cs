using System;
using System.Collections.Generic;
using System.Text;

namespace WTBM.Domain.IPC
{
    internal sealed class NamedPipeCoverage
    {
        public int PipesEnumerated { get; init; }

        public int SecurityOk { get; init; }
        public int SecurityFailed { get; init; }
        public int MandatoryLabelOk { get; init; }
        public int MandatoryLabelFailed { get; init; }

        public int ReachabilityComputed { get; init; }

        public int AttributionOk { get; init; }          // ServerPid resolved
        public int AttributionAmbiguous { get; init; }   // multiple candidates
        public int AttributionFailed { get; init; }

        public IReadOnlyDictionary<string, int> FailuresByReason { get; init; } = new Dictionary<string, int>();
    }

}
