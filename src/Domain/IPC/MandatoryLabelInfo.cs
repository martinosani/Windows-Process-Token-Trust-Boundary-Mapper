using System;
using System.Collections.Generic;
using System.Text;

namespace WTBM.Domain.IPC
{
    /// <summary>
    /// Represents the Mandatory Integrity Label (MIL) applied to an IPC object.
    /// This is derived from SYSTEM_MANDATORY_LABEL_ACE entries in the SACL.
    ///
    /// The model is intentionally minimal and passive:
    /// - No policy decisions are made here
    /// - Used for reachability and trust-boundary analysis
    /// </summary>
    internal sealed class MandatoryLabelInfo
    {
        /// <summary>
        /// SID of the mandatory label (e.g. S-1-16-4096 for Low, S-1-16-8192 for Medium).
        /// </summary>
        public string Sid { get; init; } = string.Empty;

        /// <summary>
        /// Best-effort resolved name (e.g. "Mandatory Label\\Low Mandatory Level").
        /// May be null if SID translation fails.
        /// </summary>
        public string? Principal { get; init; }

        /// <summary>
        /// Policy flags encoded in the ACE access mask.
        /// Typical values: NoWriteUp, NoReadUp, NoExecuteUp.
        /// Stored as a compact string for explainability.
        /// </summary>
        public string Policy { get; init; } = string.Empty;
    }
}
