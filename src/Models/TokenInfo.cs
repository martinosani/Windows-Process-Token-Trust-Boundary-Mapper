using System;
using System.Collections.Generic;
using System.Text;

namespace PTTBM.Models
{
    public enum IntegrityLevel
    {
        Unknown = 0,
        Untrusted,
        Low,
        Medium,
        High,
        System,
        Protected // optional bucket for completeness; may be inferred in some contexts
    }

    public enum TokenElevationType
    {
        Unknown = 0,
        Default = 1,
        Full = 2,
        Limited = 3
    }

    public enum TokenType
    {
        Unknown = 0,
        Primary,
        Impersonation
    }

    public enum TokenImpersonationLevel
    {
        Unknown = 0,
        Anonymous = 1,
        Identification = 2,
        Impersonation = 3,
        Delegation = 4
    }

    [Flags]
    public enum TokenGroupAttributes : uint
    {
        None = 0,
        Mandatory = 0x00000001,
        EnabledByDefault = 0x00000002,
        Enabled = 0x00000004,
        Owner = 0x00000008,
        UseForDenyOnly = 0x00000010,
        Integrity = 0x00000020,
        IntegrityEnabled = 0x00000040,
        LogonId = 0xC0000000,
        Resource = 0x20000000
    }

    [Flags]
    public enum TokenPrivilegeAttributes : uint
    {
        None = 0,
        EnabledByDefault = 0x00000001,
        Enabled = 0x00000002,
        Removed = 0x00000004,
        UsedForAccess = 0x80000000
    }

    /// <summary>
    /// A security-oriented representation of a token group entry.
    /// </summary>
    public sealed class TokenGroupInfo
    {
        public string Sid { get; init; } = string.Empty;          // e.g., S-1-5-32-544
        public string? Name { get; init; }                        // e.g., BUILTIN\Administrators (best-effort)
        public TokenGroupAttributes Attributes { get; init; }
    }

    /// <summary>
    /// A security-oriented representation of a token privilege entry.
    /// </summary>
    public sealed class TokenPrivilegeInfo
    {
        public long Luid { get; init; }                           // LUID as Int64 (High<<32 | Low)
        public string? Name { get; init; }                        // e.g., SeImpersonatePrivilege (best-effort)
        public TokenPrivilegeAttributes Attributes { get; init; }

        public bool IsEnabled => (Attributes & TokenPrivilegeAttributes.Enabled) != 0;
        public bool IsEnabledByDefault => (Attributes & TokenPrivilegeAttributes.EnabledByDefault) != 0;
        public bool IsRemoved => (Attributes & TokenPrivilegeAttributes.Removed) != 0;
    }

    /// <summary>
    /// Security-relevant token metadata for trust-boundary analysis.
    /// This model is designed for explainability and rule evaluation, not exploitation.
    /// Fields are best-effort; some may be null/Unknown depending on visibility and access constraints.
    /// </summary>
    public sealed class TokenInfo
    {
        // =========================
        // Identity / Ownership
        // =========================

        public int Pid { get; init; }

        public string? UserSid { get; init; }
        public string? UserName { get; init; }                    // DOMAIN\User (best-effort)

        public string? OwnerSid { get; init; }                    // TokenOwner (can differ from TokenUser)
        public string? OwnerName { get; init; }                   // best-effort

        public string? PrimaryGroupSid { get; init; }             // TokenPrimaryGroup
        public string? PrimaryGroupName { get; init; }            // best-effort

        // =========================
        // Core Boundaries / Context
        // =========================

        public IntegrityLevel IntegrityLevel { get; init; } = IntegrityLevel.Unknown;
        public uint? IntegrityRid { get; init; }                  // raw RID used to derive IL (useful for research)

        public int? SessionId { get; init; }                      // TokenSessionId

        public TokenType TokenType { get; init; } = TokenType.Unknown;
        public TokenImpersonationLevel? ImpersonationLevel { get; init; } // only meaningful for impersonation tokens

        // =========================
        // UAC / Elevation semantics
        // =========================

        public bool? IsElevated { get; init; }                    // TokenElevation
        public TokenElevationType ElevationType { get; init; } = TokenElevationType.Unknown; // TokenElevationType

        public bool? IsVirtualizationAllowed { get; init; }       // TokenVirtualizationAllowed
        public bool? IsVirtualizationEnabled { get; init; }       // TokenVirtualizationEnabled

        public bool? HasUIAccess { get; init; }                   // TokenUIAccess

        // =========================
        // AppContainer / Sandboxing
        // =========================

        public bool? IsAppContainer { get; init; }                // TokenIsAppContainer
        public string? AppContainerSid { get; init; }             // TokenAppContainerSid (string SID)
        public string? AppContainerName { get; init; }            // best-effort (often not resolvable to a name)

        public IReadOnlyList<string>? CapabilitiesSids { get; init; } // TokenCapabilities (SID list, best-effort)

        // =========================
        // Groups and Privileges
        // =========================

        public IReadOnlyList<TokenGroupInfo>? Groups { get; init; }
        public IReadOnlyList<TokenPrivilegeInfo>? Privileges { get; init; }

        // Convenience: high-signal derived flags (set by collector/rule layer)
        public bool? IsMemberOfAdministrators { get; init; }
        public bool? IsLocalSystem { get; init; }
        public bool? IsLocalService { get; init; }
        public bool? IsNetworkService { get; init; }

        // =========================
        // Restrictions / Delegation / Impersonation controls
        // =========================

        public bool? IsRestricted { get; init; }                  // TokenIsRestricted (derived via restricted SIDs presence)
        public IReadOnlyList<string>? RestrictedSids { get; init; } // TokenRestrictedSids (SIDs, best-effort)

        public bool? HasLinkedToken { get; init; }                // TokenLinkedToken (true if retrievable)
        public int? LinkedTokenPidHint { get; init; }             // optional: for future correlation (not always available)

        // =========================
        // Provenance / Audit-friendly fields
        // =========================

        public string? AuthenticationId { get; init; }            // TokenStatistics.AuthenticationId (LUID string)
        public string? TokenId { get; init; }                     // TokenStatistics.TokenId (LUID string)
        public string? LogonTypeHint { get; init; }               // optional hint if you later correlate to LSA sessions

        // =========================
        // Diagnostics
        // =========================

        public string? CollectionError { get; init; }             // AccessDenied / NotFound / etc.
        public IReadOnlyList<string>? CollectionWarnings { get; init; } // e.g., "Privileges not retrievable"

        // Extension bag for future research fields without breaking schema
        public IDictionary<string, object?>? Extensions { get; init; }
    }
}
