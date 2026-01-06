
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace WTBM.NtNative
{
    internal static class Win32Security
    {
        internal sealed record SecurityDescriptorInfo(
            string Sddl,
            string OwnerSid,
            string OwnerName,
            SddlSummary? SddlSummary,
            string? Error
        );

        internal sealed record SddlAceSummary(
            AceType Type,               // Allow / Deny / etc.
            string Sid,                 // S-1-...
            string? Name,               // DOMAIN\User (best-effort)
            uint AccessMask,            // raw access mask
            string AccessText,          // decoded (best-effort)
            AceFlags Flags
        );

        internal sealed record SddlSummary(
            bool HasDacl,
            bool HasSacl,
            int? MandatoryIntegrityRid,
            uint? MandatoryPolicyMask,
            IReadOnlyList<SddlAceSummary> DaclAces,
            IReadOnlyList<string> Tags
        );


        public static bool HasAny(uint granted, uint mask) => (granted & mask) != 0;

        public static SecurityDescriptorInfo GetSecurityDescriptorByHandle(IntPtr handle)
        {
            // Defensive defaults: never throw from this best-effort collector.
            // The caller can decide how to handle partial/failed visibility.
            const string Unknown = "<unknown>";

            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                return new SecurityDescriptorInfo(
                    Sddl: string.Empty,
                    OwnerSid: string.Empty,
                    OwnerName: Unknown,
                    SddlSummary: null,
                    Error: "InvalidHandle"
                );
            }

            // We try to read OWNER/GROUP/DACL and (if possible) SACL.
            // SACL typically requires SeSecurityPrivilege; if we cannot read it, we fall back to DACL-only.
            const SecurityInformation siWithSacl =
                SecurityInformation.OWNER_SECURITY_INFORMATION |
                SecurityInformation.GROUP_SECURITY_INFORMATION |
                SecurityInformation.DACL_SECURITY_INFORMATION |
                SecurityInformation.SACL_SECURITY_INFORMATION;

            const SecurityInformation siNoSacl =
                SecurityInformation.OWNER_SECURITY_INFORMATION |
                SecurityInformation.GROUP_SECURITY_INFORMATION |
                SecurityInformation.DACL_SECURITY_INFORMATION;

            IntPtr pOwnerSid = IntPtr.Zero;
            IntPtr pSecurityDescriptor = IntPtr.Zero;

            SecurityInformation usedSi = siWithSacl;
            uint err = 0;

            // ---- Step 1: Query security descriptor (prefer including SACL) ----
            err = GetSecurityInfo(
                handle,
                SE_OBJECT_TYPE.SE_FILE_OBJECT,
                usedSi,
                out pOwnerSid,
                out IntPtr _,
                out IntPtr _,
                out IntPtr _,
                out pSecurityDescriptor);

            if (err != 0)
            {
                // Common cases: AccessDenied or PrivilegeNotHeld when requesting SACL.
                // Fall back to DACL-only to maximize usefulness.
                usedSi = siNoSacl;
                pOwnerSid = IntPtr.Zero;
                pSecurityDescriptor = IntPtr.Zero;

                err = GetSecurityInfo(
                    handle,
                    SE_OBJECT_TYPE.SE_FILE_OBJECT,
                    usedSi,
                    out pOwnerSid,
                    out IntPtr _,
                    out IntPtr _,
                    out IntPtr _,
                    out pSecurityDescriptor);

                if (err != 0)
                {
                    // Hard failure even for DACL-only. Return a structured error instead of throwing.
                    return new SecurityDescriptorInfo(
                        Sddl: string.Empty,
                        OwnerSid: string.Empty,
                        OwnerName: Unknown,
                        SddlSummary: null,
                        Error: $"GetSecurityInfo:{err}"
                    );
                }
            }

            try
            {
                // ---- Step 2: Convert SD to SDDL string ----
                if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        pSecurityDescriptor,
                        SDDL_REVISION_1,
                        usedSi,
                        out IntPtr pSddl,
                        out uint _))
                {
                    int le = Marshal.GetLastWin32Error();
                    return new SecurityDescriptorInfo(
                        Sddl: string.Empty,
                        OwnerSid: string.Empty,
                        OwnerName: Unknown,
                        SddlSummary: null,
                        Error: $"ConvertSDToSDDL:{le}"
                    );
                }

                string sddl = string.Empty;
                try
                {
                    // ConvertSecurityDescriptorToStringSecurityDescriptorW returns a null-terminated LPWSTR.
                    sddl = Marshal.PtrToStringUni(pSddl) ?? string.Empty;
                }
                finally
                {
                    // pSddl must be freed with LocalFree (per Win32 contract).
                    LocalFree(pSddl);
                }

                // ---- Step 3: Determine owner (prefer SDDL owner; fall back to pOwnerSid) ----
                string ownerSid = string.Empty;
                string ownerName = Unknown;

                try
                {
                    if (!string.IsNullOrWhiteSpace(sddl))
                    {
                        // Use RawSecurityDescriptor for correctness and future-proof parsing.
                        var rsd = new RawSecurityDescriptor(sddl);

                        ownerSid = rsd.Owner?.Value ?? string.Empty;
                        ownerName = TryTranslateSidToName(rsd.Owner) ?? ownerName;

                        // If SDDL lacks an owner, fall back to pointer returned by GetSecurityInfo.
                        if (string.IsNullOrWhiteSpace(ownerSid) && pOwnerSid != IntPtr.Zero)
                        {
                            try
                            {
                                var sid = new SecurityIdentifier(pOwnerSid);
                                ownerSid = sid.Value;
                                ownerName = TryTranslateSidToName(sid) ?? ownerName;
                            }
                            catch
                            {
                                // Keep best-effort behavior.
                            }
                        }

                        // ---- Step 4: Parse DACL and SACL into SddlSummary ----
                        var daclSummaries = new List<SddlAceSummary>(capacity: 16);

                        if (rsd.DiscretionaryAcl != null)
                        {
                            foreach (GenericAce ace in rsd.DiscretionaryAcl)
                            {
                                // Only parse ACEs we can safely interpret into (Type, SID, AccessMask).
                                if (ace is not CommonAce ca)
                                    continue;

                                if (ca is not KnownAce ka)
                                    continue;

                                string sid = ka.SecurityIdentifier.Value;
                                string? name = TryTranslateSidToName(ka.SecurityIdentifier);

                                // Normalize GENERIC_* to file rights for consistent downstream heuristics.
                                uint rawMask = unchecked((uint)ka.AccessMask);
                                uint normMask = NormalizeFileAccessMask(rawMask);

                                // Compact human-friendly representation for evidence output.
                                string accessText = DescribeFileAccess(normMask);

                                daclSummaries.Add(new SddlAceSummary(
                                    Type: ca.AceType,
                                    Sid: sid,
                                    Name: name,
                                    AccessMask: normMask,
                                    AccessText: accessText,
                                    Flags: ca.AceFlags
                                ));
                            }
                        }

                        bool hasDacl = rsd.DiscretionaryAcl != null;
                        bool hasSacl = rsd.SystemAcl != null;

                        // Mandatory label info is in SACL (if we managed to retrieve it).
                        (int? ilRid, uint? ilPolicy) = GetMandatoryLabelInfo(rsd);

                        // ---- Step 5: Derive compact tags for triage/metrics ----
                        var tags = new List<string>(capacity: 12);

                        if (!hasSacl)
                        {
                            // We likely fell back to DACL-only or the object has no SACL.
                            // This helps downstream logic distinguish "unknown" from "safe".
                            tags.Add("sd:partial-no-sacl");
                        }

                        // Helper local to avoid repeated LINQ allocations.
                        static bool HasAce(List<SddlAceSummary> aces, AceType type, string sid) =>
                            aces.Exists(a => a.Type == type && string.Equals(a.Sid, sid, StringComparison.OrdinalIgnoreCase));

                        const string SID_EVERYONE = "S-1-1-0";
                        const string SID_AUTH_USERS = "S-1-5-11";
                        const string SID_BUILTIN_USERS = "S-1-5-32-545";
                        const string SID_ALL_APP_PACKAGES = "S-1-15-2-1";

                        if (hasDacl)
                        {
                            if (HasAce(daclSummaries, AceType.AccessAllowed, SID_EVERYONE)) tags.Add("dacl:everyone-allow");
                            if (HasAce(daclSummaries, AceType.AccessAllowed, SID_AUTH_USERS)) tags.Add("dacl:auth-users-allow");
                            if (HasAce(daclSummaries, AceType.AccessAllowed, SID_BUILTIN_USERS)) tags.Add("dacl:users-allow");
                            if (HasAce(daclSummaries, AceType.AccessAllowed, SID_ALL_APP_PACKAGES)) tags.Add("dacl:all-app-packages-allow");

                            if (HasAce(daclSummaries, AceType.AccessDenied, SID_EVERYONE)) tags.Add("dacl:everyone-deny");
                            if (HasAce(daclSummaries, AceType.AccessDenied, SID_AUTH_USERS)) tags.Add("dacl:auth-users-deny");
                            if (HasAce(daclSummaries, AceType.AccessDenied, SID_BUILTIN_USERS)) tags.Add("dacl:users-deny");
                        }

                        if (ilRid.HasValue)
                        {
                            // Keep it as a stable tag for grouping/aggregation.
                            tags.Add($"sacl:integrity-rid=0x{ilRid.Value:X}");
                        }

                        if (ilPolicy.HasValue)
                        {
                            // Common policy bits: 0x1 NO_WRITE_UP, 0x2 NO_READ_UP, 0x4 NO_EXECUTE_UP
                            if ((ilPolicy.Value & 0x1) != 0) tags.Add("sacl:no-write-up");
                            if ((ilPolicy.Value & 0x2) != 0) tags.Add("sacl:no-read-up");
                            if ((ilPolicy.Value & 0x4) != 0) tags.Add("sacl:no-exec-up");
                        }

                        var summary = new SddlSummary(
                            HasDacl: hasDacl,
                            HasSacl: hasSacl,
                            MandatoryIntegrityRid: ilRid,
                            MandatoryPolicyMask: ilPolicy,
                            DaclAces: daclSummaries,
                            Tags: tags
                        );

                        return new SecurityDescriptorInfo(
                            Sddl: sddl,
                            OwnerSid: ownerSid,
                            OwnerName: ownerName,
                            SddlSummary: summary,
                            Error: string.Empty
                        );
                    }
                }
                catch (Exception ex)
                {
                    // Parsing failed but we still have a valid SDDL string.
                    // Return partial result + error so callers can decide how to surface it.
                    return new SecurityDescriptorInfo(
                        Sddl: sddl,
                        OwnerSid: ownerSid,
                        OwnerName: ownerName,
                        SddlSummary: null,
                        Error: $"ParseSddl:{ex.GetType().Name}"
                    );
                }

                // If we reach here, SDDL was empty/unavailable.
                return new SecurityDescriptorInfo(
                    Sddl: sddl,
                    OwnerSid: string.Empty,
                    OwnerName: Unknown,
                    SddlSummary: null,
                    Error: "EmptySddl"
                );
            }
            finally
            {
                // Per GetSecurityInfo contract, security descriptor memory is freed with LocalFree.
                if (pSecurityDescriptor != IntPtr.Zero)
                    LocalFree(pSecurityDescriptor);
            }
        }

        /*
        /// <summary>
        /// Reads the security descriptor for a named pipe path like \\.\pipe\X and returns:
        /// - SDDL for the security descriptor (Owner/Group/DACL by default)
        /// - Owner SID string (S-1-...)
        /// - Owner account name (DOMAIN\User), best-effort
        /// </summary>
        public static SecurityDescriptorInfo GetSecurityDescriptor(string win32Path)
        {
            if (string.IsNullOrWhiteSpace(win32Path))
                throw new ArgumentException("Path must be non-empty.", nameof(win32Path));

            // We intentionally request OWNER + GROUP + DACL. SACL requires SeSecurityPrivilege.
            const SecurityInformation si =
                SecurityInformation.OWNER_SECURITY_INFORMATION |
                SecurityInformation.GROUP_SECURITY_INFORMATION |
                SecurityInformation.DACL_SECURITY_INFORMATION;

            IntPtr pOwnerSid = IntPtr.Zero;
            IntPtr pGroupSid = IntPtr.Zero;
            IntPtr pDacl = IntPtr.Zero;
            IntPtr pSacl = IntPtr.Zero;
            IntPtr pSecurityDescriptor = IntPtr.Zero;

            try
            {
                uint err = GetNamedSecurityInfoW(
                    win32Path,
                    SE_OBJECT_TYPE.SE_FILE_OBJECT, // named pipes are file objects
                    si,
                    out pOwnerSid,
                    out pGroupSid,
                    out pDacl,
                    out pSacl,
                    out pSecurityDescriptor);

                if (err != 0)
                    throw new Win32Exception((int)err, $"GetNamedSecurityInfo failed for '{win32Path}'.");

                // Convert returned SD (self-relative) to SDDL string.
                if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        pSecurityDescriptor,
                        SDDL_REVISION_1,
                        si,
                        out IntPtr pSddl,
                        out uint _))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ConvertSecurityDescriptorToStringSecurityDescriptor failed.");
                }

                string sddl;
                try
                {
                    sddl = Marshal.PtrToStringUni(pSddl) ?? string.Empty;
                }
                finally
                {
                    LocalFree(pSddl);
                }

                // Owner SID string
                string ownerSid = pOwnerSid != IntPtr.Zero
                    ? new SecurityIdentifier(pOwnerSid).Value
                    : string.Empty;

                // Owner name best-effort
                string ownerName = ResolveAccountNameBestEffort(pOwnerSid);

                return new SecurityDescriptorInfo(
                    Sddl: sddl,
                    OwnerSid: ownerSid,
                    OwnerName: ownerName
                );
            }
            finally
            {
                // Free SD returned by GetNamedSecurityInfo (LocalAlloc).
                if (pSecurityDescriptor != IntPtr.Zero)
                    LocalFree(pSecurityDescriptor);
            }
        }*/

        private static (int? integrityRid, uint? policy) GetMandatoryLabelInfo(RawSecurityDescriptor rsd)
        {
            if (rsd.SystemAcl == null) return (null, null);

            foreach (GenericAce ace in rsd.SystemAcl)
            {
                if (ace is not KnownAce ka) continue;

                string sid = ka.SecurityIdentifier.Value;
                if (!sid.StartsWith("S-1-16-", StringComparison.Ordinal)) continue;

                if (int.TryParse(sid.AsSpan("S-1-16-".Length), out int rid))
                {
                    uint mask = unchecked((uint)ka.AccessMask);
                    return (rid, mask);
                }
            }

            return (null, null);
        }

        private static bool DaclHasAllowFor(IReadOnlyList<SddlAceSummary> aces, string sid) =>
        aces.Any(a => a.Type == AceType.AccessAllowed && string.Equals(a.Sid, sid, StringComparison.OrdinalIgnoreCase));

        private static bool DaclHasDenyFor(IReadOnlyList<SddlAceSummary> aces, string sid) =>
            aces.Any(a => a.Type == AceType.AccessDenied && string.Equals(a.Sid, sid, StringComparison.OrdinalIgnoreCase));


        private static uint NormalizeFileAccessMask(uint mask)
        {
            var mapping = new GENERIC_MAPPING
            {
                GenericRead = READ_CONTROL | SYNCHRONIZE | 0x0001 /*READ_DATA*/ | 0x0080 /*READ_ATTR*/ | 0x0008 /*READ_EA*/,
                GenericWrite = READ_CONTROL | SYNCHRONIZE | 0x0002 /*WRITE_DATA*/ | 0x0004 /*APPEND*/ | 0x0100 /*WRITE_ATTR*/ | 0x0010 /*WRITE_EA*/,
                GenericExecute = READ_CONTROL | SYNCHRONIZE | 0x0020 /*EXECUTE*/,
                GenericAll = 0x1F01FF
            };

            uint m = mask;
            MapGenericMask(ref m, ref mapping);
            return m;
        }

        private static string DescribeFileAccess(uint mask)
        {
            // Keep this intentionally compact: it’s for “insights”, not full ACL tooling.
            var parts = new List<string>();

            if ((mask & 0x0001) != 0) parts.Add("R");
            if ((mask & 0x0002) != 0) parts.Add("W");
            if ((mask & 0x0004) != 0) parts.Add("A"); // append
            if ((mask & 0x0020) != 0) parts.Add("X");
            if ((mask & READ_CONTROL) != 0) parts.Add("RC");
            if ((mask & SYNCHRONIZE) != 0) parts.Add("SYN");

            return parts.Count == 0 ? "None" : string.Join("|", parts);
        }

        private static string? TryTranslateSidToName(SecurityIdentifier? sid)
        {
            if (sid == null) return null;
            try { return sid.Translate(typeof(NTAccount)).Value; }
            catch { return null; }
        }

        private static string ResolveAccountNameBestEffort(IntPtr pSid)
        {
            if (pSid == IntPtr.Zero)
                return "<unknown>";

            try
            {
                var sid = new SecurityIdentifier(pSid);
                try
                {
                    // This will use LSA/LookupAccountSid behind the scenes.
                    var ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));
                    return ntAccount.Value; // DOMAIN\User
                }
                catch
                {
                    // Not resolvable -> return SID string
                    return sid.Value;
                }
            }
            catch
            {
                return "<unresolved>";
            }
        }

        // --- P/Invoke ------------------------------------------------------------

        // Common file access bits (WinNT / WinBase)
        public const uint READ_CONTROL = 0x00020000;
        public const uint SYNCHRONIZE = 0x00100000;

        public const uint FILE_READ_DATA = 0x0001;
        public const uint FILE_READ_ATTRIBUTES = 0x0080;
        public const uint FILE_READ_EA = 0x0008;

        private const uint SDDL_REVISION_1 = 1;

        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint GENERIC_EXECUTE = 0x20000000;
        private const uint GENERIC_ALL = 0x10000000;

        [Flags]
        private enum SecurityInformation : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION = 0x00000004,
            SACL_SECURITY_INFORMATION = 0x00000008,
            LABEL_SECURITY_INFORMATION = 0x00000010
        }

        private enum SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE = 0,
            SE_FILE_OBJECT = 1
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct GENERIC_MAPPING
        {
            public uint GenericRead;
            public uint GenericWrite;
            public uint GenericExecute;
            public uint GenericAll;
        }

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = false)]
        private static extern void MapGenericMask(ref uint AccessMask, ref GENERIC_MAPPING GenericMapping);


        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetSecurityInfo(
            IntPtr handle,
            SE_OBJECT_TYPE ObjectType,
            SecurityInformation SecurityInfo,
            out IntPtr ppsidOwner,
            out IntPtr ppsidGroup,
            out IntPtr ppDacl,
            out IntPtr ppSacl,
            out IntPtr ppSecurityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetNamedSecurityInfoW(
            string pObjectName,
            SE_OBJECT_TYPE ObjectType,
            SecurityInformation SecurityInfo,
            out IntPtr ppsidOwner,
            out IntPtr ppsidGroup,
            out IntPtr ppDacl,
            out IntPtr ppSacl,
            out IntPtr ppSecurityDescriptor
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
            IntPtr SecurityDescriptor,
            uint RequestedStringSDRevision,
            SecurityInformation SecurityInformation,
            out IntPtr StringSecurityDescriptor,
            out uint StringSecurityDescriptorLen
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);
    }
}
