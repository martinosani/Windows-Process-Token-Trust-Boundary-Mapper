using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using WTBM.Domain.IPC;

namespace WTBM.Collectors.IPC
{
    internal sealed class NamedPipeSecurityCollector
    {
        public IReadOnlyList<NamedPipeSecurityInfo> TryCollect(IReadOnlyList<NamedPipeRef> namedPipes)
        {
            return namedPipes.Select(n => TryCollect(n)).ToList();
        }

        /// <summary>
        /// Collects Security Descriptor information for a named pipe object using GetNamedSecurityInfo:
        /// - Tries NT namespace path first (\Device\NamedPipe\name)
        /// - Falls back to Win32 path (\\.\pipe\name)
        /// - Attempts DACL + Mandatory Integrity Label (LABEL/SACL) first; falls back to DACL-only on AccessDenied.
        /// This avoids CreateFile() to prevent blocking or handshake side effects with pipe servers.
        /// </summary>
        public NamedPipeSecurityInfo TryCollect(NamedPipeRef pipe)
        {
            if (pipe is null) throw new ArgumentNullException(nameof(pipe));
            if (string.IsNullOrWhiteSpace(pipe.Name))
                return new NamedPipeSecurityInfo { Error = "InvalidPipeName" };

            // Primary + fallback paths (best-effort)
            var candidates = new[]
            {
                pipe.NtPath,    // \Device\NamedPipe\<name>
                pipe.Win32Path  // \\.\pipe\<name>
            }
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

            if (candidates.Length == 0)
                return new NamedPipeSecurityInfo { Error = "NoCandidatePaths" };

            // Strategy:
            // 1) Try DACL + LABEL (SACL) for Mandatory Integrity Label (MIL)
            // 2) If AccessDenied, retry DACL-only (still valuable for reachability)
            // 3) If name resolution fails, try next candidate path
            var lastError = "UnknownError";

            foreach (var path in candidates)
            {
                // 1) DACL + LABEL
                var r1 = TryQuerySecurity(path, includeMandatoryLabel: true);
                if (r1.Success)
                    return r1.Info!;

                lastError = r1.Error ?? lastError;

                // If we could not read LABEL/SACL due to AccessDenied, retry DACL-only for the same path.
                if (r1.ErrorCode == ERROR_ACCESS_DENIED)
                {
                    var r2 = TryQuerySecurity(path, includeMandatoryLabel: false);
                    if (r2.Success)
                        return r2.Info!;

                    lastError = r2.Error ?? lastError;
                }

                // If the name isn't valid/resolvable, continue with the next candidate.
                if (r1.ErrorCode == ERROR_INVALID_NAME ||
                    r1.ErrorCode == ERROR_FILE_NOT_FOUND ||
                    r1.ErrorCode == ERROR_PATH_NOT_FOUND)
                {
                    continue;
                }
            }

            return new NamedPipeSecurityInfo
            {
                Error = lastError
            };
        }

        private static QueryResult TryQuerySecurity(string objectName, bool includeMandatoryLabel)
        {
            var flags = SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;

            // LABEL_SECURITY_INFORMATION requests integrity label ACEs (SYSTEM_MANDATORY_LABEL_ACE) in SACL.
            // This may require higher privileges on some objects; we handle AccessDenied by falling back.
            if (includeMandatoryLabel)
                flags |= SECURITY_INFORMATION.LABEL_SECURITY_INFORMATION;

            IntPtr pSecurityDescriptor = IntPtr.Zero;

            try
            {
                var err = GetNamedSecurityInfoW(
                    objectName,
                    SE_OBJECT_TYPE.SE_FILE_OBJECT,
                    flags,
                    out _,
                    out _,
                    out _,
                    out _,
                    out pSecurityDescriptor);

                if (err != 0)
                {
                    return QueryResult.Fail(
                        errorCode: err,
                        error: $"{Win32ErrorName(err)}:{Stage(flags)}");
                }

                // Convert SD -> SDDL for explainability and easier parsing.
                if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        pSecurityDescriptor,
                        SDDL_REVISION_1,
                        flags,
                        out var pSddl,
                        out _))
                {
                    var werr = Marshal.GetLastWin32Error();
                    return QueryResult.Fail(werr, $"{Win32ErrorName(werr)}:ConvertToSddl:{Stage(flags)}");
                }

                try
                {
                    var sddl = Marshal.PtrToStringUni(pSddl) ?? string.Empty;

                    // Parse DACL and (best-effort) MIL from SDDL using RawSecurityDescriptor.
                    var raw = new RawSecurityDescriptor(sddl);

                    var dacl = raw.DiscretionaryAcl is null
                        ? null
                        : ParseDacl(raw.DiscretionaryAcl);

                    MandatoryLabelInfo? mil = null;
                    if (includeMandatoryLabel && raw.SystemAcl is not null)
                    {
                        mil = TryParseMandatoryLabel(raw.SystemAcl);
                    }

                    var info = new NamedPipeSecurityInfo
                    {
                        Sddl = sddl,
                        Dacl = dacl,
                        MandatoryLabel = mil,
                        Error = null
                    };

                    return QueryResult.Ok(info);
                }
                finally
                {
                    LocalFree(pSddl);
                }
            }
            catch (Exception ex)
            {
                // Collector must be best-effort: no exceptions should break the run.
                return QueryResult.Fail(
                    errorCode: -1,
                    error: $"Exception:{ex.GetType().Name}");
            }
            finally
            {
                if (pSecurityDescriptor != IntPtr.Zero)
                    LocalFree(pSecurityDescriptor);
            }

            static string Stage(SECURITY_INFORMATION flagsUsed)
                => flagsUsed.HasFlag(SECURITY_INFORMATION.LABEL_SECURITY_INFORMATION) ? "Dacl+Label" : "DaclOnly";
        }

        private static IReadOnlyList<AceInfo> ParseDacl(RawAcl dacl)
        {
            var list = new List<AceInfo>(dacl.Count);

            for (int i = 0; i < dacl.Count; i++)
            {
                var ace = dacl[i];

                if (ace is not CommonAce ca)
                    continue;

                var sid = ca.SecurityIdentifier?.Value ?? string.Empty;
                var principal = TryTranslateSid(ca.SecurityIdentifier);

                // For named pipes the object type is "File" in the NT object manager.
                // The access mask is still meaningful for reachability (read/write/execute/etc.).
                var rights = FormatAccessMask(ca.AccessMask);

                list.Add(new AceInfo
                {
                    Sid = sid,
                    Principal = principal,
                    Rights = rights,
                    AceType = ca.AceQualifier.ToString(), // Allow/Deny/SystemAudit etc.
                    Condition = null
                });
            }

            return list;
        }

        /// <summary>
        /// Attempts to parse the Mandatory Integrity Label from the SACL.
        /// This is best-effort. If not present or not supported, returns null.
        /// </summary>
        private static MandatoryLabelInfo? TryParseMandatoryLabel(RawAcl sacl)
        {
            for (int i = 0; i < sacl.Count; i++)
            {
                var ace = sacl[i];
                if (ace is not CommonAce ca)
                    continue;

                if (ca.AceType != ACE_TYPE_SYSTEM_MANDATORY_LABEL)
                    continue;

                var sid = ca.SecurityIdentifier?.Value;
                if (string.IsNullOrWhiteSpace(sid))
                    return null;

                var policy = FormatMandatoryLabelPolicy(ca.AccessMask);

                return new MandatoryLabelInfo
                {
                    Sid = sid,
                    Principal = TryTranslateSid(ca.SecurityIdentifier),
                    Policy = policy
                };
            }

            return null;
        }

        private static string FormatAccessMask(int accessMask)
        {
            // Keep a stable representation + a small human-friendly summary.
            // Do NOT attempt perfect decoding; this is for triage and research explainability.
            var hex = $"0x{accessMask:X8}";
            var rwx = SummarizeRwx(accessMask);

            return rwx.Length == 0 ? hex : $"{hex} ({rwx})";
        }

        private static string SummarizeRwx(int accessMask)
        {
            // Generic bits
            const int GENERIC_READ = unchecked((int)0x80000000);
            const int GENERIC_WRITE = 0x40000000;
            const int GENERIC_EXECUTE = 0x20000000;
            const int GENERIC_ALL = 0x10000000;

            // File-specific low bits often map to read/write semantics for named pipe objects.
            const int FILE_READ_DATA = 0x0001;
            const int FILE_WRITE_DATA = 0x0002;
            const int FILE_APPEND_DATA = 0x0004;

            var parts = new List<string>();

            if ((accessMask & GENERIC_ALL) != 0)
                parts.Add("ALL");

            if ((accessMask & (GENERIC_READ | FILE_READ_DATA)) != 0)
                parts.Add("R");

            if ((accessMask & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0)
                parts.Add("W");

            if ((accessMask & GENERIC_EXECUTE) != 0)
                parts.Add("X");

            return string.Join("", parts);
        }

        private static string FormatMandatoryLabelPolicy(int accessMask)
        {
            const int NO_WRITE_UP = 0x1;
            const int NO_READ_UP = 0x2;
            const int NO_EXECUTE_UP = 0x4;

            var parts = new List<string>();

            if ((accessMask & NO_WRITE_UP) != 0) parts.Add("NoWriteUp");
            if ((accessMask & NO_READ_UP) != 0) parts.Add("NoReadUp");
            if ((accessMask & NO_EXECUTE_UP) != 0) parts.Add("NoExecuteUp");

            return parts.Count == 0 ? $"0x{accessMask:X8}" : string.Join("|", parts);
        }

        private static string? TryTranslateSid(SecurityIdentifier? sid)
        {
            if (sid is null) return null;

            try
            {
                return sid.Translate(typeof(NTAccount)).Value;
            }
            catch
            {
                return null;
            }
        }

        private static string Win32ErrorName(int code)
        {
            // Translate a Win32/NTSTATUS-like error to a stable identifier.
            // GetNamedSecurityInfo returns Win32 error codes (DWORD).
            try
            {
                return new Win32Exception(code).NativeErrorCode switch
                {
                    ERROR_ACCESS_DENIED => "AccessDenied",
                    ERROR_INVALID_NAME => "InvalidName",
                    ERROR_FILE_NOT_FOUND => "NotFound",
                    ERROR_PATH_NOT_FOUND => "PathNotFound",
                    _ => $"Win32Error{code}"
                };
            }
            catch
            {
                return $"Win32Error{code}";
            }
        }

        private const int ERROR_ACCESS_DENIED = 5;
        private const int ERROR_INVALID_NAME = 123;
        private const int ERROR_FILE_NOT_FOUND = 2;
        private const int ERROR_PATH_NOT_FOUND = 3;

        private const uint SDDL_REVISION_1 = 1;

        // =========================
        // P/Invoke
        // =========================

        private const AceType ACE_TYPE_SYSTEM_MANDATORY_LABEL = (AceType)0x11;

        [Flags]
        private enum SECURITY_INFORMATION : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION = 0x00000004,
            SACL_SECURITY_INFORMATION = 0x00000008,

            // Integrity label ACEs live in the SACL; LABEL_SECURITY_INFORMATION requests them.
            LABEL_SECURITY_INFORMATION = 0x00000010,

            ATTRIBUTE_SECURITY_INFORMATION = 0x00000020,
            SCOPE_SECURITY_INFORMATION = 0x00000040
        }

        private enum SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE = 0,
            SE_FILE_OBJECT = 1,
            // (others omitted)
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetNamedSecurityInfoW(
            string pObjectName,
            SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            out IntPtr ppsidOwner,
            out IntPtr ppsidGroup,
            out IntPtr ppDacl,
            out IntPtr ppSacl,
            out IntPtr ppSecurityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
            IntPtr SecurityDescriptor,
            uint RequestedStringSDRevision,
            SECURITY_INFORMATION SecurityInformation,
            out IntPtr StringSecurityDescriptor,
            out uint StringSecurityDescriptorLen);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        private readonly struct QueryResult
        {
            public bool Success { get; }
            public NamedPipeSecurityInfo? Info { get; }
            public string? Error { get; }
            public int ErrorCode { get; }

            private QueryResult(bool success, NamedPipeSecurityInfo? info, string? error, int errorCode)
            {
                Success = success;
                Info = info;
                Error = error;
                ErrorCode = errorCode;
            }

            public static QueryResult Ok(NamedPipeSecurityInfo info) => new(true, info, null, 0);
            public static QueryResult Fail(int errorCode, string error) => new(false, null, error, errorCode);
        }
    }

    
}
