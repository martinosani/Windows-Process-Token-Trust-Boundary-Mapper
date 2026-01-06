using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Text;
using WTBM.Domain.Processes;

namespace WTBM.Collectors
{
    /// <summary>
    /// Collects a security-oriented TokenInfo snapshot for a given process PID.
    /// This is an analysis/visibility component (trust boundary mapper), not an exploitation component.
    ///
    /// Design principles:
    /// - Best-effort: AccessDenied, races, and partial visibility are expected.
    /// - Explainable: Populate stable, security-relevant fields used for rule evaluation.
    /// - Safe: Uses SafeHandle patterns and avoids leaking native resources.
    /// </summary>
    internal sealed class TokenCollector
    {
        public ProcessSnapshot TryCollect(ProcessRecord process)
        {
            var warnings = new List<string>();

            try
            {
                using var processHandle = OpenProcess(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, false, process.Pid);
                if (processHandle is null || processHandle.IsInvalid)
                    return new ProcessSnapshot { Process = process, Token = new TokenInfo { Pid = process.Pid, CollectionError = BuildLastWin32Error("OpenProcess") } };

                if (!OpenProcessToken(processHandle, TOKEN_ACCESS_RIGHTS.TOKEN_QUERY, out SafeTokenHandle tokenHandle))
                    return new ProcessSnapshot { Process = process, Token = new TokenInfo { Pid = process.Pid, CollectionError = BuildLastWin32Error("OpenProcessToken") } };

                using (tokenHandle)
                {
                    // Identity
                    var (userSid, userName) = TryGetTokenUser(tokenHandle, warnings);
                    var (ownerSid, ownerName) = TryGetTokenOwner(tokenHandle, warnings);
                    var (pgSid, pgName) = TryGetTokenPrimaryGroup(tokenHandle, warnings);

                    // Core boundaries/context
                    var (il, ilRid) = TryGetIntegrityLevel(tokenHandle, warnings);
                    var sessionId = TryGetTokenSessionId(tokenHandle, warnings);
                    var tokenType = TryGetTokenType(tokenHandle, warnings);
                    var impLevel = TryGetImpersonationLevel(tokenHandle, tokenType, warnings);

                    // UAC / elevation
                    var isElevated = TryGetIsElevated(tokenHandle, warnings);
                    var elevationType = TryGetElevationType(tokenHandle, warnings);

                    var virtAllowed = TryGetTokenBool(tokenHandle, TOKEN_INFORMATION_CLASS.TokenVirtualizationAllowed, warnings);
                    var virtEnabled = TryGetTokenBool(tokenHandle, TOKEN_INFORMATION_CLASS.TokenVirtualizationEnabled, warnings);
                    var uiAccess = TryGetTokenBool(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUIAccess, warnings);

                    // AppContainer / sandboxing
                    var isAppContainer = TryGetTokenBool(tokenHandle, TOKEN_INFORMATION_CLASS.TokenIsAppContainer, warnings);
                    var (appContainerSid, appContainerName) = TryGetAppContainerSid(tokenHandle, warnings);
                    var capabilities = TryGetCapabilitiesSids(tokenHandle, warnings);

                    // Groups / privileges
                    var groups = TryGetGroups(tokenHandle, warnings);
                    var privileges = TryGetPrivileges(tokenHandle, warnings);

                    // High-signal derived flags
                    var adminMember = groups is null ? (bool?)null : IsMemberOfWellKnownSid(groups, WELL_KNOWN_SIDS.Administrators);
                    var isSystem = userSid is null ? (bool?)null : string.Equals(userSid, WELL_KNOWN_SIDS.LocalSystem, StringComparison.OrdinalIgnoreCase);
                    var isLocalService = userSid is null ? (bool?)null : string.Equals(userSid, WELL_KNOWN_SIDS.LocalService, StringComparison.OrdinalIgnoreCase);
                    var isNetworkService = userSid is null ? (bool?)null : string.Equals(userSid, WELL_KNOWN_SIDS.NetworkService, StringComparison.OrdinalIgnoreCase);

                    // Restrictions / delegation controls
                    var restrictedSids = TryGetRestrictedSids(tokenHandle, warnings);
                    bool? isRestricted = restrictedSids is null ? (bool?)null : restrictedSids.Count > 0;

                    // Linked token (UAC split token)
                    var hasLinked = TryProbeLinkedToken(tokenHandle, warnings);

                    // Provenance / stats
                    var (authId, tokenId) = TryGetTokenStatistics(tokenHandle, warnings);

                    return new ProcessSnapshot { Process = process, Token = new TokenInfo {

                        Pid = process.Pid,

                        UserSid = userSid,
                        UserName = userName,

                        OwnerSid = ownerSid,
                        OwnerName = ownerName,

                        PrimaryGroupSid = pgSid,
                        PrimaryGroupName = pgName,

                        IntegrityLevel = il,
                        IntegrityRid = ilRid,

                        SessionId = sessionId,
                        TokenType = tokenType,
                        ImpersonationLevel = impLevel,

                        IsElevated = isElevated,
                        ElevationType = elevationType,

                        IsVirtualizationAllowed = virtAllowed,
                        IsVirtualizationEnabled = virtEnabled,
                        HasUIAccess = uiAccess,

                        IsAppContainer = isAppContainer,
                        AppContainerSid = appContainerSid,
                        AppContainerName = appContainerName,
                        CapabilitiesSids = capabilities,

                        Groups = groups,
                        Privileges = privileges,

                        IsMemberOfAdministrators = adminMember,
                        IsLocalSystem = isSystem,
                        IsLocalService = isLocalService,
                        IsNetworkService = isNetworkService,

                        IsRestricted = isRestricted,
                        RestrictedSids = restrictedSids,

                        HasLinkedToken = hasLinked,

                        AuthenticationId = authId,
                        TokenId = tokenId,

                        CollectionError = null,
                        CollectionWarnings = warnings.Count > 0 ? warnings : null
                    } };
                }
            }
            catch (Exception ex)
            {
                // Defensive: do not allow a single PID to break enumeration.
                return new ProcessSnapshot { Process = process, Token = new TokenInfo 
                    { Pid = process.Pid, CollectionError = $"Exception:{ex.GetType().Name}" } };
            }
        }

        // =========================
        // Identity collectors
        // =========================

        private static (string? Sid, string? Name) TryGetTokenUser(SafeTokenHandle token, List<string> warnings)
            => TryGetSidAndNameFromToken(token, TOKEN_INFORMATION_CLASS.TokenUser, warnings, parseAsSidAndAttributes: true);

        private static (string? Sid, string? Name) TryGetTokenOwner(SafeTokenHandle token, List<string> warnings)
            => TryGetSidAndNameFromToken(token, TOKEN_INFORMATION_CLASS.TokenOwner, warnings, parseAsSidAndAttributes: false);

        private static (string? Sid, string? Name) TryGetTokenPrimaryGroup(SafeTokenHandle token, List<string> warnings)
            => TryGetSidAndNameFromToken(token, TOKEN_INFORMATION_CLASS.TokenPrimaryGroup, warnings, parseAsSidAndAttributes: false);

        private static (string? Sid, string? Name) TryGetSidAndNameFromToken(
            SafeTokenHandle token,
            TOKEN_INFORMATION_CLASS clazz,
            List<string> warnings,
            bool parseAsSidAndAttributes)
        {
            try
            {
                var buf = GetTokenInformationBytes(token, clazz);
                if (buf is null) return (null, null);

                IntPtr sidPtr;
                if (parseAsSidAndAttributes)
                {
                    // TOKEN_USER / TOKEN_OWNER-like: SID_AND_ATTRIBUTES
                    sidPtr = ReadIntPtr(buf, 0);
                }
                else
                {
                    // TOKEN_OWNER / TOKEN_PRIMARY_GROUP: struct { PSID Sid; }
                    sidPtr = ReadIntPtr(buf, 0);
                }

                if (sidPtr == IntPtr.Zero) return (null, null);

                var sid = TryConvertSidToString(sidPtr);
                var name = TryLookupAccountName(sidPtr);

                return (sid, name);
            }
            catch
            {
                warnings.Add($"{clazz}:Failed");
                return (null, null);
            }
        }

        // =========================
        // Integrity level
        // =========================

        private static (IntegrityLevel Level, uint? Rid) TryGetIntegrityLevel(SafeTokenHandle token, List<string> warnings)
        {
            try
            {
                var buf = GetTokenInformationBytes(token, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel);
                if (buf is null) return (IntegrityLevel.Unknown, null);

                // TOKEN_MANDATORY_LABEL begins with SID_AND_ATTRIBUTES (PSID at offset 0)
                IntPtr sidPtr = ReadIntPtr(buf, 0);
                if (sidPtr == IntPtr.Zero) return (IntegrityLevel.Unknown, null);

                int subAuthCount = GetSidSubAuthorityCountManaged(sidPtr);
                if (subAuthCount <= 0) return (IntegrityLevel.Unknown, null);

                uint rid = GetSidSubAuthorityRidManaged(sidPtr, subAuthCount - 1);
                return (MapIntegrityRidToLevel(rid), rid);
            }
            catch
            {
                warnings.Add("TokenIntegrityLevel:Failed");
                return (IntegrityLevel.Unknown, null);
            }
        }

        private static IntegrityLevel MapIntegrityRidToLevel(uint rid) =>
            rid switch
            {
                0x0000 => IntegrityLevel.Untrusted,
                0x1000 => IntegrityLevel.Low,
                0x2000 => IntegrityLevel.Medium,
                0x3000 => IntegrityLevel.High,
                0x4000 => IntegrityLevel.System,
                _ => IntegrityLevel.Unknown
            };

        // =========================
        // Token type & impersonation
        // =========================

        private static TokenType TryGetTokenType(SafeTokenHandle token, List<string> warnings)
        {
            try
            {
                var buf = GetTokenInformationBytes(token, TOKEN_INFORMATION_CLASS.TokenType);
                if (buf is null) return TokenType.Unknown;

                int type = BitConverter.ToInt32(buf, 0);
                return type switch
                {
                    1 => TokenType.Primary,
                    2 => TokenType.Impersonation,
                    _ => TokenType.Unknown
                };
            }
            catch
            {
                warnings.Add("TokenType:Failed");
                return TokenType.Unknown;
            }
        }

        private static TokenImpersonationLevel? TryGetImpersonationLevel(SafeTokenHandle token, TokenType tokenType, List<string> warnings)
        {
            // Only meaningful for impersonation tokens. For primary tokens, keep null.
            if (tokenType != TokenType.Impersonation) return null;

            try
            {
                var buf = GetTokenInformationBytes(token, TOKEN_INFORMATION_CLASS.TokenImpersonationLevel);
                if (buf is null) return TokenImpersonationLevel.Unknown;

                int level = BitConverter.ToInt32(buf, 0);
                return level switch
                {
                    1 => TokenImpersonationLevel.Anonymous,
                    2 => TokenImpersonationLevel.Identification,
                    3 => TokenImpersonationLevel.Impersonation,
                    4 => TokenImpersonationLevel.Delegation,
                    _ => TokenImpersonationLevel.Unknown
                };
            }
            catch
            {
                warnings.Add("TokenImpersonationLevel:Failed");
                return TokenImpersonationLevel.Unknown;
            }
        }

        // =========================
        // Session / elevation / booleans
        // =========================

        private static int? TryGetTokenSessionId(SafeTokenHandle token, List<string> warnings)
        {
            try
            {
                var buf = GetTokenInformationBytes(token, TOKEN_INFORMATION_CLASS.TokenSessionId);
                if (buf is null) return null;

                return BitConverter.ToInt32(buf, 0);
            }
            catch
            {
                warnings.Add("TokenSessionId:Failed");
                return null;
            }
        }

        private static bool? TryGetIsElevated(SafeTokenHandle token, List<string> warnings)
        {
            try
            {
                var buf = GetTokenInformationBytes(token, TOKEN_INFORMATION_CLASS.TokenElevation);
                if (buf is null) return null;

                // TOKEN_ELEVATION { DWORD TokenIsElevated; }
                int elevated = BitConverter.ToInt32(buf, 0);
                return elevated != 0;
            }
            catch
            {
                warnings.Add("TokenElevation:Failed");
                return null;
            }
        }

        private static TokenElevationType TryGetElevationType(SafeTokenHandle token, List<string> warnings)
        {
            try
            {
                var buf = GetTokenInformationBytes(token, TOKEN_INFORMATION_CLASS.TokenElevationType);
                if (buf is null) return TokenElevationType.Unknown;

                int t = BitConverter.ToInt32(buf, 0);
                return t switch
                {
                    1 => TokenElevationType.Default,
                    2 => TokenElevationType.Full,
                    3 => TokenElevationType.Limited,
                    _ => TokenElevationType.Unknown
                };
            }
            catch
            {
                warnings.Add("TokenElevationType:Failed");
                return TokenElevationType.Unknown;
            }
        }

        private static bool? TryGetTokenBool(SafeTokenHandle token, TOKEN_INFORMATION_CLASS clazz, List<string> warnings)
        {
            try
            {
                var buf = GetTokenInformationBytes(token, clazz);
                if (buf is null) return null;

                // Most boolean token info classes return a DWORD/BOOL at offset 0.
                int v = BitConverter.ToInt32(buf, 0);
                return v != 0;
            }
            catch
            {
                warnings.Add($"{clazz}:Failed");
                return null;
            }
        }

        // =========================
        // AppContainer / capabilities
        // =========================

        private static (string? Sid, string? Name) TryGetAppContainerSid(SafeTokenHandle token, List<string> warnings)
        {
            try
            {
                var buf = GetTokenInformationBytes(token, TOKEN_INFORMATION_CLASS.TokenAppContainerSid);
                if (buf is null) return (null, null);

                // TOKEN_APPCONTAINER_INFORMATION { PSID TokenAppContainer; }
                IntPtr sidPtr = ReadIntPtr(buf, 0);
                if (sidPtr == IntPtr.Zero) return (null, null);

                string? sid = TryConvertSidToString(sidPtr);
                // AppContainer SIDs often do not resolve cleanly to "DOMAIN\Name"; keep best-effort.
                string? name = TryLookupAccountName(sidPtr);

                return (sid, name);
            }
            catch
            {
                warnings.Add("TokenAppContainerSid:Failed");
                return (null, null);
            }
        }

        private static IReadOnlyList<string>? TryGetCapabilitiesSids(SafeTokenHandle token, List<string> warnings)
        {
            // TokenCapabilities returns TOKEN_GROUPS
            try
            {
                var groups = TryGetSidListFromTokenGroups(token, TOKEN_INFORMATION_CLASS.TokenCapabilities, warnings);
                return groups;
            }
            catch
            {
                warnings.Add("TokenCapabilities:Failed");
                return null;
            }
        }

        // =========================
        // Groups / restricted SIDs
        // =========================

        private static IReadOnlyList<TokenGroupInfo>? TryGetGroups(SafeTokenHandle token, List<string> warnings)
        {
            try
            {
                var buf = GetTokenInformationBytes(token, TOKEN_INFORMATION_CLASS.TokenGroups);
                if (buf is null) return null;

                return ParseTokenGroups(buf);
            }
            catch
            {
                warnings.Add("TokenGroups:Failed");
                return null;
            }
        }

        private static IReadOnlyList<string>? TryGetRestrictedSids(SafeTokenHandle token, List<string> warnings)
        {
            try
            {
                return TryGetSidListFromTokenGroups(token, TOKEN_INFORMATION_CLASS.TokenRestrictedSids, warnings);
            }
            catch
            {
                warnings.Add("TokenRestrictedSids:Failed");
                return null;
            }
        }

        private static IReadOnlyList<string>? TryGetSidListFromTokenGroups(SafeTokenHandle token, TOKEN_INFORMATION_CLASS clazz, List<string> warnings)
        {
            var buf = GetTokenInformationBytes(token, clazz);
            if (buf is null) return null;

            // TOKEN_GROUPS layout:
            // DWORD GroupCount; SID_AND_ATTRIBUTES Groups[GroupCount];
            int count = BitConverter.ToInt32(buf, 0);
            if (count < 0 || count > 65535) return null;

            var result = new List<string>(count);
            int offset = 4;
            int entrySize = IntPtr.Size + 4;

            for (int i = 0; i < count; i++)
            {
                IntPtr sidPtr = ReadIntPtr(buf, offset);
                if (sidPtr != IntPtr.Zero)
                {
                    var s = TryConvertSidToString(sidPtr);
                    if (!string.IsNullOrWhiteSpace(s))
                        result.Add(s!);
                }

                offset += entrySize;
            }

            return result;
        }

        private static IReadOnlyList<TokenGroupInfo> ParseTokenGroups(byte[] buf)
        {
            int count = BitConverter.ToInt32(buf, 0);
            if (count < 0) count = 0;

            var groups = new List<TokenGroupInfo>(count);
            int offset = 4;
            int entrySize = IntPtr.Size + 4;

            for (int i = 0; i < count; i++)
            {
                IntPtr sidPtr = ReadIntPtr(buf, offset);
                uint attrs = BitConverter.ToUInt32(buf, offset + IntPtr.Size);

                string sid = TryConvertSidToString(sidPtr) ?? string.Empty;
                string? name = sidPtr != IntPtr.Zero ? TryLookupAccountName(sidPtr) : null;

                groups.Add(new TokenGroupInfo
                {
                    Sid = sid,
                    Name = name,
                    Attributes = (TokenGroupAttributes)attrs
                });

                offset += entrySize;
            }

            return groups;
        }

        private static bool? IsMemberOfWellKnownSid(IReadOnlyList<TokenGroupInfo> groups, string wellKnownSid)
        {
            foreach (var g in groups)
            {
                if (string.Equals(g.Sid, wellKnownSid, StringComparison.OrdinalIgnoreCase) &&
                    (g.Attributes & TokenGroupAttributes.Enabled) != 0 &&
                    (g.Attributes & TokenGroupAttributes.UseForDenyOnly) == 0)
                {
                    return true;
                }
            }
            return false;
        }

        // =========================
        // Privileges
        // =========================

        private static IReadOnlyList<TokenPrivilegeInfo>? TryGetPrivileges(SafeTokenHandle token, List<string> warnings)
        {
            try
            {
                var buf = GetTokenInformationBytes(token, TOKEN_INFORMATION_CLASS.TokenPrivileges);
                if (buf is null) return null;

                // TOKEN_PRIVILEGES:
                // DWORD PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[PrivilegeCount];
                int count = BitConverter.ToInt32(buf, 0);
                if (count < 0 || count > 65535) return null;

                var result = new List<TokenPrivilegeInfo>(count);

                int offset = 4;
                int entrySize = 8 + 4; // LUID (8) + Attributes (4)

                for (int i = 0; i < count; i++)
                {
                    uint low = BitConverter.ToUInt32(buf, offset + 0);
                    int high = BitConverter.ToInt32(buf, offset + 4);
                    uint attrs = BitConverter.ToUInt32(buf, offset + 8);

                    long luid64 = ((long)high << 32) | low;
                    string? name = TryLookupPrivilegeName(low, high);

                    result.Add(new TokenPrivilegeInfo
                    {
                        Luid = luid64,
                        Name = name,
                        Attributes = (TokenPrivilegeAttributes)attrs
                    });

                    offset += entrySize;
                }

                return result;
            }
            catch
            {
                warnings.Add("TokenPrivileges:Failed");
                return null;
            }
        }

        private static string? TryLookupPrivilegeName(uint luidLow, int luidHigh)
        {
            try
            {
                var luid = new LUID { LowPart = luidLow, HighPart = luidHigh };

                // First call to get required length.
                int nameLen = 0;
                _ = LookupPrivilegeName(null, ref luid, null, ref nameLen);
                int err = Marshal.GetLastWin32Error();
                if (err != ERROR_INSUFFICIENT_BUFFER || nameLen <= 0) return null;

                var sb = new string('\0', nameLen + 1);
                if (!LookupPrivilegeName(null, ref luid, sb, ref nameLen))
                    return null;

                return sb.Substring(0, nameLen);
            }
            catch
            {
                return null;
            }
        }

        // =========================
        // Linked token & statistics
        // =========================

        private static bool? TryProbeLinkedToken(SafeTokenHandle token, List<string> warnings)
        {
            try
            {
                var buf = GetTokenInformationBytes(token, TOKEN_INFORMATION_CLASS.TokenLinkedToken);
                if (buf is null) return null;

                // TOKEN_LINKED_TOKEN { HANDLE LinkedToken; }
                IntPtr linked = ReadIntPtr(buf, 0);
                if (linked == IntPtr.Zero) return false;

                // Close the linked handle if present (avoid leaks).
                CloseHandle(linked);
                return true;
            }
            catch
            {
                // Not always accessible (especially without elevated context); treat as unknown with warning.
                warnings.Add("TokenLinkedToken:Unavailable");
                return null;
            }
        }

        private static (string? AuthenticationId, string? TokenId) TryGetTokenStatistics(SafeTokenHandle token, List<string> warnings)
        {
            try
            {
                var buf = GetTokenInformationBytes(token, TOKEN_INFORMATION_CLASS.TokenStatistics);
                if (buf is null) return (null, null);

                // TOKEN_STATISTICS is a fixed struct; parse only the LUID fields we care about.
                // Layout (partial):
                // LUID TokenId; LUID AuthenticationId; ...
                // Each LUID: DWORD LowPart; LONG HighPart
                long tokenId = ReadLuid64(buf, 0);
                long authId = ReadLuid64(buf, 8);

                return (FormatLuid(authId), FormatLuid(tokenId));
            }
            catch
            {
                warnings.Add("TokenStatistics:Failed");
                return (null, null);
            }
        }

        private static long ReadLuid64(byte[] buf, int offset)
        {
            uint low = BitConverter.ToUInt32(buf, offset + 0);
            int high = BitConverter.ToInt32(buf, offset + 4);
            return ((long)high << 32) | low;
        }

        private static string FormatLuid(long luid64)
        {
            uint low = unchecked((uint)(luid64 & 0xFFFFFFFF));
            int high = unchecked((int)(luid64 >> 32));
            return $"0x{high:X8}{low:X8}";
        }

        // =========================
        // Core buffer plumbing
        // =========================

        private static byte[]? GetTokenInformationBytes(SafeTokenHandle token, TOKEN_INFORMATION_CLASS clazz)
        {
            // Standard pattern: call once with null buffer to get required size.
            if (!GetTokenInformation(token, clazz, IntPtr.Zero, 0, out int needed))
            {
                int err = Marshal.GetLastWin32Error();
                if (err != ERROR_INSUFFICIENT_BUFFER)
                {
                    // For best-effort callers, return null for "not available" classes.
                    return null;
                }
            }

            if (needed <= 0) return null;

            IntPtr buffer = IntPtr.Zero;
            try
            {
                buffer = Marshal.AllocHGlobal(needed);
                if (!GetTokenInformation(token, clazz, buffer, needed, out _))
                    return null;

                var managed = new byte[needed];
                Marshal.Copy(buffer, managed, 0, needed);
                return managed;
            }
            finally
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            }
        }

        private static IntPtr ReadIntPtr(byte[] buf, int offset)
        {
            return IntPtr.Size == 8
                ? new IntPtr(BitConverter.ToInt64(buf, offset))
                : new IntPtr(BitConverter.ToInt32(buf, offset));
        }

        // =========================
        // SID helpers
        // =========================

        private static string? TryConvertSidToString(IntPtr sid)
        {
            if (sid == IntPtr.Zero) return null;

            try
            {
                // Defensive: prevents undefined behavior if sid is corrupt/dangling.
                if (!IsValidSid(sid))
                {
                    // TODO: log: invalid SID pointer
                    return null;
                }

                if (!ConvertSidToStringSidW(sid, out IntPtr strPtr) || strPtr == IntPtr.Zero)
                {
                    // TODO: log: ConvertSidToStringSidW failed + Marshal.GetLastWin32Error()
                    return null;
                }

                try
                {
                    // ConvertSidToStringSidW returns a Unicode string (LPWSTR).
                    var s = Marshal.PtrToStringUni(strPtr);
                    return string.IsNullOrWhiteSpace(s) ? null : s;
                }
                finally
                {
                    _ = LocalFree(strPtr);
                }
            }
            catch
            {
                // Best-effort: never crash token collection due to SID conversion.
                // TODO: log exception details
                return null;
            }
        }

        private static string? TryLookupAccountName(IntPtr sid)
        {
            if (sid == IntPtr.Zero)
                return null;

            try
            {
                // Defensive: avoid calling into advapi with an invalid SID pointer.
                // This prevents a class of hard crashes when the SID pointer is corrupt/dangling.
                if (!IsValidSid(sid))
                {
                    // TODO: log: invalid SID pointer / corrupt SID
                    return null;
                }

                uint nameLen = 0;
                uint domainLen = 0;

                // Probe call to get required buffer sizes (expected to fail with INSUFFICIENT_BUFFER).
                _ = LookupAccountSidW(
                    lpSystemName: null,
                    Sid: sid,
                    Name: null,
                    cchName: ref nameLen,
                    ReferencedDomainName: null,
                    cchReferencedDomainName: ref domainLen,
                    peUse: out _);

                int err = Marshal.GetLastWin32Error();

                if (err == ERROR_NONE_MAPPED)
                {
                    // SID is valid but not mapped to a friendly account name (common for capability SIDs, etc.)
                    return null;
                }

                if (err != ERROR_INSUFFICIENT_BUFFER)
                {
                    // Any other error: treat as non-fatal in a best-effort tool.
                    // TODO: log: LookupAccountSidW probe failed, include err
                    return null;
                }

                // Allocate buffers using the sizes returned by the probe call.
                var name = new StringBuilder(checked((int)nameLen));
                var domain = new StringBuilder(checked((int)domainLen));

                if (!LookupAccountSidW(
                    lpSystemName: null,
                    Sid: sid,
                    Name: name,
                    cchName: ref nameLen,
                    ReferencedDomainName: domain,
                    cchReferencedDomainName: ref domainLen,
                    peUse: out _))
                {
                    // TODO: log: LookupAccountSidW final call failed, include Marshal.GetLastWin32Error()
                    return null;
                }

                // StringBuilder already contains the correct string; no need for substring logic.
                if (domain.Length == 0)
                    return name.ToString();

                return $"{domain}\\{name}";
            }
            catch (Exception ex) when (
                ex is Win32Exception ||
                ex is ArgumentException ||
                ex is OverflowException ||
                ex is SEHException ||
                ex is AccessViolationException)
            {
                // Best-effort: never crash the tool due to name resolution.
                // TODO: log: exception type + message
                return null;
            }
            catch (Exception ex)
            {
                Logger.LogDebug(ex.Message);
                return null;
            }
        }

        private static int GetSidSubAuthorityCountManaged(IntPtr sid)
        {
            IntPtr pCount = GetSidSubAuthorityCount(sid);
            return pCount == IntPtr.Zero ? 0 : Marshal.ReadByte(pCount);
        }

        private static uint GetSidSubAuthorityRidManaged(IntPtr sid, int index)
        {
            IntPtr pRid = GetSidSubAuthority(sid, checked((uint)index));
            return pRid == IntPtr.Zero ? 0u : unchecked((uint)Marshal.ReadInt32(pRid));
        }

        // =========================
        // Error helpers / constants
        // =========================

        private static string BuildLastWin32Error(string api)
        {
            int code = Marshal.GetLastWin32Error();
            return code switch
            {
                ERROR_ACCESS_DENIED => $"{api}:AccessDenied",
                ERROR_INVALID_PARAMETER => $"{api}:InvalidParameter",
                ERROR_INVALID_HANDLE => $"{api}:InvalidHandle",
                ERROR_NOT_FOUND => $"{api}:NotFound",
                _ => $"{api}:Win32Error:{code}"
            };
        }

        private const int ERROR_ACCESS_DENIED = 5;
        private const int ERROR_INVALID_HANDLE = 6;
        private const int ERROR_INVALID_PARAMETER = 87;
        private const int ERROR_NOT_FOUND = 1168;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int ERROR_NONE_MAPPED = 1332;

        private static class WELL_KNOWN_SIDS
        {
            // S-1-5-32-544
            public const string Administrators = "S-1-5-32-544";

            // S-1-5-18
            public const string LocalSystem = "S-1-5-18";

            // S-1-5-19
            public const string LocalService = "S-1-5-19";

            // S-1-5-20
            public const string NetworkService = "S-1-5-20";
        }

        // =========================
        // Native interop
        // =========================

        [Flags]
        private enum PROCESS_ACCESS_RIGHTS : uint
        {
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        }

        [Flags]
        private enum TOKEN_ACCESS_RIGHTS : uint
        {
            TOKEN_QUERY = 0x0008
        }

        private enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups = 2,
            TokenPrivileges = 3,
            TokenOwner = 4,
            TokenPrimaryGroup = 5,
            TokenDefaultDacl = 6,
            TokenSource = 7,
            TokenType = 8,
            TokenImpersonationLevel = 9,
            TokenStatistics = 10,
            TokenRestrictedSids = 11,
            TokenSessionId = 12,
            TokenGroupsAndPrivileges = 13,
            TokenSandBoxInert = 15,
            TokenOrigin = 17,
            TokenElevationType = 18,
            TokenLinkedToken = 19,
            TokenElevation = 20,
            TokenHasRestrictions = 21,
            TokenAccessInformation = 22,
            TokenVirtualizationAllowed = 23,
            TokenVirtualizationEnabled = 24,
            TokenIntegrityLevel = 25,
            TokenUIAccess = 26,
            TokenMandatoryPolicy = 27,
            TokenLogonSid = 28,
            TokenIsAppContainer = 29,
            TokenCapabilities = 30,
            TokenAppContainerSid = 31
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        private sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeTokenHandle() : base(true) { }
            protected override bool ReleaseHandle() => CloseHandle(handle);
        }


        [DllImport("advapi32.dll", SetLastError = false)]
        private static extern bool IsValidSid(IntPtr pSid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeProcessHandle OpenProcess(PROCESS_ACCESS_RIGHTS dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(SafeProcessHandle ProcessHandle, TOKEN_ACCESS_RIGHTS DesiredAccess, out SafeTokenHandle TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(
            SafeTokenHandle TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        /*[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LookupAccountSid(
            string? lpSystemName,
            IntPtr Sid,
            string? Name,
            ref uint cchName,
            string? ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out SidNameUse peUse);*/

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern bool LookupAccountSidW(
            string? lpSystemName,
            IntPtr Sid,
            StringBuilder? Name,
            ref uint cchName,
            StringBuilder? ReferencedDomainName,
            ref uint cchReferencedDomainName,
            out SidNameUse peUse);

        private enum SidNameUse
        {
            User = 1,
            Group,
            Domain,
            Alias,
            WellKnownGroup,
            DeletedAccount,
            Invalid,
            Unknown,
            Computer,
            Label
        }

        /*[DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ConvertSidToStringSid(IntPtr Sid, out IntPtr StringSid);*/

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern bool ConvertSidToStringSidW(IntPtr Sid, out IntPtr StringSid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeName(
            string? lpSystemName,
            ref LUID lpLuid,
            string? lpName,
            ref int cchName);
    }
}
