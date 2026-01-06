using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using WTBM.Domain.IPC;

namespace WTBM.Collectors.IPC
{
    internal sealed class NamedPipeSecurityCollector
    {
        private static readonly int Win32BusyRetryCount = ParseEnvInt("WTBM_NPSEC_WIN32_BUSY_RETRIES", 3);
        private static readonly int Win32BusyWaitMs = ParseEnvInt("WTBM_NPSEC_WIN32_BUSY_WAIT_MS", 10);

        private static readonly int NtBusyRetryCount = ParseEnvInt("WTBM_NPSEC_NT_BUSY_RETRIES", 2);
        private static readonly int NtBusyBackoffMs = ParseEnvInt("WTBM_NPSEC_NT_BUSY_BACKOFF_MS", 5);

        private static int ParseEnvInt(string name, int fallback)
        {
            var v = Environment.GetEnvironmentVariable(name);
            return int.TryParse(v, out var x) && x >= 0 ? x : fallback;
        }

        // ============================================================
        // Trace (console) - enable with env var WTBM_TRACE_NPSEC=1/true
        // ============================================================

        private static readonly bool TraceEnabled = true;
            //string.Equals(Environment.GetEnvironmentVariable("WTBM_TRACE_NPSEC"), "1", StringComparison.OrdinalIgnoreCase) ||
            //string.Equals(Environment.GetEnvironmentVariable("WTBM_TRACE_NPSEC"), "true", StringComparison.OrdinalIgnoreCase);

        private static void Trace(string phase, string message, string? path = null, int? status = null, Exception? ex = null)
        {
            if (!TraceEnabled) return;

            var sb = new StringBuilder(256);
            sb.Append(DateTime.UtcNow.ToString("o"));
            sb.Append(" [NamedPipeSecurityCollector] ");
            sb.Append(phase);
            sb.Append(" - ");
            sb.Append(message);

            if (!string.IsNullOrWhiteSpace(path))
            {
                sb.Append(" | path=");
                sb.Append(path);
            }

            if (status is not null)
            {
                sb.Append(" | status=");
                sb.Append(NtStatusName(status.Value));
            }

            if (ex is not null)
            {
                sb.Append(" | ex=");
                sb.Append(ex.GetType().Name);
                sb.Append(":");
                sb.Append(ex.Message);
            }

            Console.WriteLine(sb.ToString());
        }

        public NamedPipeSecurityInfo TryCollect(NamedPipeRef pipe, bool includeMandatoryLabel = true)
        {
            if (pipe is null) throw new ArgumentNullException(nameof(pipe));

            // Strategy:
            // 1) Prefer NT path (\Device\NamedPipe\foo) via NtOpenFile + NtQuerySecurityObject.
            // 2) Fallback to Win32 path (\\.\pipe\foo) via GetNamedSecurityInfo (legacy compatibility).
            Trace("TryCollect", "start", pipe.NtPath);

            var nt = TryCollectViaNt(pipe.NtPath, includeMandatoryLabel);
            if (nt.Info is not null)
            {
                Trace("TryCollect", "NT success", pipe.NtPath);
                return nt.Info;
            }

            Trace("TryCollect", $"NT failed: {nt.Error}", pipe.NtPath);

            var win32 = TryCollectViaWin32(pipe.Win32Path, includeMandatoryLabel);
            if (win32.Info is not null)
            {
                Trace("TryCollect", "Win32 success", pipe.Win32Path);
                return win32.Info;
            }

            Trace("TryCollect", $"Win32 failed: {win32.Error}", pipe.Win32Path);

            // Return the "best" error we have.
            return new NamedPipeSecurityInfo
            {
                Error = nt.Error ?? win32.Error ?? "SecurityQuery:UnknownFailure"
            };
        }

        // =========================
        // NT path implementation
        // =========================

        private static QueryAttempt TryCollectViaNt(string ntObjectPath, bool includeMandatoryLabel)
        {
            Trace("NT", "begin", ntObjectPath);

            // Open with READ_CONTROL first (covers Owner/Group/DACL).
            var infoFlags = SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION
                          | SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION
                          | SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;

            var (sdOwnerDacl, err1) = TryQuerySecurityDescriptorNt(ntObjectPath, desiredAccess: READ_CONTROL, infoFlags);
            if (sdOwnerDacl is null)
            {
                Trace("NT", $"owner/dacl query failed: {err1}", ntObjectPath);
                return QueryAttempt.Fail($"NT:{err1}");
            }

            // Optionally: try query label. This may require ACCESS_SYSTEM_SECURITY and SeSecurityPrivilege.
            byte[]? sdWithLabel = null;
            if (includeMandatoryLabel)
            {
                // NOTE:
                // - LABEL_SECURITY_INFORMATION retrieves the integrity label (MIL) if available.
                // - Some systems require ACCESS_SYSTEM_SECURITY; some allow it with READ_CONTROL.
                var labelFlags = infoFlags | SECURITY_INFORMATION.LABEL_SECURITY_INFORMATION;

                // Try with ACCESS_SYSTEM_SECURITY first, fallback to READ_CONTROL only (best-effort).
                (sdWithLabel, var err2) = TryQuerySecurityDescriptorNt(
                    ntObjectPath,
                    desiredAccess: READ_CONTROL | ACCESS_SYSTEM_SECURITY,
                    labelFlags);

                if (sdWithLabel is null)
                {
                    Trace("NT", $"label query (with ACCESS_SYSTEM_SECURITY) failed: {err2}", ntObjectPath);

                    // try again without ACCESS_SYSTEM_SECURITY (best-effort)
                    (sdWithLabel, var err3) = TryQuerySecurityDescriptorNt(
                        ntObjectPath,
                        desiredAccess: READ_CONTROL,
                        labelFlags);

                    if (sdWithLabel is null)
                        Trace("NT", $"label query (READ_CONTROL only) failed: {err3}", ntObjectPath);
                }
            }

            // Parse base SD (Owner/Group/DACL) from sdOwnerDacl.
            // If label succeeded, parse from sdWithLabel instead (contains everything).
            var sdToParse = sdWithLabel ?? sdOwnerDacl;

            try
            {
                var raw = new RawSecurityDescriptor(sdToParse, 0);

                var ownerSid = raw.Owner?.Value;
                var ownerName = TryResolveSidToName(raw.Owner);

                var sddl = raw.GetSddlForm(AccessControlSections.All);

                var dacl = raw.DiscretionaryAcl is null
                    ? null
                    : ParseDacl(raw.DiscretionaryAcl);

                MandatoryLabelInfo? mil = null;
                if (includeMandatoryLabel && raw.SystemAcl is not null)
                {
                    mil = TryParseMandatoryLabel(raw.SystemAcl);
                }

                Trace("NT", "parsed ok", ntObjectPath);

                return QueryAttempt.Ok(new NamedPipeSecurityInfo
                {
                    OwnerSid = ownerSid,
                    OwnerName = ownerName,
                    Sddl = sddl,
                    Dacl = dacl,
                    MandatoryLabel = mil,
                    Error = null
                });
            }
            catch (Exception ex)
            {
                Trace("NT", "parse failed", ntObjectPath, ex: ex);
                return QueryAttempt.Fail($"NT:Parse:{ex.GetType().Name}");
            }
        }

        private static (byte[]? securityDescriptor, string? error) TryQuerySecurityDescriptorNt(
            string ntObjectPath,
            uint desiredAccess,
            SECURITY_INFORMATION infoFlags)
        {
            SafeNtHandle? handle = null;

            try
            {
                int status;

                for (int attempt = 0; ; attempt++)
                {
                    status = NtOpenNamedPipe(ntObjectPath, desiredAccess, out handle);
                    if (status == 0) break;

                    if (IsPipeBusyNt(status) && attempt < NtBusyRetryCount)
                    {
                        Trace("NT",
                            $"STATUS_PIPE_BUSY -> backoff {NtBusyBackoffMs}ms then retry (attempt {attempt + 1}/{NtBusyRetryCount})",
                            ntObjectPath,
                            status: status);

                        System.Threading.Thread.Sleep(NtBusyBackoffMs);
                        handle?.Dispose();
                        handle = null;
                        continue;
                    }

                    return (null, $"NtOpenFile:{NtStatusName(status)}");
                }

                // Query pattern: call NtQuerySecurityObject with growing buffer.
                var bufferSize = 4096u;

                for (int attempt = 0; attempt < 6; attempt++)
                {
                    var buf = Marshal.AllocHGlobal((int)bufferSize);
                    try
                    {
                        uint returned = 0;
                        status = NtQuerySecurityObject(handle.DangerousGetHandle(), infoFlags, buf, bufferSize, out returned);

                        if (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW)
                        {
                            // Use returned if plausible, otherwise grow exponentially.
                            var next = returned > bufferSize ? returned : bufferSize * 2;
                            bufferSize = Math.Min(next, 1_048_576u); // cap at 1MB
                            Trace("NT", $"resize sd buffer -> {bufferSize} bytes (attempt {attempt + 1})", ntObjectPath, status: status);
                            continue;
                        }

                        if (status != 0)
                        {
                            Trace("NT", "NtQuerySecurityObject failed", ntObjectPath, status: status);
                            return (null, $"NtQuerySecurityObject:{NtStatusName(status)}");
                        }

                        // Copy the SD bytes out.
                        var bytes = new byte[returned];
                        Marshal.Copy(buf, bytes, 0, (int)returned);
                        return (bytes, null);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buf);
                    }
                }

                return (null, "NtQuerySecurityObject:TooManyResizeAttempts");
            }
            catch (Exception ex)
            {
                Trace("NT", "exception in TryQuerySecurityDescriptorNt", ntObjectPath, ex: ex);
                return (null, $"Exception:{ex.GetType().Name}");
            }
            finally
            {
                handle?.Dispose();
            }
        }

        private static int NtOpenNamedPipe(string ntPath, uint desiredAccess, out SafeNtHandle handle)
        {
            handle = new SafeNtHandle();

            // Improved robustness:
            // - Use correctly laid-out UNICODE_STRING (x86/x64 safe).
            // - Avoid setting the SafeHandle with garbage if NtOpenFile fails.
            IntPtr stringBuffer = IntPtr.Zero;
            IntPtr unicodeStringPtr = IntPtr.Zero;

            try
            {
                var us = CreateUnicodeString(ntPath, out stringBuffer, out unicodeStringPtr);

                var oa = new OBJECT_ATTRIBUTES
                {
                    Length = (uint)Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
                    RootDirectory = IntPtr.Zero,
                    ObjectName = unicodeStringPtr, // PUNICODE_STRING
                    Attributes = OBJ_CASE_INSENSITIVE,
                    SecurityDescriptor = IntPtr.Zero,
                    SecurityQualityOfService = IntPtr.Zero
                };

                IO_STATUS_BLOCK iosb;

                // Use FILE_OPEN + FILE_NON_DIRECTORY_FILE.
                // Share flags allow coexistence with server instances.
                var status = NtOpenFile(
                    out var h,
                    desiredAccess,
                    ref oa,
                    out iosb,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_NON_DIRECTORY_FILE);

                if (status == 0)
                {
                    handle.SetHandle(h);
                }
                else
                {
                    Trace("NT", "NtOpenFile failed", ntPath, status: status);
                }

                return status;
            }
            catch (Exception ex)
            {
                Trace("NT", "exception in NtOpenNamedPipe", ntPath, ex: ex);
                return unchecked((int)0xC0000001); // STATUS_UNSUCCESSFUL
            }
            finally
            {
                if (unicodeStringPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(unicodeStringPtr);

                if (stringBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(stringBuffer);
            }
        }

        private static UNICODE_STRING CreateUnicodeString(string s, out IntPtr stringBuffer, out IntPtr unicodeStringPtr)
        {
            // Allocate the UTF-16 string buffer.
            // Must be null-terminated; StringToHGlobalUni does that.
            stringBuffer = Marshal.StringToHGlobalUni(s);

            var us = new UNICODE_STRING
            {
                Length = checked((ushort)(s.Length * 2)),
                MaximumLength = checked((ushort)((s.Length * 2) + 2)),
                Buffer = stringBuffer
            };

            // Allocate UNICODE_STRING struct.
            unicodeStringPtr = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>());
            Marshal.StructureToPtr(us, unicodeStringPtr, fDeleteOld: false);

            return us;
        }

        // =========================
        // Win32 fallback (improved and complete)
        // =========================

        private static QueryAttempt TryCollectViaWin32(string win32Path, bool includeMandatoryLabel)
        {
            Trace("Win32", "begin", win32Path);

            // Base flags always requested.
            const SECURITY_INFORMATION baseFlags =
                SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION |
                SECURITY_INFORMATION.GROUP_SECURITY_INFORMATION |
                SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;

            // We will try to include label if requested, but must tolerate access denied.
            SECURITY_INFORMATION flags = baseFlags;
            if (includeMandatoryLabel)
                flags |= SECURITY_INFORMATION.LABEL_SECURITY_INFORMATION;

            // Attempt 1: with label (if requested).
            var (sdBytes, err) = TryQuerySecurityDescriptorWin32(win32Path, flags);
            if (sdBytes is null && includeMandatoryLabel)
            {
                Trace("Win32", $"query with LABEL failed: {err} (retry without LABEL)", win32Path);

                // Attempt 2: without label.
                (sdBytes, err) = TryQuerySecurityDescriptorWin32(win32Path, baseFlags);
            }

            if (sdBytes is null)
            {
                Trace("Win32", $"query failed: {err}", win32Path);
                return QueryAttempt.Fail($"Win32:{err}");
            }

            try
            {
                var raw = new RawSecurityDescriptor(sdBytes, 0);

                var ownerSid = raw.Owner?.Value;
                var ownerName = TryResolveSidToName(raw.Owner);

                var sddl = raw.GetSddlForm(AccessControlSections.All);

                var dacl = raw.DiscretionaryAcl is null
                    ? null
                    : ParseDacl(raw.DiscretionaryAcl);

                MandatoryLabelInfo? mil = null;
                if (includeMandatoryLabel && raw.SystemAcl is not null)
                {
                    // MIL is typically stored as an ACE in the SACL (integrity SID S-1-16-*)
                    mil = TryParseMandatoryLabel(raw.SystemAcl);
                }

                Trace("Win32", "parsed ok", win32Path);

                return QueryAttempt.Ok(new NamedPipeSecurityInfo
                {
                    OwnerSid = ownerSid,
                    OwnerName = ownerName,
                    Sddl = sddl,
                    Dacl = dacl,
                    MandatoryLabel = mil,
                    Error = null
                });
            }
            catch (Exception ex)
            {
                Trace("Win32", "parse failed", win32Path, ex: ex);
                return QueryAttempt.Fail($"Win32:Parse:{ex.GetType().Name}");
            }
        }

        private static (byte[]? securityDescriptor, string? error) TryQuerySecurityDescriptorWin32(
    string win32Path,
    SECURITY_INFORMATION securityInformation)
        {
            var normalized = NormalizeWin32PipePath(win32Path);

            for (int attempt = 0; attempt <= Win32BusyRetryCount; attempt++)
            {
                IntPtr pSD = IntPtr.Zero;
                IntPtr pOwner = IntPtr.Zero;
                IntPtr pGroup = IntPtr.Zero;
                IntPtr pDacl = IntPtr.Zero;
                IntPtr pSacl = IntPtr.Zero;

                try
                {
                    var result = GetNamedSecurityInfoW(
                        normalized,
                        SE_OBJECT_TYPE.SE_FILE_OBJECT,
                        securityInformation,
                        out pOwner,
                        out pGroup,
                        out pDacl,
                        out pSacl,
                        out pSD);

                    if (result == ERROR_PIPE_BUSY && attempt < Win32BusyRetryCount)
                    {
                        Trace("Win32",
                            $"ERROR_PIPE_BUSY -> WaitNamedPipe {Win32BusyWaitMs}ms then retry (attempt {attempt + 1}/{Win32BusyRetryCount})",
                            normalized);

                        // WaitNamedPipe returns false on timeout (ERROR_SEM_TIMEOUT=121) or other errors.
                        var ok = WaitNamedPipeW(normalized, (uint)Win32BusyWaitMs);
                        if (!ok)
                        {
                            var last = Marshal.GetLastWin32Error();
                            Trace("Win32", $"WaitNamedPipe failed/timeout (lastError={last})", normalized);
                        }
                        else
                        {
                            Trace("Win32", "WaitNamedPipe signaled availability", normalized);
                        }

                        continue;
                    }

                    if (pSD == IntPtr.Zero)
                        return (null, "GetNamedSecurityInfo:NullSecurityDescriptor");

                    // Convert absolute SD to self-relative bytes
                    uint needed = 0;
                    if (!MakeSelfRelativeSD(pSD, IntPtr.Zero, ref needed))
                    {
                        var last = Marshal.GetLastWin32Error();
                        if (last != ERROR_INSUFFICIENT_BUFFER)
                            return (null, $"MakeSelfRelativeSD:ProbeFailed:{last}");
                    }

                    var buf = Marshal.AllocHGlobal((int)needed);
                    try
                    {
                        uint needed2 = needed;
                        if (!MakeSelfRelativeSD(pSD, buf, ref needed2))
                        {
                            var last2 = Marshal.GetLastWin32Error();
                            return (null, $"MakeSelfRelativeSD:ConvertFailed:{last2}");
                        }

                        var bytes = new byte[needed2];
                        Marshal.Copy(buf, bytes, 0, (int)needed2);
                        return (bytes, null);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buf);
                    }
                }
                catch (Exception ex)
                {
                    Trace("Win32", "exception in TryQuerySecurityDescriptorWin32", normalized, ex: ex);
                    return (null, $"Exception:{ex.GetType().Name}");
                }
                finally
                {
                    if (pSD != IntPtr.Zero)
                        LocalFree(pSD);
                }
            }

            // Should not reach here due to returns, but keep deterministic.
            return (null, "GetNamedSecurityInfo:PIPE_BUSY_RetryExhausted");
        }

        // Helper used for probing MakeSelfRelativeSD
        private static uint UnsafeZero = 0;

        private const int STATUS_PIPE_BUSY = unchecked((int)0xC00000AC);
        private const int ERROR_PIPE_BUSY = 231;

        private static bool IsPipeBusyNt(int status) => status == STATUS_PIPE_BUSY;
        private static bool IsPipeBusyWin32(string? err) => err?.Contains("231(") == true || err?.Contains(":231(") == true;

        // =========================
        // Parsing helpers
        // =========================

        private static IReadOnlyList<AceInfo> ParseDacl(RawAcl dacl)
        {
            var list = new List<AceInfo>(dacl.Count);

            for (int i = 0; i < dacl.Count; i++)
            {
                if (dacl[i] is not CommonAce ace)
                    continue;

                var sid = ace.SecurityIdentifier?.Value ?? string.Empty;

                list.Add(new AceInfo
                {
                    Sid = sid,
                    Principal = TryResolveSidToName(ace.SecurityIdentifier),
                    AceType = ace.AceType.ToString(),
                    Rights = FormatPipeRights(ace.AccessMask),
                    Condition = null
                });
            }

            return list;
        }

        // Conservative placeholder: you can refine to map mask bits to pipe semantics later.
        private static string FormatPipeRights(int accessMask)
        {
            // Keep as hex for research-grade explainability if you don’t have a clean mapping yet.
            return $"0x{accessMask:X8}";
        }

        private static string? TryResolveSidToName(SecurityIdentifier? sid)
        {
            if (sid is null) return null;
            try
            {
                var nt = (NTAccount)sid.Translate(typeof(NTAccount));
                return nt.Value;
            }
            catch
            {
                return sid.Value; // fallback to SID string for deterministic output
            }
        }

        // For MIL in SDDL, RawSecurityDescriptor.SystemAcl includes CommonAce entries;
        // we detect the mandatory label by looking for the SID S-1-16-* (integrity) and policy bits.
        private static MandatoryLabelInfo? TryParseMandatoryLabel(RawAcl sacl)
        {
            for (int i = 0; i < sacl.Count; i++)
            {
                if (sacl[i] is not CommonAce ace)
                    continue;

                var sid = ace.SecurityIdentifier;
                if (sid is null)
                    continue;

                // Integrity SIDs are S-1-16-*
                if (!sid.Value.StartsWith("S-1-16-", StringComparison.OrdinalIgnoreCase))
                    continue;

                // AccessMask on label ACE encodes mandatory policy flags.
                var policy = FormatMandatoryLabelPolicy(ace.AccessMask);

                return new MandatoryLabelInfo
                {
                    Sid = sid.Value,
                    Principal = TryResolveSidToName(sid),
                    Policy = policy
                };
            }

            return null;
        }

        private static string FormatMandatoryLabelPolicy(int accessMask)
        {
            // Bits (documented for SYSTEM_MANDATORY_LABEL_ACE) commonly include:
            // 0x1 = NO_WRITE_UP, 0x2 = NO_READ_UP, 0x4 = NO_EXECUTE_UP.
            var parts = new List<string>(3);

            if ((accessMask & 0x1) != 0) parts.Add("NoWriteUp");
            if ((accessMask & 0x2) != 0) parts.Add("NoReadUp");
            if ((accessMask & 0x4) != 0) parts.Add("NoExecuteUp");

            return parts.Count == 0 ? $"0x{accessMask:X}" : string.Join("|", parts);
        }

        // =========================
        // NT interop
        // =========================

        private const uint READ_CONTROL = 0x00020000;
        private const uint ACCESS_SYSTEM_SECURITY = 0x01000000;

        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint FILE_SHARE_DELETE = 0x00000004;

        private const uint FILE_NON_DIRECTORY_FILE = 0x00000040;

        private const uint OBJ_CASE_INSENSITIVE = 0x00000040;

        private const int STATUS_BUFFER_TOO_SMALL = unchecked((int)0xC0000023);
        private const int STATUS_BUFFER_OVERFLOW = unchecked((int)0x80000005);

        private const int ERROR_INSUFFICIENT_BUFFER = 122;

        [Flags]
        private enum SECURITY_INFORMATION : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION = 0x00000004,
            SACL_SECURITY_INFORMATION = 0x00000008,
            LABEL_SECURITY_INFORMATION = 0x00000010
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_STATUS_BLOCK
        {
            public IntPtr Status;
            public IntPtr Information;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName; // PUNICODE_STRING
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        private sealed class SafeNtHandle : SafeHandle
        {
            public SafeNtHandle() : base(IntPtr.Zero, ownsHandle: true) { }
            public override bool IsInvalid => handle == IntPtr.Zero || handle == new IntPtr(-1);

            protected override bool ReleaseHandle()
            {
                return NtClose(handle) == 0;
            }

            public void SetHandle(IntPtr h) => handle = h;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtOpenFile(
            out IntPtr FileHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            out IO_STATUS_BLOCK IoStatusBlock,
            uint ShareAccess,
            uint OpenOptions);

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySecurityObject(
            IntPtr Handle,
            SECURITY_INFORMATION SecurityInformation,
            IntPtr SecurityDescriptor,
            uint Length,
            out uint LengthNeeded);

        [DllImport("ntdll.dll")]
        private static extern int NtClose(IntPtr Handle);

        private static string NtStatusName(int status)
        {
            // Minimal mapping; keep deterministic strings for research.
            if (status == 0) return "STATUS_SUCCESS";
            if (status == STATUS_BUFFER_TOO_SMALL) return "STATUS_BUFFER_TOO_SMALL";
            if (status == STATUS_BUFFER_OVERFLOW) return "STATUS_BUFFER_OVERFLOW";
            return $"0x{status:X8}";
        }

        // =========================
        // Win32 interop
        // =========================

        private enum SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE = 0,
            SE_FILE_OBJECT = 1,
            SE_SERVICE = 2,
            SE_PRINTER = 3,
            SE_REGISTRY_KEY = 4,
            SE_LMSHARE = 5,
            SE_KERNEL_OBJECT = 6,
            SE_WINDOW_OBJECT = 7,
            SE_DS_OBJECT = 8,
            SE_DS_OBJECT_ALL = 9,
            SE_PROVIDER_DEFINED_OBJECT = 10,
            SE_WMIGUID_OBJECT = 11,
            SE_REGISTRY_WOW64_32KEY = 12
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetNamedSecurityInfoW(
            string pObjectName,
            SE_OBJECT_TYPE objectType,
            SECURITY_INFORMATION securityInfo,
            out IntPtr ppsidOwner,
            out IntPtr ppsidGroup,
            out IntPtr ppDacl,
            out IntPtr ppSacl,
            out IntPtr ppSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool MakeSelfRelativeSD(
            IntPtr pAbsoluteSecurityDescriptor,
            IntPtr pSelfRelativeSecurityDescriptor,
            ref uint lpdwBufferLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool WaitNamedPipeW(string lpNamedPipeName, uint nTimeOut);

        private static string NormalizeWin32PipePath(string win32Path)
        {
            if (string.IsNullOrWhiteSpace(win32Path))
                return win32Path;

            // Canonical form: \\.\pipe\<name>
            if (win32Path.StartsWith(@"\\.\pipe\", StringComparison.OrdinalIgnoreCase))
                return win32Path;

            // If someone passed only the name, fix it.
            if (!win32Path.Contains(@"\") && !win32Path.Contains(@"/"))
                return @"\\.\pipe\" + win32Path;
            return win32Path;
        }

        // Lightweight result holder.
        private readonly struct QueryAttempt
        {
            public NamedPipeSecurityInfo? Info { get; }
            public string? Error { get; }

            private QueryAttempt(NamedPipeSecurityInfo? info, string? error)
            {
                Info = info;
                Error = error;
            }

            public static QueryAttempt Ok(NamedPipeSecurityInfo info) => new QueryAttempt(info, null);
            public static QueryAttempt Fail(string error) => new QueryAttempt(null, error);
        }
    }
}
