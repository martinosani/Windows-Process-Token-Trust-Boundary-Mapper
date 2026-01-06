using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;
using WTBM.Collectors.IPC.OLD;
using WTBM.Domain.IPC;
using WTBM.NtNative;
using static WTBM.NtNative.Win32Security;


namespace WTBM.Collectors.IPC
{
    internal sealed class NamedPipeExtractor
    {
        private const string PipeRootWin32 = @"\\.\pipe\";
        private const string PipeRootNt = @"\Device\NamedPipe\";

        private readonly HashSet<string> _nameQueryTimeouts = new(StringComparer.OrdinalIgnoreCase);


        public NamedPipeExtractor()
        {
            try
            {
                using var token = NtToken.OpenProcessToken(NtProcess.Current, TokenAccessRights.AdjustPrivileges | TokenAccessRights.Query);
                token.SetPrivilege(TokenPrivilegeValue.SeDebugPrivilege, PrivilegeAttributes.Enabled);
            }
            catch (Exception ex)
            {
                Logger.LogDebug("Cannot set SeDebugPrivilege privilege.");
            }
        }

        public IReadOnlyList<NamedPipeEndpoint> GetNamedPipesFromProcessHandles(int pid)
        {
            //var results = new List<NamedPipeEndpoint>();
            var map = new Dictionary<string, NamedPipeEndpoint>(StringComparer.OrdinalIgnoreCase);

            int errorCounter = 0;

            // Logger.LogDebug(String.Format("[PID:{0}] Retrieving named pipes ...", pid));

            // Enumerate all system handles, then filter by PID
            foreach (var h in NtSystemInfo.GetHandles().Where(h => h.ProcessId == pid))
            {
                try
                {
                    string objectType = h.ObjectType;

                    if (!string.Equals(objectType, "File", StringComparison.OrdinalIgnoreCase))
                        continue;

                    //if (String.IsNullOrEmpty(h.Name))
                    //    continue;

                    // Logger.LogDebug(String.Format("[PID:{0}] Retrieving named pipe: {1} ...", pid, h.Name));

                    var hProcess = Native.OpenProcess(Native.PROCESS_DUP_HANDLE, false, h.ProcessId);
                    var dupHandle = IntPtr.Zero;

                    //Logger.LogDebug("DuplicateHandle");

                    bool ok = Native.DuplicateHandle(
                        hProcess,
                        h.Handle,
                        Native.GetCurrentProcess(),
                        out dupHandle,
                        0,
                        false,
                        Native.DUPLICATE_SAME_ACCESS
                    );

                    //Logger.LogDebug("DuplicateHandle - END");

                    if (!ok)
                    {
                        continue;
                    }

                    if (!Win32Security.HasAny(h.GrantedAccess.Access,
                        Win32Security.READ_CONTROL |
                        Win32Security.SYNCHRONIZE |
                        Win32Security.FILE_READ_DATA |
                        Win32Security.FILE_READ_ATTRIBUTES |
                        FILE_READ_EA))
                        continue;

                    if (h.Attributes == AttributeFlags.ProtectClose ||
                        h.Attributes == AttributeFlags.KernelHandle)
                        continue;

                    Logger.LogDebug(String.Format("[PID:{0}] Named pipe|Name={1} | ProcessName={2} | Attributes={3} ...", pid, h.Name, h.ProcessName, h.Attributes));
                    
                    var taskKey = $"{pid}:{h.Handle:X}";
                    if (_nameQueryTimeouts.Contains(taskKey))
                        continue;

                    if (!TryGetObjectNameWithTimeout(dupHandle, 100, out var fullPath))
                    {
                        _nameQueryTimeouts.Add(taskKey);
                        Logger.LogDebug($"[PID:{pid}] ObjectName query TIMEOUT | Handle={h.Handle} | Type={h.ObjectType} | Proc={h.ProcessName}");
                        continue;
                    }

                    if (string.IsNullOrEmpty(fullPath))
                        continue;

                    //string fullPath = NtQuery.GetObjectName(dupHandle);
                    Logger.LogDebug(String.Format("[PID:{0}] Named pipe|FullPath: {1} ...", pid, fullPath));

                    if (string.IsNullOrEmpty(fullPath))
                        continue;

                    if (!fullPath.StartsWith(@"\Device\NamedPipe\", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var namedPipeRef = getNamedPipeRef(fullPath);
                    // Logger.LogDebug(String.Format("[PID:{0}] Named pipe|NtPath={1} | Win32Path={2}", pid, namedPipeRef.NtPath, namedPipeRef.Win32Path));

                    NamedPipeSecurityInfo npsi = null;
                    
                    try
                    {
                        // var sd = Win32Security.GetSecurityDescriptor(namedPipeRef.Win32Path);
                        //Logger.LogDebug($"[PID:{pid}] SD query START | {namedPipeRef.Win32Path}");
                        var sd = Win32Security.GetSecurityDescriptorByHandle(dupHandle);
                        //Logger.LogDebug($"[PID:{pid}] SD query END   | {namedPipeRef.Win32Path}");

                        npsi = new NamedPipeSecurityInfo
                        {
                            OwnerName = sd.OwnerName,
                            OwnerSid = sd.OwnerSid,
                            Sddl = sd.Sddl,
                        };
                    }
                    catch (Exception ex)
                    {
                        npsi = new NamedPipeSecurityInfo
                        {
                            Error = ex.Message
                        };
                    }

                    var endpoint = new NamedPipeEndpoint
                    {
                        Pipe = namedPipeRef,
                        Security = npsi,
                        ServerPid = pid
                    };

                    var key = endpoint.Pipe.NtPath;

                    if (!map.ContainsKey(key))
                    {
                        map[key] = endpoint;
                    }
                    else
                    {
                        map[key] = MergePreferMoreComplete(map[key], endpoint);
                    }


                    // /////////////////////////////

                    /*
                    // Duplicate handle into current process and query object
                    using var obj = h.GetObject().DuplicateObject();

                    // Named pipes are "File" objects with a kernel path under \Device\NamedPipe\
                    if (!string.Equals(obj.NtType.Name, "File", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var fullpath = obj.FullPath; // kernel object name
                    if (string.IsNullOrEmpty(fullpath))
                        continue;

                    if (!fullpath.StartsWith(@"\Device\NamedPipe\", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var owner = obj.SecurityDescriptor.Owner.Sid.GetName();

                    //foreach (var ace in obj.SecurityDescriptor.Dacl)
                   

                    results.Add(new NamedPipeEndpoint
                    {
                        Pipe = getNamedPipeRef(obj.FullPath),
                        Security = new NamedPipeSecurityInfo
                        {
                            OwnerName = owner.QualifiedName,
                            OwnerSid = owner.Sddl,
                            Sddl = obj.SecurityDescriptor.ToString()
                        },
                        ServerPid = pid
                    });

                    */

                }
                catch (Exception ex)
                {
                    // Access denied, protected processes, or race conditions.
                    if (errorCounter < 5)
                    {
                        ++errorCounter;
                    }
                    else
                    {
                        Logger.LogDebug(String.Format("[PID:{0}] {1}", pid, ex.ToString()));
                        return map.Values
                            .OrderBy(e => e.Pipe.NtPath, StringComparer.OrdinalIgnoreCase)
                            .ToArray();
                    }
                }
            }

            return map.Values
                .OrderBy(e => e.Pipe.NtPath, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        private bool TryGetObjectNameWithTimeout(IntPtr dupHandle, int timeoutMs, out string? fullPath)
        {
            fullPath = null;

            string? local = null;
            Exception? ex = null;

            var t = new Thread(() =>
            {
                try { local = NtQuery.GetObjectName(dupHandle); }
                catch (Exception e) { ex = e; }
            })
            { IsBackground = true, Name = "WTBM-ObjName" };

            t.Start();

            if (!t.Join(timeoutMs))
                return false; // timed out

            if (ex != null)
                return true;  // call returned but failed; treat as "no name" and continue

            fullPath = local;
            return true;
        }

        private static NamedPipeEndpoint MergePreferMoreComplete(NamedPipeEndpoint a, NamedPipeEndpoint b)
        {
            bool aOk = a.Security != null && string.IsNullOrEmpty(a.Security.Error) && !string.IsNullOrEmpty(a.Security.Sddl);
            bool bOk = b.Security != null && string.IsNullOrEmpty(b.Security.Error) && !string.IsNullOrEmpty(b.Security.Sddl);

            var best = bOk && !aOk ? b : a;

            var tags = (a.Tags ?? Array.Empty<string>())
                .Concat(b.Tags ?? Array.Empty<string>())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            return new NamedPipeEndpoint
            {
                Pipe = best.Pipe,
                Security = best.Security,
                ReachableFromMedium = best.ReachableFromMedium,
                ReachableFromLow = best.ReachableFromLow,
                ReachableFromAppContainer = best.ReachableFromAppContainer,
                ReachabilityConfidence = best.ReachabilityConfidence,
                ReachabilityNotes = best.ReachabilityNotes,
                ServerPid = best.ServerPid,
                CandidateServerPids = best.CandidateServerPids,
                ServerQueryError = best.ServerQueryError,
                Tags = tags
            };
        }

        private NamedPipeRef getNamedPipeRef(string ntFullPath)
        {
            if (string.IsNullOrWhiteSpace(ntFullPath))
                return null;

            // Expect: \Device\NamedPipe\<relative>
            if (!ntFullPath.StartsWith(PipeRootNt, StringComparison.OrdinalIgnoreCase))
                return null;

            // Keep the relative name EXACTLY as-is (including backslashes).
            var relativeName = ntFullPath.Substring(PipeRootNt.Length);
            if (string.IsNullOrWhiteSpace(relativeName))
                return null;

            var displayName = NormalizePipeNameForDisplay(relativeName);

            return new NamedPipeRef(
                Name: displayName ?? ntFullPath,
                Win32Path: PipeRootWin32 + relativeName,
                NtPath: ntFullPath
            );

            return null;
        }

        private string NormalizePipeNameForDisplay(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return string.Empty;

            var name = raw.Trim().TrimStart('\\', '/');

            if (name is "." or "..")
                return string.Empty;

            // Pipes are leaf names under \\.\pipe\; avoid path separators breaking concatenation.
            if (name.IndexOfAny(new[] { '\\', '/' }) >= 0)
                name = name.Replace('\\', '_').Replace('/', '_');

            return name;
        }
    }
}
