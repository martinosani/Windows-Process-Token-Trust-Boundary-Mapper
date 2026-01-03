using PTTBM.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace PTTBM.Collectors
{
    internal sealed class ProcessEnumerator
    {
        public IReadOnlyList<ProcessRecord> Enumerate()
        {
            var results = new List<ProcessRecord>();

            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == IntPtr.Zero || snapshot == INVALID_HANDLE_VALUE)
                throw new InvalidOperationException("CreateToolhelp32Snapshot failed.");

            try
            {
                var entry = new PROCESSENTRY32();
                entry.dwSize = (uint)Marshal.SizeOf(entry);

                if (!Process32First(snapshot, ref entry))
                    return results;

                do
                {
                    var pid = unchecked((int)entry.th32ProcessID);
                    var ppid = unchecked((int)entry.th32ParentProcessID);

                    int? sessionId = null;

                    // Best-effort: retrieving the SessionId may legitimately fail (race conditions, access limits).
                    // A failure here is not an error and simply means the information is not observable
                    // from the current security context.
                    if (ProcessIdToSessionId(pid, out uint sid))
                        sessionId = unchecked((int)sid);

                    results.Add(new ProcessRecord
                    {
                        Pid = pid,
                        Ppid = ppid,
                        Name = entry.szExeFile ?? string.Empty,
                        SessionId = sessionId
                    });

                } while (Process32Next(snapshot, ref entry));
            }
            finally
            {
                CloseHandle(snapshot);
            }

            return results;
        }

        // ===== Win32 Interop =====

        private const uint TH32CS_SNAPPROCESS = 0x00000002;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ProcessIdToSessionId(int dwProcessId, out uint pSessionId);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }
    }
}
