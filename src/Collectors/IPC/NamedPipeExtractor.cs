using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Collectors.IPC.OLD;
using WTBM.Domain.IPC;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace WTBM.Collectors.IPC
{
    internal sealed class NamedPipeExtractor
    {
        private const string PipeRootWin32 = @"\\.\pipe\";
        private const string PipeRootNt = @"\Device\NamedPipe\";

        public IReadOnlyList<NamedPipeEndpoint> GetNamedPipesFromProcessHandles(int pid)
        {
            var results = new List<NamedPipeEndpoint>();
            int errorCounter = 0;

            // Enumerate all system handles, then filter by PID
            foreach (var h in NtSystemInfo.GetHandles().Where(h => h.ProcessId == pid))
            {
                try
                {
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
                        }
                    });

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
                        return results;
                    }
                }
            }

            return results;
        }

        private NamedPipeRef getNamedPipeRef(string path)
        {
            var name = NormalizePipeName(path);
            if (!string.IsNullOrEmpty(name))
            {
                return new NamedPipeRef(
                    Name: name,
                    Win32Path: PipeRootWin32 + name,
                    NtPath: PipeRootNt + name
                );
            }
            return null;
        }

        private string NormalizePipeName(string? raw)
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
