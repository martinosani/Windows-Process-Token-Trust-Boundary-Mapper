using System;
using System.Collections.Generic;
using System.Text;

namespace WTBM.Domain.IPC
{
    internal sealed record NamedPipeRef(string Name, string Win32Path, string NtPath);
}
