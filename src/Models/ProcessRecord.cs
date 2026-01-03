using System;
using System.Collections.Generic;
using System.Text;

namespace PTTBM.Models
{
    internal sealed class ProcessRecord
    {
        public int Pid { get; init; }
        public int Ppid { get; init; }
        public string Name { get; init; } = string.Empty;
        public int? SessionId { get; init; }
        public string? ImagePath { get; init; }
        public string? CollectionError { get; init; }
        public TokenInfo? Token { get; init; }
    }
}
