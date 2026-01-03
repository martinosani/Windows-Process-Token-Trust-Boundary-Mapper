using PTTBM.Collectors;
using System;

namespace PTTBM
{
    internal static class Program
    {
        static int Main(string[] args)
        {
            Console.WriteLine("PTTBM - Process & Token Trust Boundary Mapper");
            Console.WriteLine("Initializing...");

            var processes = new ProcessEnumerator().Enumerate();
            Console.WriteLine($"Found {processes.Count} processes.");

            foreach (var process in processes)
            {
                Console.WriteLine($"{process.Pid,6} {process.Ppid,6} S:{process.SessionId,2} {process.Name}");
            }


            return 0;
        }
    }
}
