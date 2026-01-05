using System;
using System.Collections.Generic;
using System.Text;

namespace WTBM
{
    internal static class Logger
    {
        public static void LogDebug(string message = "")
        {
            Console.WriteLine(message);
        }
    }
}
