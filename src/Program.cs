using WTBM.Collectors;
using WTBM.Renders.OutputWriter;
using System;
using WTBM.Output.Terminal;
using WTBM.Rules.Engine;
using WTBM.Collectors.IPC;

namespace WTBM
{
    internal static class Program
    {
        static int Main(string[] args)
        {
            Console.WriteLine("WTBM - Process & Token Trust Boundary Mapper");
            Console.WriteLine("Initializing...");

            var processes = new ProcessEnumerator().Enumerate();
            var tokenCollector = new TokenCollector();
            var snapshots = processes.Select(p => tokenCollector.TryCollect(p)).ToList();

            var namedPipes = new NamedPipeEnumerator().Enumerate();
            
            // NamedPipesConsoleWriter.WriteSummary(namedPipes, namedPipesSecurityInfo);

            var rules = DefaultRuleSet.Create();
            var findings = RuleEngine.EvaluateAll(snapshots, namedPipes,  rules);

            /*
            FindingsConsoleWriter.WriteSummary(findings, snapshots);

            if (findings.Count > 0)
            {
                Console.WriteLine();

                FindingsConsoleWriter.Explain(findings[0], snapshots);
            }*/

            Console.ReadLine();


            return 0;
        }
    }
}
