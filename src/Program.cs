using System;
using System.Collections;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;
using WTBM.Collectors;
using WTBM.Collectors.IPC;
using WTBM.Domain.IPC;
using WTBM.Domain.Processes;
using WTBM.Output.Terminal;
using WTBM.Renders.OutputWriter;
using WTBM.Rules.Engine;

namespace WTBM
{
    internal static class Program
    {
        private enum RunMode { Process, Pipes }

        static async Task<int> Main(string[] args)
        {
            Logger.LogDebug("WTBM - Windows Trust Boundary Mapper");

            return runMainLoop(args);
        }

        private static int runMainLoop(string[] args)
        {
            var root = new RootCommand("WTBM - Windows Trust Boundary Mapper");
            
            var processCommand = new Command("process", "Enumerate processes and run rules");

            var enumerationOption = new Option<bool>("enumeration", "--enumeration")
            {
                Description = "Enumerate processes and associated token info; print a flat list"
            };

            var ruleOption = new Option<string>("rule", "--rule", "-r")
            {
                Description = "Rule to execute (highimpact, default)"
            };

            var processPidOption = new Option<int>("process-pid", "--process-pid", "-pid")
            {
                Description = "Process PID",
                DefaultValueFactory = _ => -1
            };

            var ruleExplainOption = new Option<bool>("rule-explain", "--rule-explain")
            {
                Description = "Explain the rule for the process with PID in <process-pid>"
            };

            var topOption = new Option<int?>("top", "--top")
            {
                Description = "Show only top N findings"
            };

            var verboseOption = new Option<bool>("verbose", "--verbose", "-v")
            {
                Description = "Verbose output"
            };

            var noPauseOption = new Option<bool>("noPause", "--no-pause")
            {
                Description = "Do not pause at the end"
            };

            processCommand.Add(enumerationOption);
            processCommand.Add(ruleOption);
            processCommand.Add(processPidOption);
            processCommand.Add(ruleExplainOption);
            processCommand.Add(topOption);
            processCommand.Add(verboseOption);
            processCommand.Add(noPauseOption);

            processCommand.SetAction(result =>
            {
                bool enumeration = result.GetValue(enumerationOption);
                string? rule = result.GetValue(ruleOption);
                int? processPid = result.GetValue(processPidOption);
                int? top = result.GetValue(topOption);
                bool verbose = result.GetValue(verboseOption);
                bool noPause = result.GetValue(noPauseOption);
                bool explainRule = result.GetValue(ruleExplainOption);

                var processes = new ProcessEnumerator().Enumerate();
                var tokenCollector = new TokenCollector();

                Logger.LogDebug(String.Format("enumeration={0} - rule={1} - processPid={2}",
                    enumeration, rule, processPid));

                if (processPid != null && processPid > -1)
                {
                    var process = processes.FirstOrDefault(p => p.Pid == processPid);

                    if (process == null)
                        throw new ArgumentException($"Process with PID {processPid} not found.");

                    processes = new List<ProcessRecord>() { process };
                }

                var processSnapshots = processes.Select(p => tokenCollector.TryCollect(p)).ToList();

                if (enumeration)
                {
                    if (top.HasValue && top.Value > 0)
                    {
                        processSnapshots = processSnapshots.Take(top.Value).ToList();
                    }

                    ProcessSnapshotConsoleSummaryWriter.WriteSummary(processSnapshots);
                }

                if (!String.IsNullOrEmpty(rule))
                {
                    var rules = RuleRegistry.CreateFromSelection(rule);
                    var findings = RuleEngine.EvaluateAll(processSnapshots, Array.Empty<NamedPipeEndpoint>(), rules);

                    var max = top.HasValue ? top.Value : -1;
                    FindingsConsoleWriter.WriteSummary(findings, processSnapshots, max);

                    if (explainRule && findings.Count > 0)
                    {
                        FindingsConsoleWriter.Explain(findings[0], processSnapshots);
                    }
                }

                if (!noPause)
                {
                    Console.WriteLine();
                    Console.WriteLine("Press ENTER to exit ...");
                    Console.ReadLine();
                }

            });

            root.Add(processCommand);
            return root.Parse(args).Invoke();
        }
    }

   
}
