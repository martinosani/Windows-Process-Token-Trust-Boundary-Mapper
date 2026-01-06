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
                Description = "Enumerates processes and associated token information and prints a flat summary list."
            };

            var ruleOption = new Option<string>("rule", "--rule", "-r")
            {
                Description = "Selects which rule set to execute against the collected process snapshots."
            };

            var processPidOption = new Option<int>("process-pid", "--process-pid", "-pid")
            {
                Description = "Restricts enumeration and rule evaluation to a specific process ID.",
                DefaultValueFactory = _ => -1
            };

            var ruleExplainOption = new Option<bool>("rule-explain", "--rule-explain")
            {
                Description = "Prints a detailed explanation for each rule finding associated with the process specified via --process-pid."
            };

            var namedPipesOption = new Option<bool>("named-pipes", "--named-pipes")
            {
                Description = "Enumerates Named Pipes associated with the high authority processes retrieved."
            };

            var topOption = new Option<int?>("top", "--top")
            {
                Description = "Limits the number of process snapshots printed during enumeration."
            };

            var verboseOption = new Option<bool>("verbose", "--verbose", "-v")
            {
                Description = "Verbose output"
            };

            var pauseOption = new Option<bool>("pause", "--pause")
            {
                Description = "Enable the interactive pause at the end of execution.",
                DefaultValueFactory = _ => false
            };

            processCommand.Add(enumerationOption);
            processCommand.Add(ruleOption);
            processCommand.Add(processPidOption);
            processCommand.Add(ruleExplainOption);
            processCommand.Add(namedPipesOption);
            processCommand.Add(topOption);
            processCommand.Add(verboseOption);
            processCommand.Add(pauseOption);

            processCommand.SetAction(result =>
            {
                bool enumeration = result.GetValue(enumerationOption);
                string? rule = result.GetValue(ruleOption);
                int? processPid = result.GetValue(processPidOption);
                int? top = result.GetValue(topOption);
                bool verbose = result.GetValue(verboseOption);
                bool pause = result.GetValue(pauseOption);
                bool explainRule = result.GetValue(ruleExplainOption);
                bool getNamedPipes = result.GetValue(namedPipesOption);

                var processes = new ProcessEnumerator().Enumerate();
                var tokenCollector = new TokenCollector();

                // Logger.LogDebug(String.Format("enumeration={0} - rule={1} - processPid={2}", enumeration, rule, processPid));

                if (processPid != null && processPid > -1)
                {
                    var process = processes.FirstOrDefault(p => p.Pid == processPid);

                    if (process == null)
                        throw new ArgumentException($"Process with PID {processPid} not found.");

                    processes = new List<ProcessRecord>() { process };
                }

                var processSnapshots = processes.Select(p => tokenCollector.TryCollect(p)).ToList();

                var namedPipes = new List<NamedPipeEndpoint>();

                if (getNamedPipes)
                {
                    var npe = new NamedPipeExtractor();

                    foreach (var process in processes)
                    {
                        var pipes = npe.GetNamedPipesFromProcessHandles(process.Pid);
                        namedPipes.AddRange(pipes);
                    }                    
                }

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
                    var findings = RuleEngine.EvaluateAll(processSnapshots, namedPipes, rules);

                    var max = top.HasValue ? top.Value : -1;
                    FindingsConsoleWriter.WriteSummary(findings, processSnapshots, max);

                    if (explainRule && processes.Count == 1)
                    {
                        foreach (var finding in findings)
                        {
                            FindingsConsoleWriter.Explain(finding, processSnapshots);
                        }
                    }
                }

                if (pause)
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
