using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Rules.Abstractions;
using WTBM.Rules.Markers;

namespace WTBM.Rules.Engine
{
    internal static class RuleRegistry
    {
        // Canonical rule IDs used by CLI (stable contract)
        // Value: factory to create the rule instance on demand
        private static readonly IReadOnlyDictionary<string, Func<IRule>> _factories =
            new Dictionary<string, Func<IRule>>(StringComparer.OrdinalIgnoreCase)
            {
                // Markers
                ["HighImpactPrivilegeProcesses"] = () => new HighImpactPrivilegeProcessesRule(),

                // Future:
                // ["legacy-sandbox"] = () => new LegacySandboxTokenRule(),
                // ["uiaccess"] = () => new UiAccessEnabledRule(),
            };

        /// <summary>
        /// Returns canonical rule IDs supported by this build.
        /// </summary>
        public static IReadOnlyList<string> ListRuleIds()
            => _factories.Keys.OrderBy(k => k).ToArray();

        /// <summary>
        /// Create the default rule set (used when user does not specify any rule).
        /// </summary>
        public static IReadOnlyList<IRule> CreateDefault()
            => new IRule[]
            {
                // Keep this minimal and intentional.
                new HighImpactPrivilegeProcessesRule(),
            };

        /// <summary>
        /// Create rules requested by CLI. Supports comma-separated list or multiple tokens.
        /// Example: "highimpact,uiaccess"
        /// </summary>
        public static IReadOnlyList<IRule> CreateFromSelection(string selection)
        {
            if (string.IsNullOrWhiteSpace(selection))
                return CreateDefault();

            var tokens = selection
                .Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim())
                .Where(s => s.Length > 0)
                .ToArray();

            return CreateFromIds(tokens);
        }

        public static IReadOnlyList<IRule> CreateFromIds(IEnumerable<string> ruleIds)
        {
            var list = new List<IRule>();
            var unknown = new List<string>();

            foreach (var id in ruleIds)
            {
                if (_factories.TryGetValue(id, out var factory))
                {
                    list.Add(factory());
                }
                else
                {
                    unknown.Add(id);
                }
            }

            if (unknown.Count > 0)
            {
                var supported = string.Join(", ", ListRuleIds());
                throw new ArgumentException(
                    $"Unknown rule(s): {string.Join(", ", unknown)}. Supported: {supported}");
            }

            return list;
        }
    }
}