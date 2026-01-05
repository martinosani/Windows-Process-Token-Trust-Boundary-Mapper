using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Rules.Abstractions;
using WTBM.Rules.Markers;

namespace WTBM.Rules.Engine
{
    internal static class DefaultRuleSet
    {
        public static IReadOnlyList<IRule> Create()
            => new IRule[]
            {
                // Markers
                new HighImpactPrivilegeProcessesRule(),


                /*
                // Sandbox / boundary states
                new LegacySandboxTokenRule(),
                // Trust boundary asymmetry
                //new HighIntegrityInteractiveRule(),
                //new SystemInInteractiveSessionRule(),

                // UAC-related boundary markers
                //new UiAccessEnabledRule(),
                //new LinkedTokenPresentRule(),

                // Token complexity signals
                //new ImpersonationTokenRule(),
                //new SessionMismatchRule(),

                // Privilege leverage indicator

                // Visibility boundaries
                //new VisibilityBoundaryRule()
                */
            };
    }
}
