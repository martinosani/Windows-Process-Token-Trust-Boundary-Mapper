# Windows IPC Security (Inter-Process Communication)

This document explains **Windows Inter-Process Communication (IPC)** from a **Windows internals and security research** perspective.

The goal is not to catalog APIs. The goal is to provide a practical framework for understanding:

- where trust boundaries exist in real systems,
- how components cross them,
- what evidence you can collect to reason about reachability and authority,
- and why IPC design and authorization mistakes are a frequent root cause of Windows vulnerabilities.

In PTTBM, IPC is treated as a first-class trust-boundary surface. Where reachability or consumption is not evaluated, that is recorded as a **visibility boundary** (a data limitation), not as evidence that the surface is safe or absent.

---

## 1. Why IPC matters for Windows security

IPC is where privilege separation becomes operational.

Most modern Windows systems have a mix of low-trust and high-trust components. The lower-trust parts still need higher-trust work done (filesystem operations, device access, policy-enforced actions, privileged configuration, brokered capabilities). IPC is the mechanism that makes that delegation possible.

As a result, IPC is where:

- sandbox boundaries are enforced (or fail),
- privilege separation succeeds or collapses,
- confused-deputy vulnerabilities emerge,
- local privilege escalation (LPE) chains are built.

Many serious vulnerabilities are not “memory corruption in isolation”. They are cases where high-authority code performs privileged work based on lower-trust input.

---

## 2. IPC as a trust-boundary surface

### IPC is not just “communication”

Every IPC endpoint implicitly answers a set of security questions:

- Who can reach this endpoint?
- Under what identity does the server execute?
- What privileged actions can the server perform?
- How does the server authenticate the caller?
- How does the server authorize requests (per endpoint and per operation)?
- How does the server validate inputs (paths, object names, parameters)?
- Does it re-validate at the use site to reduce TOCTOU risk?

From a security perspective, an IPC interface is an API boundary with authority behind it.

If the authority of the server exceeds the trust of the caller, the IPC boundary is a privilege boundary.

---

### Trust transitions commonly mediated by IPC

Real Windows and Windows application architectures routinely cross boundaries via IPC:

- **Low integrity → Medium integrity** (browser sandboxes, renderers)
- **Medium integrity → High integrity** (UAC helpers, elevated components)
- **Medium/High integrity → SYSTEM** (services)
- **AppContainer → broker** (capability-mediated access)
- **Unprivileged user → service account**

In vulnerability research, these transitions matter more than absolute privilege levels.

---

## 3. IPC risk model: Reachability × Authority

A useful way to reason about IPC risk is as the product of two dimensions.

### 3.1 Reachability

Can a lower-trust subject reach the IPC endpoint at all?

Reachability is determined by:

- object DACLs,
- COM/RPC permissions,
- session boundaries,
- integrity level enforcement (MIC/UIPI),
- AppContainer capability checks,
- and “who can open/connect” semantics specific to the mechanism.

If the endpoint is not reachable, it is not part of that trust boundary.

### 3.2 Authority

What happens if the endpoint is reached?

Authority is driven by:

- the server token (integrity, elevation, privileges),
- impersonation semantics (server acts as itself vs acts as the client),
- and the operations performed on behalf of the caller.

High authority combined with reachability creates high-value attack surfaces.

---

## 4. Explicit IPC mechanisms (security-oriented view)

This section focuses on how IPC mechanisms fail, not just how they work.

---

### 4.1 Named Pipes

#### What they are

Named pipes are kernel-managed IPC objects that implement a client/server byte-stream or message-based model.

- Win32 path: `\\.\pipe\<Name>`
- NT object namespace: `\Device\NamedPipe\<Name>`

A named pipe is not just “a file-like handle”. There are two related but distinct layers you need to keep separate when building tools:

- **Namespace object (the name)**  
  The entry under `\Device\NamedPipe\<Name>` is a kernel object with a security descriptor (owner, DACL, label).  
  This is the layer you want for surface mapping, ACL analysis, and reachability hypotheses.

- **Server instances (the endpoints)**  
  A pipe name can have one or more server instances created by the server using `CreateNamedPipe`.  
  Clients connect to an available instance. Many runtime behaviors (including `PIPE_BUSY`) are about instance availability, not about whether the pipe name exists.

This distinction matters because you can often enumerate names, while metadata queries can fail or block depending on instance state and timing.

---

#### Why they matter

Named pipes are pervasive in Windows userland software and are commonly used to connect:

- a low-privilege UI/client component
- to a higher-privilege service or broker component

That makes named pipes one of the most common practical privilege boundaries in Windows applications.

In real-world LPE and broker-escape work, pipes show up repeatedly because the most common failures are design and authorization errors:

- A caller can reach an endpoint it was not meant to reach.
- The server performs privileged actions on untrusted input.
- Identity is not correctly bound to intent.

---

#### Security properties that matter (what to extract and why)

For each pipe you enumerate, the goal is to turn a **name** into evidence-backed reachability and trust hypotheses.

High-value metadata includes:

- **Owner**
  - Helps attribute the pipe to a principal (SYSTEM, service SID, per-user component).
  - Useful for prioritization: privileged owner often correlates with privileged behavior.

- **DACL (Discretionary ACL)**
  - Core reachability signal: who can open/connect.
  - Overly broad DACLs are common and often accidental.
  - In triage, focus on identities that represent lower-trust callers (e.g., `Users`, `Authenticated Users`, `Everyone`, low-priv service accounts).

- **SDDL (string form of the security descriptor)**
  - Stable representation for baselines, diffing, and reporting.
  - Allows comparisons across machines/builds without losing detail.

- **Mandatory Integrity Label (MIL)**
  - Adds MIC context (Low IL, AppContainer, etc.).
  - Often best-effort: retrieving it can require `ACCESS_SYSTEM_SECURITY` and the right privileges.
  - Missing MIL data is not evidence of safety; it may be a visibility limitation.

- **Name characteristics and scope**
  - Stable, service-like names often represent long-lived interfaces.
  - Random/GUID-like names often indicate ephemeral channels.
  - Session scoping matters; the surface can differ per session/user.

- **Operational state**
  - Pipes can exist while all instances are occupied during a query window.
  - A mapper should represent this explicitly rather than silently dropping results.

---

#### Common failure modes (design-level)

High-signal failure patterns seen in LPEs and broker escapes include:

- **Overly permissive DACL**: low-trust callers can reach a privileged endpoint.
- **Confused deputy**:
  - Server impersonates the client and performs privileged actions incorrectly, or
  - Server does not impersonate when it should, and treats requests as trusted.
- **Authorization not bound to identity**:
  - Server authenticates but does not authorize per operation.
  - Identity is checked once but not tied to the requested action/object.
- **Untrusted path/object handling**:
  - Client-controlled filesystem paths, registry paths, object names used without canonicalization.
  - TOCTOU when validation and use occur under different contexts or interpretations.
- **Protocol parsing mistakes**:
  - Length/format confusion, missing bounds checks, inconsistent framing across versions.
- **Instance/lifetime handling**:
  - Race windows, denial-of-service, or state confusion triggered by connect/disconnect patterns.

Named pipes are a common root of confused-deputy LPEs because they frequently bridge low-trust reachability to high-authority execution.

---

#### Named pipe extraction strategy (high-authority processes)

This section documents the current strategy implemented in WTBM to extract **named pipes associated with high-authority processes** and to enrich them with **stable identifiers** and **security metadata**.

The approach is handle-centric and is meant to work on live systems. It is explicit about failure modes: access denied, protected processes, transient objects, and blocking object queries are treated as normal conditions that must be handled.

---

##### Rationale: process-attributed inventory

WTBM is not trying to produce a global list under `\\.\pipe\*`. The primary question is:

> Which IPC endpoints are associated with a specific high-authority process at runtime?

To answer this, WTBM starts from the process and works outward through its handle table. This design is important for later correlation rules, because it gives you a concrete process-to-endpoint relationship rather than a global namespace snapshot.

---

##### Privilege model

The extractor attempts to enable `SeDebugPrivilege` at initialization time to improve visibility when duplicating and inspecting handles from other processes.

This reduces avoidable failures but does not guarantee full visibility (e.g., protected processes or PPL constraints).

---

##### High-level extraction pipeline

For each target PID, the extractor:

1. Enumerates all system handles and filters by the target PID.
2. Keeps only handles whose object type is `File`.
3. Duplicates each candidate handle into the current process.
4. Applies conservative access-mask and attribute filters.
5. Resolves the kernel object name with a strict timeout.
6. Classifies named pipe objects via the NT namespace (`\Device\NamedPipe\`).
7. Builds stable identifiers (NT path and Win32 path).
8. Retrieves the security descriptor **by handle**.
9. Deduplicates and merges results per pipe.

The output is a sorted list of `NamedPipeEndpoint` values keyed by the pipe NT path.

---

##### Handle enumeration and initial filtering

WTBM uses a system-wide handle snapshot and restricts it to a specific PID.

Only handles whose reported `ObjectType` is `File` are considered. This matches how named pipes appear at the handle level and avoids spending time on unrelated object types.

---

##### Handle duplication

WTBM duplicates each candidate handle into the current process using `DuplicateHandle` with `DUPLICATE_SAME_ACCESS`.

All subsequent queries (name and security) are performed on the duplicated handle. This keeps the logic local and avoids relying on remote handle operations.

---

##### Access-mask and attribute heuristics

Not all file handles are equally useful or safe to query. WTBM applies a conservative heuristic:

- require at least one of:
  - READ_CONTROL
  - SYNCHRONIZE
  - FILE_READ_DATA
  - FILE_READ_ATTRIBUTES
  - FILE_READ_EA

Additionally, handles flagged as `KernelHandle` or `ProtectClose` are skipped.

These checks are heuristics: they reduce the volume of low-value handles, but they are not a proof of safety.

---

##### Object name resolution with bounded execution

Resolving an object name via `NtQueryObject(ObjectNameInformation)` can block indefinitely for a minority of handles on real systems (often due to timing and kernel edge cases on volatile IPC endpoints).

WTBM treats object name resolution as best-effort and enforces bounded execution:

- the name query runs on a dedicated background thread,
- the caller waits a fixed time window (timeout),
- if the timeout is exceeded, that `(pid, handle)` pair is cached and skipped for the remainder of the run.

Two outcomes are handled explicitly:

- **Timeout**: skip and record that the handle is not observable within the configured budget.
- **Empty name**: skip; the object cannot be mapped to a named pipe path.

This design prevents a single pathological handle from stalling the entire extraction pass.

---

##### Named pipe identification via NT namespace

After successful name resolution, a handle is treated as a named pipe only if the kernel path starts with:

```
\Device\NamedPipe\
```

This check is explicit and avoids misclassifying other file-backed objects or device paths.

---

##### Stable pipe identity construction

For each named pipe, WTBM builds a `NamedPipeRef` that contains:

- `NtPath`: the full kernel path (e.g. `\Device\NamedPipe\LOCAL\example`)
- `Win32Path`: the corresponding Win32 path (`\\.\pipe\LOCAL\example`)
- `Name`: a display-safe identifier used only for output and logging

The relative pipe name is preserved exactly when constructing the Win32 path. Any normalization (for display purposes) is confined to the display `Name` so the tool does not fabricate non-existent pipe names.

---

##### Security descriptor retrieval (by handle)

WTBM retrieves security metadata using the duplicated handle rather than the pipe name.

Security-by-handle avoids additional name-resolution paths and is more robust in practice on volatile endpoints.

The extractor records:

- Owner SID
- Owner account name (best-effort resolution)
- Full SDDL string

If security retrieval fails, the error is stored alongside the endpoint instead of silently discarding it. That preserves evidence for later triage and makes visibility limitations explicit.

---

##### Deduplication and merge strategy

The stable identity of a pipe for mapping purposes is its NT path.

If multiple handles refer to the same pipe, WTBM merges endpoints by:

- preferring the instance with a complete security descriptor (no error and SDDL present),
- combining tags and metadata.

This reduces duplicate output while keeping the most informative observation.

---

##### Observability guarantees and limitations

This strategy provides:

- process-attributed named pipe inventory for high-authority processes,
- stable identifiers suitable for correlation rules,
- bounded execution in the presence of kernel edge cases.

It does not attempt to:

- prove client reachability from low/medium/AppContainer contexts,
- fully attribute server ownership beyond “this process held a handle to the pipe object”.

Those are deliberately deferred to later stages that consume this evidence.

---

##### Role in the overall research workflow

This extraction layer exists to produce evidence objects that subsequent rules can analyze for trust-boundary exposure.

Collection and interpretation are separated on purpose: the collector’s job is to gather reliable, structured observations; later logic decides which observations represent risk.

---

##### Vulnerability research workflow (how to use the extracted data)

###### Step 1: Triage for reachability

Start with the DACL:

- Identify principals representing lower-trust callers (`Users`, `Authenticated Users`, `Everyone`, broad groups).
- Look for broad allow ACEs on the pipe object.

This is the fastest way to identify “unexpected caller can reach server”.

###### Step 2: Attribute the endpoint

Use owner information and name patterns to form hypotheses:

- SYSTEM/service ownership often implies a privileged server.
- Stable naming is more likely to represent a long-lived interface worth deeper study.
- Random naming often indicates ephemeral broker channels; still relevant, but requires different collection tactics.

###### Step 3: Validate server behavior (beyond ACLs)

Reachability is only one side. The key questions are:

- Does the server impersonate? Under what conditions?
- Is authorization checked per operation?
- Are client-controlled paths/object names handled safely?
- Are privileged actions tied to identity and intent?

ACLs tell you who can talk. Vulnerabilities often lie in what the server does after it accepts input.

###### Step 4: Feed tooling improvements back into collection

If a high-value pipe is persistently busy or intermittently observable:

- increase retry window for that target,
- run multi-pass sampling,
- or observe during lower system activity.

For a research tool, it is better to report “busy or not observed” than to silently drop endpoints.

---

##### Representing extraction outcomes explicitly

For research correctness, the tool should not collapse all failures into “no data”.

Each pipe should have an explicit extraction outcome, for example:

- `Ok` – security descriptor retrieved and parsed
- `Busy` – pipe exists but all instances were busy during the observation window
- `Denied` – access denied under current token/privileges
- `Error` – unexpected API or parsing failure

Storing this state prevents misinterpretation and enables multi-pass aggregation, privilege-context comparison, and accurate reporting of visibility gaps.

---

##### Implementation notes (C# tool design)

To keep the tool reliable and research-friendly:

- Always store:
  - pipe name, NT path, and Win32 path,
  - owner SID + resolved name,
  - SDDL,
  - parsed DACL ACE list (keep raw access mask),
  - MIL if available,
  - query status (`ok`, `busy`, `denied`, `error`) + raw code/message.

- Implement bounded retries and make them configurable:
  - Win32: retries + `WaitNamedPipe` timeout
  - NT: retries + backoff
  - Multi-pass: number of passes + delay

- Keep trace output focused on:
  - which strategy path is used,
  - where it failed (open vs query vs parse),
  - whether failure is `busy`, `denied`, or other.

- Do not treat missing label data as failure. It is often a privilege/visibility limitation.

Named pipes are a common root of confused-deputy LPEs because they frequently bridge low-trust reachability to high-authority execution.

---

### 4.2 RPC (Remote Procedure Call)

#### What it is

RPC provides structured request/response IPC and is heavily used by Windows itself. It provides interface-based calls with marshalling, authentication, and multiple transports (often ALPC locally).

#### Why it matters

Many SYSTEM services and privileged helpers expose RPC endpoints. RPC is frequently the “official” call surface for privileged operations.

#### Security properties that matter

- Authentication level (who is authenticated, and with what guarantees)
- Authorization checks per method (not just endpoint-level)
- Identity binding between caller and request (authorization must match caller)
- Marshalling/unmarshalling correctness and structure complexity risk
- Legacy endpoints / compatibility paths that keep weaker semantics alive

#### Common failure modes

- Methods callable without adequate authorization
- Incorrect assumptions about caller identity (or identity persistence across calls)
- Parameter smuggling through optional/nested structures
- Legacy endpoints with overly broad access
- “Authenticated” treated as “authorized”
- Dangerous privileged actions reachable through benign-looking methods

RPC issues often look routine in code and severe in effect.

---

### 4.3 COM / DCOM

#### What it is

COM is an object activation and invocation system built on top of RPC. It supports:

- in-proc servers (DLL),
- out-of-proc servers (EXE),
- service-hosted COM servers,

and it relies heavily on registry configuration.

#### Why it matters

Many brokers and automation components are COM servers. COM frequently forms cross-integrity or cross-UAC boundaries, especially in desktop software and enterprise environments.

#### Security properties that matter

- Launch and access permissions
- Server identity (user, elevated, SYSTEM)
- Activation model (in-proc vs out-of-proc; affects isolation and trust)
- Registry-based configuration (security descriptors and class registration)
- Caller identity semantics (what identity the server sees, and how it uses it)

#### Common failure modes

- Privileged COM servers callable by low-trust callers
- Misconfigured activation permissions (too broad)
- Incorrect trust assumptions in broker-like COM servers
- “Same user” treated as “same trust” (ignores IL/UAC boundaries)
- Registry-based configuration misuse leading to redirection/hijack behaviors

COM issues are often design bugs rather than implementation bugs.

---

### 4.4 Shared Memory / Sections

#### What they are

Memory regions mapped into multiple processes via section objects (file mappings). Often used for performance-critical IPC and shared state.

#### Why they matter

Used for performance-critical IPC in:

- browsers
- antivirus engines
- graphics subsystems

Shared memory becomes dangerous when a lower-trust process can write and a higher-trust process consumes that data as trusted input.

#### Security properties that matter

- Who can write (DACL and handle inheritance)
- Validation before use (structure integrity, bounds, invariants)
- Lifetime and synchronization semantics (ownership, locking, versioning)
- Concurrency assumptions (race behavior becomes the bug)

#### Common failure modes

- Writable shared memory consumed as trusted input
- Structure confusion or version mismatches
- Race conditions amplified by shared state
- Partial validation (header checked, body trusted)
- Shared-memory “signals” treated as authorization

Shared memory is rarely the root cause alone, but it often amplifies other failures.

---

### 4.5 UI-based IPC (Windows messages, UIPI)

#### What it is

GUI processes communicate via window messages and related UI mechanisms (handles, message loops, accessibility interactions).

#### Why it matters

Historically this was a rich attack surface (“shatter attacks”) where low-privilege senders could manipulate privileged GUI processes.

#### Modern constraints

- Mandatory Integrity Control (MIC)
- User Interface Privilege Isolation (UIPI)

These reduce cross-trust message flows significantly.

#### Remaining risks

- UIAccess tokens (deliberate bypass of UIPI constraints)
- Allowed message types with unsafe handlers
- Indirect UI-to-privileged execution flows
- Accessibility frameworks and privileged UI bridges
- Legacy UI components that assume “local UI = trusted”

UI IPC is less common today but still relevant in specific contexts.

---

## 5. Indirect IPC and Delegation Channels

Windows IPC is not limited to explicit transports (pipes/RPC/COM). Many real-world boundaries are crossed through indirect delegation channels, where a lower-trust component influences a higher-trust component by writing state into a shared substrate.

These channels matter because they frequently produce:

- confused-deputy conditions,
- canonicalization mistakes,
- TOCTOU races,
- object squatting attacks.

The core model is the same as classic IPC:

> A lower-trust actor supplies data; a higher-trust actor consumes it and performs privileged work.

---

### 5.1 Filesystem-based Handoff

#### What it is

Filesystem handoff occurs when one component writes a file (or a path) and another later reads, parses, moves, or executes it. This can be intentional (staging directory) or accidental (cache, temp artifacts, logs used as input).

It functions as IPC because the filesystem is the transport.

#### Why it matters for security

Filesystem handoff intersects directly with privileged operations:

- writing into protected locations,
- replacing binaries/configuration read by privileged services,
- loading libraries/plugins,
- software updates,
- scheduled tasks and helper executables.

Even without a classic “exploit”, unsafe file consumption can yield privileged behavior.

#### Common insecure patterns

1) Writable staging locations used by higher-trust consumers  
   Examples: `C:\Temp`, `%TEMP%`, `%LOCALAPPDATA%`, `%APPDATA%`, `%ProgramData%` (permission-dependent)

2) Path canonicalization mismatches  
   String form vs actual target mismatch (`\\?\`, short/long paths, UNC normalization)

3) TOCTOU (time-of-check to time-of-use)  
   Check happens before use; attacker switches target in the gap

4) Reparse point / junction / symlink / mount point abuse  
   Privileged process follows reparse points into unintended targets

5) Hardlink abuse  
   Privileged writer overwrites protected file through attacker-controlled link

6) Unsafe DLL/plugin loading from user-writable locations  
   Search paths including user-writable folders; config-driven load without allowlisting

#### Practical research workflow

1) Identify all file inputs consumed (configs, caches, assets, update packages, plugins, temp artifacts)
2) Determine origin: can a lower-trust process write them?
3) Validate enforcement at use sites: canonicalize and re-check permissions
4) Look for race windows: creation then privileged action is a classic TOCTOU shape
5) Pay attention to token context: backup/restore semantics can bypass DACL expectations

#### How this maps to token/trust signals

Filesystem handoff is higher value when the consumer runs with:

- High/System integrity
- elevation semantics (ElevationType=Full)
- high-impact privileges (`SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeManageVolumePrivilege`)
- broker/service identity signals (SYSTEM/service accounts)

These signals do not prove a bug, but they prioritize investigation.

---

### 5.2 Registry-based Handoff

#### What it is

Registry handoff occurs when a lower-trust component writes data to a registry key and a higher-trust component later reads and acts on it.

This is common because the registry is global (within ACL constraints), persistent, and heavily used for configuration and activation.

#### Why it matters for security

Registry handoffs frequently show up in:

- COM activation and configuration
- file/protocol handlers
- per-user configuration consumed by elevated helpers
- “recent file / last used path” state crossing boundaries

Registry issues are often logic/design failures.

#### Common insecure patterns

1) HKCU data trusted by elevated/SYSTEM components (“same user” ≠ “same trust”)
2) COM hijack primitives via mis-scoped write permissions
3) Handler/shell integration misuse (open commands / protocol handlers)
4) Policy/config injection (assumes registry is admin-only)
5) Registry pointing to filesystem targets (registry + filesystem TOCTOU chains)

#### Practical research workflow

1) Identify keys/hives read (HKLM vs HKCU; ACLs matter more)
2) Determine effective write access
3) Track how values are used (paths, command lines, DLL names, CLSIDs, endpoints)
4) Validate canonicalization and use-site re-validation

#### How this maps to token/trust signals

Registry handoff becomes high value when you see:

- High/System IL processes that are interactive or broker-like
- UAC boundary markers (elevation type, linked token)
- COM usage likelihood
- components acting on behalf of other processes

Registry often acts as a control plane: writable control plane + privileged consumer = attack surface.

---

### 5.3 Named Object Namespace Abuse

#### What it is

Windows exposes a kernel object namespace used by IPC and coordination:

- Mutexes, Events, Semaphores
- Section objects (shared memory)
- Named pipes (as objects)
- ALPC ports (advanced)

Objects may exist in namespaces such as:

- `Global\...`
- `Local\...`
- `\BaseNamedObjects\...`

This becomes a delegation channel when a higher-trust process assumes:

- a name is unique,
- an existing object is trusted,
- or default DACLs are safe.

#### Why it matters for security

Named objects become boundary failures because:

- names can be pre-created (“squatted”),
- ACLs can be weak or misapplied,
- global/session namespaces create unintended reachability,
- synchronization/state objects are treated as authenticity signals.

#### Common insecure patterns

1) Object squatting / pre-creation  
   Attacker creates expected object before privileged component; privileged component opens attacker-controlled object.

2) Weak DACL on named objects  
   Low-trust callers can signal events, write shared memory, or disrupt coordination.

3) Cross-session surprises  
   `Global\*` objects visible across sessions; assumptions about isolation break.

4) Confused coordination between components  
   Low-trust side controls synchronization/state consumed by high-trust side.

5) Shared memory poisoning  
   High-trust consumer reads shared memory as trusted and performs privileged work.

#### Practical research workflow

1) Identify named objects used by the target (runtime observation, strings, docs)
2) Check create/open semantics and DACL correctness
3) Assess namespace scope (Global vs session-local)
4) Look for privileged follow-on actions driven by object state/data

#### How this maps to token/trust signals

This class becomes a strong hypothesis when:

- high-trust processes coordinate with lower-trust peers (broker models),
- session boundaries differ (services vs interactive),
- shared memory/synchronization is likely,
- privileges imply high-impact actions if misled.

---

## 6. The confused deputy problem (central failure class)

Most IPC-related vulnerabilities are confused-deputy failures:

- a high-trust component accepts input from a lower-trust caller,
- then performs privileged actions based on that input,
- without correctly binding authorization to identity and intent.

Common patterns include:

- incorrect impersonation usage,
- path traversal and TOCTOU issues,
- identity vs privilege confusion (UAC),
- “same user” treated as “same trust”.

This is primarily a logic failure, not an IPC mechanism failure.

---

## 7. IPC in sandbox and broker architectures

Modern Windows security relies heavily on broker designs:

1) Low-trust component requests an operation
2) Broker validates identity/capability and parameters
3) Broker performs the operation with higher authority

The broker is therefore the security boundary. If broker validation fails, the sandbox fails.

---

## 8. IPC enumeration in tooling (PTTBM perspective)

A mapper tool cannot “solve IPC”, but it can collect evidence.

### Feasible enrichment steps

- Enumerate named pipe namespaces
- Identify IPC-related modules (RPC/COM indicators)
- Correlate processes by session, logon, and ancestry
- Detect likely broker neighborhoods

### Advanced steps (future)

- Map pipes to owning processes
- Enumerate active RPC endpoints
- Enumerate active COM servers
- ETW-based runtime surface discovery

Each step increases confidence, not certainty.

---

## 9. Confidence and visibility boundaries

Without direct reachability validation:

- IPC findings are hypotheses,
- confidence must be explicit,
- assumptions must be documented.

This matters for research credibility and for avoiding false conclusions from incomplete data.

---

## 10. Key takeaway

IPC is where authority meets reachability.

- tokens describe what a process can do,
- IPC determines who can ask it to do it.

Many vulnerabilities arise when higher-trust components act on lower-trust input across IPC boundaries without adequate validation and authorization.
