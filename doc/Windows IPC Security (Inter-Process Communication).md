# Windows IPC Security (Inter-Process Communication)

This document explains **Windows Inter-Process Communication (IPC)** from a **Windows Internals and security research** perspective.

The goal is not to catalog APIs, but to provide a **mental and analytical framework** for understanding **where trust boundaries actually exist**, how OS and application components cross them, and why IPC is one of the most common roots of real-world Windows vulnerabilities.

In PTTBM, IPC is treated as a **first-class trust-boundary surface**.  
Where IPC reachability/consumption is not evaluated, this is explicitly treated as a **visibility boundary**, not as evidence that the surface does not exist.

---

## 1. Why IPC matters for Windows security

IPC is where Windows security architecture becomes concrete.

At a high level, most modern Windows systems are built around the idea that:
- **low-trust components exist**
- **high-trust components exist**
- lower-trust code must request higher-trust work indirectly

IPC is the mechanism that makes this delegation possible.

As a result, IPC is where:
- sandbox boundaries are enforced (or fail),
- privilege separation succeeds or collapses,
- confused-deputy vulnerabilities emerge,
- local privilege escalation chains are built.

Many severe Windows vulnerabilities are not about memory corruption in isolation, but about **high-trust code acting on lower-trust input**.

---

## 2. IPC as a trust-boundary surface

### IPC is not just “communication”

Every IPC endpoint implicitly answers security questions:

- Who is allowed to reach this endpoint?
- Under what identity does the server execute?
- What privileged actions can the server perform?
- How does the server authenticate and authorize the caller?
- How does the server validate the request (paths, object names, parameters)?
- Does the server re-validate at the use site to prevent TOCTOU?

From a security perspective, an IPC interface is an **API boundary with authority behind it**.

If the authority of the server exceeds the trust of the caller, the IPC boundary becomes a **privilege boundary**.

---

### Trust transitions commonly mediated by IPC

Real-world Windows designs frequently rely on IPC to cross these boundaries:

- **Low Integrity → Medium Integrity** (browser sandboxes, renderers)
- **Medium Integrity → High Integrity** (UAC helpers, elevated components)
- **Medium/High Integrity → SYSTEM** (services)
- **AppContainer → broker** (capability-mediated access)
- **Unprivileged user → service account**

In vulnerability research, these transitions matter more than absolute privilege levels.

---

## 3. IPC risk model: Reachability × Authority

IPC risk can be modeled as the combination of two dimensions.

### 3.1 Reachability

Can a lower-trust subject reach the IPC endpoint at all?

Determined by:
- object DACLs,
- COM/RPC permissions,
- session boundaries,
- integrity level enforcement (MIC/UIPI),
- AppContainer capability checks,
- and “who can open or connect” semantics.

If the endpoint is not reachable, it is not part of that boundary.

### 3.2 Authority

What happens if the endpoint is reached?

Authority is defined by:
- server token (integrity, elevation, privileges),
- impersonation semantics (whether the server acts as itself or as the client),
- and the operations performed on behalf of the caller.

High authority combined with reachability creates high-risk surfaces.

---

## 4. Explicit IPC mechanisms (security-oriented view)

This section focuses on **how IPC mechanisms fail**, not just how they work.

---

### 4.1 Named Pipes

#### What they are
Named pipes are kernel-managed IPC objects that implement a client/server byte-stream or message-based communication model.  
They are exposed to userland via the Win32 path `\\.\pipe\<Name>`. Internally, they exist as objects under the NT object namespace as `\Device\NamedPipe\<Name>`.

A named pipe is not just "a file-like handle". It has two related but distinct aspects:

- **Namespace object (the name)**  
  The entry under `\Device\NamedPipe\<Name>` is a kernel object with a security descriptor (owner, DACL, label).  
  This is what you want when you do surface mapping and access control analysis.

- **Server instances (the endpoints)**  
  A pipe name can have one or more server instances created by the server using `CreateNamedPipe`.  
  Clients connect to an available instance. Many behaviors you observe (including `PIPE_BUSY`) are about instance availability, not about the absence of the name.

This distinction matters for tooling and research because you can often enumerate names, but querying metadata may be blocked by runtime instance state.

---

#### Why they matter
Named pipes are pervasive in Windows userland software and are often used to connect:
- a low-privilege UI or client component
- to a higher-privilege service or broker component

That makes named pipes one of the most common practical privilege boundaries in Windows applications.

In vulnerability research, pipes show up repeatedly because the most common failures are *design and authorization errors*, not complex memory corruption:
- A caller is able to reach an endpoint it was not meant to reach.
- The server performs privileged actions based on untrusted inputs.
- Identity is not correctly bound to intent.

---

#### Security properties that matter (what to extract and why)
For each pipe you enumerate, the goal is to turn a **name** into an evidence-backed **reachability and trust hypothesis**.

The highest-value metadata is:

- **Owner**
  - Helps attribute the pipe to a principal (SYSTEM, service SID, per-user component).
  - Useful for prioritization: privileged owner often correlates with privileged behavior.

- **DACL (Discretionary ACL)**
  - Core reachability signal: who can open/connect.  
  - Overly broad DACLs are common and are often accidental.
  - In triage, focus on identities that represent lower-trust callers (e.g., `Users`, `Authenticated Users`, `Everyone`, low-priv service accounts).

- **SDDL (string form of the SD)**
  - Stable representation: useful for baselines, diffing, and reporting.
  - Lets you compare configurations across machines/builds without losing detail.

- **Mandatory Integrity Label (MIL)**
  - Adds MIC context (Low IL, AppContainer, etc.).
  - Often best-effort: retrieving it can require `ACCESS_SYSTEM_SECURITY` and the right privileges.
  - Missing MIL data is not evidence of safety; it may be a visibility limitation.

- **Name characteristics and scope**
  - Stable service-like names often represent long-lived interfaces.
  - Random/GUID-like names often indicate ephemeral broker channels.
  - Session scoping matters for multi-session systems; a pipe surface may be different per session/user.

- **Operational state**
  - Some pipes exist but will appear "busy" during the query window due to all instances being occupied.
  - A correct mapper must represent this state explicitly.

---

#### Common failure modes (design-level)
Common high-value failure patterns seen in real-world LPEs and broker escapes:

- **Overly permissive DACL**: low-trust callers can reach a privileged endpoint.
- **Confused deputy**:
  - Server impersonates client and performs privileged actions incorrectly, or
  - Server does not impersonate when it should, and treats requests as trusted.
- **Authorization not bound to identity**:
  - Server authenticates but does not authorize per-operation.
  - Identity is checked once but not tied to the requested action or object.
- **Untrusted path/object handling**:
  - Client-controlled filesystem paths, registry paths, object names used without canonicalization.
  - TOCTOU when validation and use occur in different contexts or with different path interpretations.
- **Protocol parsing mistakes**:
  - Length/format confusion, missing bounds checks, inconsistent framing across versions.
- **Instance/lifetime handling**:
  - Race windows, denial-of-service, or state confusion triggered by repeated connects/disconnects.

**Named pipes are one of the most common roots of confused-deputy LPEs.**

---

#### Named pipe extraction strategy (high-authority processes)

This section documents the current strategy implemented in WTBM to extract **named pipes associated with high-authority processes** and to enrich them with **stable identifiers** and **security metadata**.

The approach is intentionally low-level and handle-centric. It is designed for research correctness on live Windows systems, where race conditions, protected processes, and kernel edge cases are expected and must be handled explicitly.

---

##### Rationale: process-attributed inventory

WTBM is not interested in producing a global list of visible pipes under `\\.\pipe\*`.
The primary research question is instead:

> Which IPC endpoints are actually associated with a specific high-authority process at runtime?

To answer this, the extractor starts from the process and works outward through its handle table, rather than starting from the global pipe namespace.

This design choice allows later correlation rules to reason about **trust boundaries** in terms of concrete process-to-endpoint relationships.

---

##### Privilege model

The extractor attempts to enable `SeDebugPrivilege` at initialization time in order to:

- duplicate handles from other processes,
- inspect metadata of objects owned by higher-privilege processes.

This step reduces avoidable access failures but does not guarantee full visibility (e.g. protected or PPL processes may still restrict access).

---

##### High-level extraction pipeline

For each target process ID, the extractor performs the following steps:

1. Enumerate all system handles and filter by the target PID.
2. Keep only handles whose object type is `File`.
3. Duplicate each candidate handle into the current process.
4. Apply conservative access-mask and attribute filters.
5. Resolve the kernel object name with a strict timeout.
6. Identify named pipe objects via the NT namespace.
7. Build stable pipe identifiers (NT path and Win32 path).
8. Retrieve the security descriptor **by handle**.
9. Deduplicate and merge results per pipe.

The final output is a sorted list of `NamedPipeEndpoint` objects keyed by the pipe NT path.

---

##### Handle enumeration and initial filtering

WTBM uses a system-wide handle snapshot and restricts it to a specific process ID.

Only handles whose `ObjectType` is reported as `File` are considered. Named pipes are exposed as file objects at the handle level, so this filter removes the majority of unrelated handles early.

---

##### Handle duplication

To query object metadata safely from user space, each candidate handle is duplicated into the current process using `DuplicateHandle` with `DUPLICATE_SAME_ACCESS`.

All subsequent queries (name and security) operate on the duplicated handle, not on the original remote handle.

---

##### Access-mask and attribute heuristics

Not all file handles are equally useful or stable to query. The extractor applies a conservative heuristic:

- at least one of the following access rights must be present:
  - READ_CONTROL
  - SYNCHRONIZE
  - FILE_READ_DATA
  - FILE_READ_ATTRIBUTES
  - FILE_READ_EA

Additionally, handles flagged as `KernelHandle` or `ProtectClose` are skipped.

These checks do not guarantee safety, but they significantly reduce the number of low-value or problematic handles queried downstream.

---

##### Object name resolution with bounded execution

Resolving an object name via `NtQueryObject(ObjectNameInformation)` can block indefinitely for certain IPC endpoints, especially high-churn named pipes used by modern frameworks.

To prevent a single pathological handle from stalling the entire extraction, WTBM resolves object names using a dedicated background thread with a fixed timeout.

Key characteristics:

- The name query is allowed to run for a bounded time window.
- If the timeout is exceeded, the handle is skipped.
- A per-run cache tracks `(pid, handle)` pairs that have already timed out to avoid repeated stalls.

If the query completes but returns an empty name, the handle is also skipped.

This design treats object name resolution as **best-effort** and explicitly prioritizes extractor stability.

---

##### Named pipe identification via NT namespace

After successful name resolution, a handle is classified as a named pipe only if its kernel path starts with:

```
\Device\NamedPipe\
```

This check is explicit and avoids misclassifying other file-backed objects or device paths.

---

##### Stable pipe identity construction

For each named pipe, the extractor builds a `NamedPipeRef` containing:

- `NtPath`: the full kernel path (e.g. `\Device\NamedPipe\LOCAL\example`)
- `Win32Path`: the corresponding Win32 path (`\\.\pipe\LOCAL\example`)
- `Name`: a display-safe identifier used only for output and logging

The relative pipe name is preserved **exactly** when constructing the Win32 path.
Any normalization (such as replacing path separators) is limited to the display name to avoid generating non-existent pipe paths.

---

##### Security descriptor retrieval (by handle)

Security metadata is retrieved using the duplicated handle, not the pipe name.

Querying security **by handle** avoids additional name-resolution paths and has proven more robust on volatile or short-lived IPC endpoints.

The extractor records:

- Owner SID
- Owner account name (best-effort)
- Full SDDL representation

If security retrieval fails, the error is stored alongside the pipe rather than silently discarding the endpoint.

---

##### Deduplication and merge strategy

The stable identity of a pipe is its NT path.

When multiple handles reference the same pipe, results are merged using the following rule:

- prefer the instance with a complete and successfully retrieved security descriptor,
- union tags and metadata where applicable.

This avoids duplicate output while preserving the most informative observation.

---

##### Observability guarantees and limitations

This strategy provides:

- process-attributed named pipe inventory for high-authority processes,
- stable identifiers suitable for correlation rules,
- bounded execution even in the presence of kernel edge cases.

It does not attempt to:

- prove client reachability from lower integrity levels,
- fully attribute server ownership beyond observed handle association.

Those aspects are intentionally deferred to later analysis stages that consume the collected evidence.

---

##### Role in the overall research workflow

This extraction layer is designed to produce high-fidelity evidence objects that later rules can analyze for trust-boundary exposure.

By separating *collection* from *interpretation*, WTBM keeps the system understandable, auditable, and adaptable as the research evolves.

---

##### Vulnerability research workflow (how to use the extracted data)

###### Step 1: Triage for reachability
Start with the DACL:
- Identify principals representing low-trust callers (`Users`, `Authenticated Users`, `Everyone`, broad groups).
- Look for overly broad allow ACEs on the pipe object.

This is the fastest way to identify “unexpected caller can reach server”.

###### Step 2: Attribute the endpoint
Use owner information and name patterns to form hypotheses:
- Service/SYSTEM ownership → likely privileged server.
- Stable naming → more likely long-lived interface worth deeper study.
- Random naming → often ephemeral broker channel; may still be relevant but requires different collection tactics.

###### Step 3: Validate server behavior (beyond ACLs)
ACL reachability is only one side. The core research questions are:
- Does the server impersonate? At what level?
- Is authorization checked per operation?
- Are client-controlled paths/object names used safely?
- Are privileged actions performed with correct identity binding?

The pipe SD tells you who can talk. The vulnerability usually lies in what happens after the server accepts input.

###### Step 4: Feed tooling improvements back into collection
If a high-value pipe is persistently busy:
- increase retry window for that specific target,
- run multi-pass sampling,
- or schedule observation when the system is less active.

For a research tool, it is better to report “busy, not observed” than to silently drop it.

---

##### Representing extraction outcomes explicitly
For research correctness, the tool should not collapse all failures into “no data”.

Each pipe should have an explicit extraction outcome, for example:
- `Ok` – security descriptor retrieved and parsed
- `Busy` – pipe exists but all instances were busy during the observation window
- `Denied` – access denied under current token/privileges
- `Error` – unexpected API or parsing failure

Storing this state explicitly prevents misinterpretation and allows:
- multi-pass aggregation,
- privilege-context comparison,
- accurate reporting of visibility gaps.

---

##### Implementation notes (C# tool design)
To keep the tool reliable and research-friendly:

- Always store:
  - pipe name, NT path and Win32 path,
  - owner SID + resolved name,
  - SDDL,
  - parsed DACL ACE list (and keep raw access mask),
  - MIL if available,
  - query status (`ok`, `busy`, `denied`, `error`) + raw code and message.

- Implement bounded retries and make them configurable:
  - Win32: retries + `WaitNamedPipe` timeout
  - NT: retries + backoff
  - Multi-pass: number of passes + delay

- Keep trace output focused on:
  - which strategy path is used,
  - where it failed (open vs query vs parse),
  - whether failure is `busy`, `denied`, or other.

- Do not treat missing label as failure. It is commonly a privilege/visibility limitation.

**Named pipes are one of the most common roots of confused-deputy LPEs because they frequently bridge low-trust reachability to high-authority execution.**

---

### 4.2 RPC (Remote Procedure Call)

#### What it is
RPC provides structured request/response IPC, heavily used by Windows itself.  
It provides interface-based calls with marshalling, authentication, and multiple transports (often ALPC locally).

#### Why it matters
Many SYSTEM services and privileged helpers expose RPC endpoints.  
RPC often represents the “official” call surface for privileged operations.

#### Security properties that matter
- **Authentication level** (who is authenticated, and with what guarantees)
- **Authorization checks per method** (not just endpoint-level)
- **Identity binding between caller and request** (authorization must match actual caller)
- **Marshalling/unmarshalling correctness** and structure complexity risk
- **Legacy endpoints / compatibility paths** that keep weak semantics alive

#### Common failure modes
- Methods callable without adequate authorization
- Incorrect assumptions about caller identity (or caller identity persistence across calls)
- Parameter smuggling through optional/nested structures
- Legacy endpoints with overly broad access
- “Authenticated” treated as “authorized”
- Dangerous privileged actions reachable through innocuous-looking methods

RPC vulnerabilities often look benign in code, but catastrophic in effect.

---

### 4.3 COM / DCOM

#### What it is
COM is an object activation and invocation system built on top of RPC.  
It supports:
- in-proc servers (DLL),
- out-of-proc servers (EXE),
- service-hosted COM servers,
and relies heavily on registry configuration.

#### Why it matters
Many brokers and automation components are COM servers.  
COM therefore frequently forms a **cross-integrity or cross-UAC boundary**, especially in desktop software and enterprise environments.

#### Security properties that matter
- **Launch and access permissions**
- **Server identity** (user, elevated, SYSTEM)
- **Activation model** (in-proc vs out-of-proc; affects isolation and trust)
- **Registry-based configuration** (security descriptors and class registration)
- **Caller identity semantics** (what identity the server sees, and how it uses it)

#### Common failure modes
- Privileged COM servers callable by low-trust callers
- Misconfigured activation permissions (too broad)
- Incorrect trust assumptions in broker-like COM servers
- “Same user” treated as “same trust” (ignores IL/UAC boundaries)
- Registry-based configuration misuse leading to redirection/hijack behaviors

COM-related issues are often **design** bugs rather than implementation bugs.

---

### 4.4 Shared Memory / Sections

#### What they are
Memory regions mapped into multiple processes via section objects (file mappings).  
Often used for performance-critical IPC and shared state.

#### Why they matter
Used for performance-critical IPC in:
- browsers
- antivirus engines
- graphics subsystems

Shared memory becomes dangerous when:
- a lower-trust process can write,
- and a higher-trust process consumes that data as trusted input.

#### Security properties that matter
- Who can write to the shared memory (DACL and handle inheritance)
- How data is validated before use (structure integrity, bounds, invariants)
- Lifetime and synchronization semantics (ownership, locking, versioning)
- Concurrency assumptions (race behavior often becomes the bug)

#### Common failure modes
- Writable shared memory consumed as trusted input
- Structure confusion or version mismatches
- Race conditions amplified by shared state
- Partial validation (only header checked, body trusted)
- Shared-memory “signals” treated as authorization

Shared memory is rarely the root cause alone, but often a force multiplier.

---

### 4.5 UI-based IPC (Windows messages, UIPI)

#### What it is
GUI processes communicate via window messages and related UI mechanisms (handles, message loops, accessibility interactions).

#### Why it matters
Historically a rich attack surface (“shatter attacks”) where low-privilege senders could manipulate privileged GUI processes.

#### Modern constraints
- Mandatory Integrity Control (MIC)
- User Interface Privilege Isolation (UIPI)

These mechanisms reduce cross-trust message flows significantly.

#### Remaining risks
- UIAccess tokens (deliberate bypass of UIPI constraints)
- Allowed message types with unsafe handlers
- Indirect UI-to-privileged execution flows (UI triggers privileged actions)
- Accessibility frameworks and privileged UI bridges
- Legacy UI components that still assume “local UI = trusted”

UI IPC is less common today, but still relevant in specific contexts.

---

## 5. Indirect IPC and Delegation Channels

Windows IPC is not limited to explicit transports (pipes/RPC/COM). Many real-world privilege boundaries are crossed through **indirect delegation channels**, where a lower-trust component influences a higher-trust component by writing state into a shared substrate.

These channels are especially important in vulnerability research because they frequently produce:
- **confused-deputy** conditions,
- **canonicalization** mistakes,
- **TOCTOU** races,
- and **object squatting** attacks.

The key mental model is identical to classic IPC:

> A lower-trust actor supplies data; a higher-trust actor consumes it and performs privileged work.

---

### 5.1 Filesystem-based Handoff

#### What it is
Filesystem-based handoff happens when one component writes a file (or a path) and another component later reads, parses, moves, or executes it. This can be intentional (a staging directory) or accidental (a cache, temp file, or log file used as input).

This is effectively IPC because the filesystem becomes the transport layer.

#### Why it matters for security
Filesystem handoff is a high-value vulnerability class because it intersects directly with privileged operations:
- writing into protected locations,
- replacing binaries/configuration read by privileged services,
- loading libraries/plugins,
- updating software,
- scheduled tasks and helper executables.

Even when the consumer process is not “exploited” in the classic sense, **unsafe file consumption** can yield privileged behavior.

#### Common insecure patterns
1) Writable staging locations used by higher-trust consumers  
   Examples: `C:\Temp`, `%TEMP%`, `%LOCALAPPDATA%`, `%APPDATA%`, `%ProgramData%` (depending on permissions)

2) Path canonicalization mismatches  
   String form vs actual target mismatch (`\\?\`, short/long paths, UNC normalization)

3) TOCTOU (Time-of-check to time-of-use)  
   Check happens before use; attacker switches target in the gap

4) Reparse point / junction / symlink / mount point abuse  
   Privileged process follows reparse points into unintended targets

5) Hardlink abuse  
   Privileged writer overwrites protected file through attacker-controlled link

6) Unsafe DLL/plugin loading from user-writable locations  
   Plugin/search paths including user-writable folders; config-driven load without allowlisting

#### Practical research workflow
1) Identify all file inputs the high-trust component consumes (configs, caches, assets, update packages, plugins, temp artifacts)
2) Determine origin: can a lower-trust process write them?
3) Validate enforcement at use sites: canonicalize and re-check permissions
4) Look for race windows: creation then privileged action is a classic TOCTOU structure
5) Pay attention to token context: backup/restore semantics can bypass typical DACL expectations

#### How this maps to token/trust signals
Filesystem handoff becomes especially interesting when the consumer runs with:
- High/System integrity
- elevation semantics (`ElevationType=Full`)
- high-impact privileges (`SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeManageVolumePrivilege`)
- broker/service identity signals (SYSTEM/service accounts)

These signals do not prove a bug, but sharply increase the value of investigating file-based inputs.

---

### 5.2 Registry-based Handoff

#### What it is
Registry-based handoff occurs when a lower-trust component writes data to a registry key and a higher-trust component later reads and acts on it.

This is common because the registry is globally accessible (within ACL constraints), persistent, and used heavily for configuration and activation.

#### Why it matters for security
Registry handoffs frequently show up in:
- COM activation and configuration
- file/protocol handlers
- per-user configuration consumed by elevated helpers
- “recent file / last used path” state crossing trust boundaries

Registry issues are often logic/design vulnerabilities, not memory-safety bugs.

#### Common insecure patterns
1) HKCU data trusted by elevated/System components (“same user” ≠ “same trust”)
2) COM-related hijack primitives via mis-scoped write permissions
3) Handler/shell integration misuse (open commands / protocol handlers)
4) Policy/config injection (assumes registry is admin-only)
5) Registry pointing to filesystem targets (registry + filesystem TOCTOU chains)

#### Practical research workflow
1) Identify keys/hives read by the target (HKLM vs HKCU matters; ACLs matter more)
2) Determine effective write access
3) Track how values are used (paths, command lines, DLL names, CLSIDs, endpoints)
4) Validate canonicalization and use-site re-validation

#### How this maps to token/trust signals
Registry handoff becomes high-value when you see:
- High/System IL processes that are interactive or broker-like
- UAC boundary markers (elevation type, linked token)
- COM usage likelihood
- components acting on behalf of other processes

Registry is often a control plane: writable control plane + privileged consumer = attack surface.

---

### 5.3 Named Object Namespace Abuse

#### What it is
Windows exposes a kernel object namespace used by IPC primitives and coordination:
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
- or DACLs are safe by default.

#### Why it matters for security
Named objects frequently become boundary failures because:
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
   Low-trust side controls synchronization or state consumed by high-trust side.

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

Common patterns:
- incorrect impersonation usage,
- path traversal and TOCTOU issues,
- identity vs privilege confusion (UAC),
- “same user” treated as “same trust”.

This is primarily a logic failure, not an IPC failure.

---

## 7. IPC in sandbox and broker architectures

Modern Windows security relies heavily on broker designs:

1) Low-trust component requests an operation
2) Broker validates identity/capability and parameters
3) Broker performs the operation with higher authority

The broker is therefore the **true security boundary**.

If broker validation fails, the sandbox fails.

---

## 8. IPC enumeration in tooling (PTTBM perspective)

A mapper tool cannot “solve IPC”, but it can build evidence.

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

Each step increases **confidence**, not certainty.

---

## 9. Confidence and visibility boundaries

Without direct reachability validation:
- IPC findings are hypotheses,
- confidence must be explicit,
- assumptions must be documented.

This honesty is critical for research credibility.

---

## 10. Key takeaway

IPC is where **authority meets reachability**.

- Tokens describe *what a process can do*
- IPC determines *who can ask it to do it*

Most Windows vulnerabilities arise when higher-trust components act on lower-trust input across IPC boundaries without correct validation.

Understanding IPC is therefore essential for:
- sandbox escape research,
- local privilege escalation research,
- trust-boundary analysis.

PTTBM treats IPC not as an implementation detail, but as the **core substrate of Windows security design**.
