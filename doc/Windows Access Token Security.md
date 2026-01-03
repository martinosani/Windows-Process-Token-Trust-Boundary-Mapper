# Windows Access Token Security

This document describes the `TokenInfo` schema used by **PTTBM (Process & Token Trust Boundary Mapper)** and explains **why each field exists** in a security-oriented Windows Internals context.

The intent is not to "collect everything", but to capture the **minimum complete set of token attributes that materially influence Windows security decisions** (access checks, mandatory integrity control, UAC, sandboxing, impersonation, and privilege semantics). Where the tool reports fields as `null` or `Unknown`, this reflects a **visibility boundary enforced by the system**, not a tool failure. The information may exist, but it is not observable from the current security context.

---

## 1. Background: what a token is (and why this matters)

In Windows, an **access token** is a **kernel object** representing the **security context** of code execution. The Security Reference Monitor (SRM) uses the token during access checks to answer questions like:

- *Who is the caller?* (user SID, group SIDs)
- *What special capabilities does the caller have?* (privileges)
- *What trust tier is the caller operating under?* (Integrity Level / MIC)
- *Is this an elevated admin context or a filtered one?* (UAC elevation type)
- *Is the caller sandboxed?* (AppContainer + capabilities)
- *Is the caller restricted beyond normal discretionary ACL checks?* (restricted SIDs)

A process has a **primary token** (stored in kernel state associated with the process object); individual threads can optionally have **impersonation tokens** that temporarily change "who the thread is" for specific operations.

Key point: **Windows does not trust process metadata or UI state**. It trusts token semantics.

## 2. Mandatory Integrity Control (MIC), Integrity Levels, and Trust Tiers

### Overview

Windows implements **Mandatory Integrity Control (MIC)** as a **mandatory access control layer** that operates *in addition to* traditional discretionary access control (DACLs).  
MIC introduces the concept of **Integrity Levels (IL)**, which are used to model **trust tiers** between execution contexts.

While DACLs answer the question *"is access allowed?"*, MIC answers a more fundamental question:

> **“Is this caller trusted enough to interact with this target at all?”**

This distinction is critical for understanding modern Windows security boundaries and many classes of local privilege escalation (LPE) vulnerabilities.

---

### Integrity Level: what it represents

An **Integrity Level** is a label attached to an access token that expresses the **relative trustworthiness** of the code executing under that token.

Conceptually:
- Integrity Levels do **not** represent permissions
- They represent **trust tiers**

At runtime, the Windows kernel uses Integrity Levels to enforce **one-way interaction rules** between subjects (processes, threads) and objects (processes, files, registry keys, windows, etc.).

Integrity Levels are implemented as **special SIDs** embedded in the token (the "mandatory label"), and evaluated by the Security Reference Monitor during access checks.

---

### Common Integrity Levels and their meaning

| Integrity Level | Conceptual trust tier | Typical examples |
|---------------|----------------------|------------------|
| Untrusted     | No trust             | Extremely constrained sandbox contexts |
| Low           | Low trust            | Browser renderers, sandboxed content |
| Medium        | Standard user trust  | Normal desktop applications |
| High          | Elevated admin trust | "Run as Administrator" processes |
| System        | OS trust             | SYSTEM services and core components |

These tiers are **relative**, not absolute: what matters is *the relationship between caller and target*.

---

### Core MIC rule (the most important part)

The fundamental MIC rule can be summarized as:

> **A lower-integrity subject cannot modify a higher-integrity object.**

This applies regardless of what the discretionary ACL says.

In practice:
- A Medium IL process cannot write to a High IL process
- A Low IL process cannot inject into a Medium IL process
- A Medium IL process cannot send certain messages to a High IL window

MIC is therefore a **hard boundary** designed to prevent "shatter attacks", injection, and cross-trust interference.

---

### Trust tiers vs identity

A key design principle of MIC is that **trust is not identity**.

The same user account can operate at multiple trust tiers simultaneously:

- A standard desktop application → Medium IL
- An elevated admin application → High IL
- A browser sandbox → Low IL

All of these may belong to the *same user SID*, yet Windows treats them as **fundamentally different trust contexts**.

This separation is intentional and is one of the reasons why:

> **Identity alone is insufficient to reason about privilege.**

---

### Integrity Level and attack surface

From a security perspective, Integrity Levels are primarily about **damage containment** and **control of lateral influence**, not about preventing compromise altogether. MIC assumes that individual components *will* fail and focuses on ensuring that a failure in one trust tier does not automatically propagate to more trusted tiers.

At a high level, the intended security properties are:

- If a **Low Integrity** process (e.g. a browser renderer or sandboxed component) is compromised, MIC aims to prevent it from:
  - modifying Medium or High Integrity processes,
  - injecting code into higher-trust components,
  - influencing privileged execution paths directly.
- If a **Medium Integrity** process (typical user application) is compromised, MIC attempts to prevent it from:
  - tampering with elevated administrator processes,
  - influencing SYSTEM services,
  - bypassing UAC boundaries through direct interaction.

In this model, Integrity Levels define **trust tiers**, and the kernel enforces strict one-way interaction rules between them. These rules are mandatory and apply regardless of discretionary permissions.

---

#### How MIC reduces the attack surface

MIC reduces the effective attack surface by:

- **Blocking write-style interactions across trust tiers**  
  A lower-integrity subject cannot write to, inject into, or otherwise modify a higher-integrity object, even if discretionary ACLs would allow it.

- **Constraining IPC and UI interactions**  
  MIC (together with related mechanisms such as UIPI) limits which cross-process messages and IPC patterns are permitted between trust tiers.

- **Preventing trivial escalation paths**  
  Without MIC, any compromise of a user-mode process could potentially lead directly to escalation by targeting privileged processes. MIC forces escalation attempts to rely on *design flaws* rather than direct access.

As a result, many straightforward privilege escalation techniques that were feasible on older versions of Windows are no longer structurally possible.

---

#### Why MIC-related vulnerabilities still exist

Despite being a strong boundary, MIC does not eliminate all privilege escalation risks. Most real-world LPE vulnerabilities related to Integrity Levels fall into one of the following categories.

##### 1. MIC is bypassed
This is the rarest and most severe class. It involves flaws where the mandatory check itself is circumvented or not enforced correctly at a low level. These issues are uncommon in modern Windows versions and typically require deep kernel or subsystem bugs.

##### 2. MIC is not applied where it should be
MIC applies only to certain classes of interactions. If a component exposes an interaction surface that:
- is not subject to MIC checks, or
- relies solely on discretionary access control,

then a lower-integrity process may still influence higher-integrity behavior indirectly. This often occurs with:
- legacy IPC mechanisms,
- poorly secured named pipes or RPC endpoints,
- file or registry locations writable by lower-integrity contexts but consumed by higher-integrity code.

##### 3. MIC assumptions are violated (the most common case)
This is the dominant class of MIC-related vulnerabilities.

In these cases:
- the operating system correctly enforces MIC,
- but application or service code **assumes** that MIC alone provides sufficient protection.

Typical flawed assumptions include:
- "This component is safe because it runs at High Integrity."
- "Lower-integrity processes cannot influence this path."
- "MIC will prevent misuse of this interface."

If a higher-trust component:
- reads configuration or data from a lower-trust location,
- exposes an IPC interface without validating the caller’s trust tier,
- impersonates a client and then performs privileged actions incorrectly,

then MIC is effectively **working as designed**, but the overall system security still fails due to architectural or logic errors.

---

#### Integrity Levels as a reasoning tool, not a verdict

It is important to emphasize that Integrity Level alone does not indicate vulnerability.

- A High Integrity process is not inherently dangerous.
- A Low Integrity process is not inherently safe.

What matters is the **relationship** between components operating at different trust tiers and the **paths of influence** between them.

In vulnerability research, Integrity Levels are best used to ask questions such as:
- *Should this interaction across trust tiers be possible at all?*
- *Is this higher-integrity component consuming data or requests from a lower-integrity context?*
- *Does this design rely on MIC as a substitute for explicit validation?*

PTTBM treats Integrity Levels as a foundational signal for identifying and reasoning about these trust relationships, rather than as a standalone indicator of security posture.

---

#### Key takeaway

MIC significantly reduces the Windows attack surface by enforcing mandatory trust boundaries, but most MIC-related vulnerabilities arise not from failures of enforcement, but from **incorrect assumptions about what MIC does and does not protect**.

Understanding Integrity Levels as **trust tiers**, and analyzing how data and control flow across them, is essential for effective Windows vulnerability research.

---

### MIC is mandatory, not discretionary

Unlike DACLs:
- MIC rules cannot be overridden by normal access control changes
- Being an administrator does **not** automatically bypass MIC
- Privileges may influence MIC behavior in limited scenarios, but MIC is enforced independently

This makes Integrity Level one of the **strongest trust signals** available in user-mode analysis.

---

### Why Integrity Level is central to trust-boundary mapping

In the context of PTTBM, Integrity Level serves as the **primary trust-tier classifier**:

- It allows grouping processes into trust domains
- It enables detection of unexpected interactions across trust tiers
- It provides a principled way to reason about "should this be possible?"

Examples of high-signal situations:
- A SYSTEM or High IL process running in an interactive session
- A Medium IL process that can influence a High IL process
- A sandboxed (Low IL / AppContainer) process with access paths to Medium IL components

---

### Integrity Level is not a vulnerability indicator by itself

An important distinction:

> **Integrity Level describes expected boundaries, not violations.**

A High IL process is not "dangerous" by default.
A Low IL process is not "safe" by default.

What matters is:
- **who can interact with whom**
- **across which trust tiers**
- **and through which mechanisms**

PTTBM uses Integrity Level as a foundational input to evaluate these relationships, not as a standalone verdict.

---

### Key takeaway

Integrity Levels implement a **mandatory trust hierarchy** in Windows.  
They are the kernel’s primary mechanism for enforcing separation between execution contexts that share identity but differ in trust.

Understanding MIC is essential to understanding:
- why many attacks fail
- why some succeed
- and where trust boundaries actually exist in real Windows systems

---


## 3. ## AppContainer Sandboxing and Capabilities

### Purpose and security model

AppContainer is Windows’ primary **application sandboxing model** for untrusted or partially trusted code.  
Its purpose is not to "run code with fewer privileges", but to **create an execution context with no ambient authority**, where access is denied by default and granted only through explicitly declared capabilities or brokered operations.

Where Mandatory Integrity Control (MIC) enforces **relative trust tiers**, AppContainer enforces an **absolute isolation boundary**.

The guiding security principle is:

> **An AppContainer process should have no access to system resources unless that access is explicitly and narrowly defined.**

---

### AppContainer at the token level (internals view)

From an internals perspective, an AppContainer is implemented as a **restricted access token** with several defining properties:

- A unique **AppContainer SID**, representing the sandbox identity
- **Low Integrity Level**
- A set of **capability SIDs**
- A restricted default DACL and restricted SID list

This token is evaluated by the kernel using the same access-check machinery as any other token, but with additional restrictions that remove implicit access normally granted to user-mode processes.

Crucially, AppContainer is enforced by the kernel, not by user-mode policy.

---

### AppContainer SID: sandbox identity, not user identity

The AppContainer SID identifies **the sandbox**, not the user.

This distinction is fundamental:

- Multiple AppContainers may run under the same user account
- Two processes running as the same user but in different AppContainers are isolated
- Access checks can explicitly allow or deny access to a *specific sandbox*

From a security standpoint, the AppContainer SID must be treated as a **first-class security principal**, just like a user or group SID.

Mistakes often occur when code checks only *"is this sandboxed?"* rather than *"which sandbox is this?"*.

---

### Capabilities: explicit authority grants

Capabilities are **SIDs embedded in the token** that represent explicit permission to access specific classes of resources.

Unlike traditional group membership, capabilities are:
- narrowly scoped
- declarative
- intended to be minimal

Examples include:
- network access
- access to specific device classes
- access to specific system brokers
- access to particular system services

Capabilities are evaluated alongside:
- user SID
- group SIDs
- Integrity Level
- discretionary ACLs

This makes AppContainer a **capability-based security model**, rather than a role-based or identity-based one.

---

### Default-deny and brokered execution

An AppContainer process starts from a position of **near-total denial**:

- no filesystem access
- no registry access
- no named object access
- no network access
- no device access

To perform meaningful work, the process must rely on **brokers**: higher-trust components that execute operations on its behalf.

A typical broker flow is:
1. AppContainer sends a request
2. Broker validates the caller’s identity and capabilities
3. Broker validates request semantics
4. Broker performs the operation in a higher-trust context

This architecture is powerful, but it introduces a critical dependency:

> **The sandbox is only as strong as the broker logic that enforces it.**

---

### AppContainer vs MIC: complementary but different

Although AppContainer processes run at Low Integrity, AppContainer is **not a special case of MIC**.

Key differences:

- MIC limits **interaction across trust tiers**
- AppContainer limits **what resources exist at all**

A non-AppContainer Low IL process still:
- has access to large parts of the user profile
- can interact with many IPC objects

An AppContainer process does not.

Therefore:
- MIC is a *relative boundary*
- AppContainer is an *absolute sandbox*

Both are needed for effective isolation.

---

### AppContainer attack surface (research perspective)

From a vulnerability research standpoint, AppContainer issues rarely involve "breaking the sandbox directly". Instead, they usually involve **boundary misuse or incorrect assumptions**.

#### 1. Broker logic flaws (most common)

A broker may:
- trust AppContainer input too much
- insufficiently validate paths, object names, or parameters
- perform privileged operations using attacker-controlled data

In these cases:
- the sandbox is functioning correctly
- the vulnerability is a **confused-deputy problem** in the broker

---

#### 2. Capability overreach

Capabilities define *what* the sandbox can reach.

Problems arise when:
- capabilities are broader than necessary
- legacy capabilities are granted for compatibility
- capability combinations expose unintended surfaces

An AppContainer with excessive capabilities may technically be sandboxed, but **practically unconfined**.

---

#### 3. Resources not fully AppContainer-aware

Some subsystems:
- predate AppContainer
- rely on discretionary ACLs alone
- were not designed for capability-based isolation

If such a resource does not enforce AppContainer semantics correctly, a sandboxed process may gain access unintentionally.

---

#### 4. Cross-sandbox confusion

If higher-trust code:
- checks only that a caller is "an AppContainer"
- but does not distinguish *which* AppContainer

then:
- one sandbox may interfere with another
- sandbox identity isolation is weakened

This is an identity vs instance confusion, not a sandbox bypass.

---

### Capabilities as attack-surface shapers

Capabilities do not create vulnerabilities by themselves, but they determine:

- which brokers are reachable
- which parsing logic is exposed
- which state machines can be influenced

From a research perspective, enumerating capabilities is often the **first step in understanding the reachable attack surface** of a sandboxed process.

---

### AppContainer in multi-stage attack chains

AppContainer escapes often represent **stage one** of a larger chain:

1. AppContainer (Low IL) → Medium IL escape
2. Medium IL → High IL or SYSTEM escalation

Understanding AppContainer boundaries is therefore essential even when the ultimate goal is not "sandbox escape", but full local privilege escalation.

---

### AppContainer in trust-boundary mapping (PTTBM)

PTTBM uses AppContainer-related fields to:

- identify sandboxed processes
- correlate sandbox identity via AppContainer SID
- enumerate declared capabilities
- highlight unexpected or overly broad capability sets

This allows reasoning about:
- whether a process is truly isolated
- what authority it has been explicitly granted
- which higher-trust components are expected to broker its requests

---

### Key takeaway

AppContainer provides **strong isolation by default**, but it does not eliminate security risk.  
Its effectiveness depends on:

- minimal capability assignment
- correct broker design
- absence of assumptions that “sandboxed” implies “safe”

For vulnerability research, AppContainer is best understood not as something to bypass, but as a **trust boundary whose correctness must be validated at every interface**.

---

## 4. User Account Control (UAC) and Privilege Separation

### Purpose and security model

User Account Control (UAC) is Windows’ mechanism for enforcing **explicit privilege activation** within the same user identity.  
Its purpose is not to prevent administrative actions, but to ensure that **administrative authority is never ambient**.

UAC is built on a core security principle:

> **Administrative identity is not the same as administrative privilege.**

A user may belong to the Administrators group and still execute the vast majority of code in a **non-administrative security context**.

This distinction is foundational to modern Windows security.

---

### The split-token architecture (internals perspective)

When an interactive user who is a member of the Administrators group logs on, Windows creates **two related access tokens**:

- a **filtered (limited) token**
- a **full (elevated) token**

The limited token:
- has administrative group SIDs marked as *deny-only*
- has most administrative privileges removed or disabled
- runs at **Medium Integrity Level**
- is used for normal desktop activity

The full token:
- has administrative group SIDs enabled
- has the full administrative privilege set
- runs at **High Integrity Level**
- is used only after explicit elevation

These two tokens are linked, but **only one is active at a time**.

This model ensures that administrative authority is **available but dormant**.

---

### Elevation as a controlled trust transition

Elevation under UAC is not a permission check; it is a **trust transition**.

Conceptually, elevation represents:
- a transition from **Medium Integrity** to **High Integrity**
- a shift from a **constrained authority set** to a **privileged authority set**

This transition is mediated by trusted system components that:
- verify user intent (consent or credentials)
- enforce policy (e.g., auto-elevation rules)
- create a new process with the full token

Importantly, elevation does **not** modify the existing process.  
It creates a **new execution context** with different trust guarantees.

---

### Elevation types and their meaning

Windows exposes elevation semantics through `TokenElevationType`:

- **Default**  
  Used for identities without split tokens (e.g., SYSTEM, LocalService, NetworkService). UAC does not apply in the interactive sense.

- **Limited**  
  A filtered administrative token. The user is an administrator by identity, but the process is not executing with administrative authority.

- **Full**  
  A fully elevated administrative token. The process executes with administrative privileges and High Integrity.

This distinction is critical: **group membership alone is not a reliable indicator of privilege**.

---

### Relationship between UAC and MIC

UAC and Mandatory Integrity Control (MIC) enforce **orthogonal but complementary boundaries**:

- UAC decides **which token** is used
- MIC decides **what that token can interact with**

In practice:
- non-elevated administrative processes run at **Medium Integrity**
- elevated administrative processes run at **High Integrity**

MIC enforces mandatory isolation between these tiers, preventing Medium Integrity code from directly modifying or injecting into High Integrity execution contexts.

---

### Why UAC is a real security boundary

Although often perceived as a usability feature, UAC is a **deliberate security boundary**.

Without UAC:
- administrator sessions would operate with full privilege at all times
- any user-mode compromise would immediately become an administrative compromise

With UAC:
- privilege escalation becomes a distinct event
- escalation paths must cross an explicit boundary
- escalation attempts are auditable and constrainable

This fundamentally changes the threat model.

---

### Common UAC-related vulnerability patterns

Most UAC-related vulnerabilities do not "break UAC". Instead, they exploit **incorrect assumptions about UAC semantics**.

#### 1. Auto-elevation trust violations

Some system components are allowed to auto-elevate without prompting the user. These components are implicitly trusted.

If such a component:
- loads configuration from user-writable locations
- resolves DLLs from user-controlled directories
- interprets user-controlled input without validation

then a Medium Integrity attacker may influence High Integrity execution.

Here, UAC functions correctly; the vulnerability is a **trust misuse in the elevated component**.

---

#### 2. Medium-to-High confused deputy scenarios

A High Integrity process may expose IPC interfaces to Medium Integrity callers.

If the process:
- does not validate the caller’s trust tier
- performs privileged actions on behalf of untrusted input

then it becomes a **confused deputy**, executing high-privilege operations driven by lower-trust data.

This is one of the most common real-world escalation patterns.

---

#### 3. Identity-based authorization errors

Some designs incorrectly assume:
- “If the user is an administrator, privileged operations are acceptable.”

UAC explicitly invalidates this assumption:
- identity ≠ privilege
- administrative authority must be explicitly activated

Failing to respect this distinction leads to fragile designs that collapse under compromise.

---

### UAC is not an authorization system

UAC answers a narrow question:

> *"Is this execution context elevated?"*

It does **not** answer:
- whether the caller should be allowed to perform a given action
- whether the input is trustworthy
- whether the operation is appropriate in the current context

UAC must be combined with:
- proper access control
- explicit authorization checks
- careful trust boundary validation

Treating UAC as a substitute for authorization is a design error.

---

### UAC in multi-stage attack chains

In practice:
- initial compromise occurs at Medium Integrity
- UAC misuse or design flaws enable Medium → High transition
- further escalation may then target SYSTEM services

UAC therefore represents **a critical intermediate boundary** in real-world attack chains.

---

### UAC in trust-boundary mapping (PTTBM)

PTTBM uses UAC-related token attributes to:

- distinguish identity from effective privilege
- detect filtered vs full administrative tokens
- correlate elevation state with Integrity Level
- highlight unexpected High Integrity execution contexts

This allows security reasoning such as:
- *Is this privileged execution expected?*
- *Was elevation explicit and intentional?*
- *Is high-trust code consuming low-trust input?*

---

### Key takeaway

UAC enforces **explicit privilege activation**, not implicit trust.  
Most UAC-related vulnerabilities arise not from flaws in UAC itself, but from software that **assumes elevation semantics incorrectly** or treats administrative identity as sufficient authorization.

For security analysis, UAC should be treated as a **hard boundary between intent and authority**, and its correctness should be evaluated at every interaction point.


## 5. TokenInfo structure

### Process correlation

#### `Pid` (int)
**Concept:** Process identity.  
**What it is:** The process identifier the token snapshot is associated with.  
**Why it matters:** Tokens are not meaningful in isolation. Security reasoning depends on correlating token data to:
- process lineage (parent/child),
- session boundaries,
- cross-process access checks (e.g., whether a low-trust process can obtain handles to high-trust targets).

---

## 6. Identity vs control: User, Owner, Primary Group

### `UserSid` (string?)
**Concept:** The security principal identity.  
**What it is:** The SID in `TokenUser`. This is the identity SRM uses.  
**Why it matters:** Names are mutable and ambiguous; SIDs are authoritative. This field enables precise detection of service identities (e.g., `S-1-5-18` for SYSTEM) and correct correlation across renames and domain changes.

### `UserName` (string?)
**Concept:** Human-readable identity mapping.  
**What it is:** Best-effort lookup of `UserSid` to `DOMAIN\User`.  
**Why it matters:** Reporting and triage. It must never be used for security decisions, because name resolution can fail, can be localized, and can be ambiguous in domain environments.

### `OwnerSid` (string?)
**Concept:** Control over the token’s security descriptor.  
**What it is:** `TokenOwner`. The owner SID stored in the token object’s security descriptor.  
**Why it matters:** Owner is not “who you are”, but **who controls the object**. In Windows, the owner typically has implicit rights to modify the object’s DACL (conceptually “WRITE_DAC”).  
**Security relevance:** When `OwnerSid` differs from `UserSid`, it indicates the token is controlled/managed by another principal (common in broker/service patterns). This is a useful signal when analyzing:
- delegated execution models,
- service-created tokens,
- potential trust boundary mistakes where a high-trust component creates/owns tokens used in lower-trust contexts.

### `OwnerName` (string?)
**Concept:** Human-readable owner mapping.  
**What it is:** Best-effort lookup of `OwnerSid`.  
**Why it matters:** Explainability in reports; not a decision primitive.

### `PrimaryGroupSid` (string?)
**Concept:** Legacy group identity hint.  
**What it is:** `TokenPrimaryGroup`.  
**Why it matters:** Rarely decisive in modern security checks, but it can still appear in legacy software expectations and some access control scenarios. It is useful for completeness and investigative work on older components.

### `PrimaryGroupName` (string?)
**Concept:** Human-readable primary group mapping.  
**What it is:** Best-effort lookup of `PrimaryGroupSid`.  
**Why it matters:** Reporting only.

---

## 7. Mandatory Integrity Control (MIC): Trust tiers

### `IntegrityLevel` (enum)
**Concept:** Mandatory trust tier (MIC).  
**What it is:** A classification derived from `TokenIntegrityLevel`, typically one of:
- Untrusted, Low, Medium, High, System  
**Why it matters:** MIC is mandatory access control layered on top of discretionary ACLs (DACLs). Even if an ACL might allow an action, MIC can prevent lower-integrity subjects from writing to higher-integrity objects.  
**Security relevance:** A large amount of Windows LPE reasoning reduces to identifying *unexpected edges* across integrity boundaries (e.g., a Medium IL process influencing High IL execution paths).

### `IntegrityRid` (uint?)
**Concept:** Raw integrity RID for precise analysis.  
**What it is:** The RID extracted from the integrity SID (last subauthority), e.g. `0x2000` for Medium.  
**Why it matters:** Avoids relying on coarse labels only; helps with non-standard integrity tiers, debugging, and exact evidence in writeups.

---

## 8. Session boundary (interactive vs service context)

### `SessionId` (int?)
**Concept:** Session isolation boundary.  
**What it is:** The token session ID (`TokenSessionId`).  
**Why it matters:** Session 0 isolation separates services from interactive user sessions. Cross-session interactions are a frequent source of design mistakes and are also relevant for understanding UI interaction policies and desktop boundaries.  
**Security relevance:** A privileged token operating in an interactive session, or a low-trust process interacting with a session-0 privileged process, is a high-signal investigation point.

---

## 9. Token mechanics: primary vs impersonation

### `TokenType` (enum)
**Concept:** Token usage model.  
**What it is:** Primary vs Impersonation token type.  
**Why it matters:** A primary token defines a process security context. An impersonation token defines a thread’s temporary context for “acting on behalf of” a client.  
**Security relevance:** Many privilege boundary failures originate from incorrect assumptions about whether the code is executing under a primary token or an impersonation token at the time a security-sensitive operation occurs.

### `ImpersonationLevel` (enum?)
**Concept:** How far impersonation can go.  
**What it is:** The impersonation level for impersonation tokens:
- Anonymous, Identification, Impersonation, Delegation  
**Why it matters:** This influences what the server can do when impersonating a client and whether it can access local and/or remote resources under that identity.  
**Security relevance:** Higher impersonation levels materially increase the “impact radius” of identity confusion or misuse in service/broker architectures.

---

## 10. UAC and elevation semantics (identity ≠ privilege)

### `IsElevated` (bool?)
**Concept:** Whether this is a high-privilege UAC context.  
**What it is:** `TokenElevation` (not a UI state).  
**Why it matters:** Membership in Administrators does not mean elevated execution. This field captures the effective elevation state used by SRM decisions.

### `ElevationType` (enum)
**Concept:** Split-token model classification.  
**What it is:** `TokenElevationType`: Default, Full, Limited.  
**Why it matters:** This explains *why* a token is or is not elevated:
- `Limited` typically means a filtered admin token,
- `Full` is elevated admin,
- `Default` is common for SYSTEM/services where UAC does not apply in the same way.  
**Security relevance:** Understanding `ElevationType` prevents incorrect conclusions about privilege based on user/group membership alone.

### `IsVirtualizationAllowed` (bool?)
**Concept:** Legacy compatibility virtualization capability.  
**What it is:** `TokenVirtualizationAllowed`.  
**Why it matters:** UAC virtualization can redirect writes to per-user locations for legacy applications.  
**Security relevance:** Virtualization can create surprising effective paths (where an application believes it wrote to a protected location but actually wrote elsewhere). This is not an exploit primitive by itself, but it is a frequent source of confusion during investigation and can affect security assumptions in legacy software.

### `IsVirtualizationEnabled` (bool?)
**Concept:** Virtualization active state.  
**What it is:** `TokenVirtualizationEnabled`.  
**Why it matters:** Allowed ≠ enabled. This field states the runtime behavior in effect.

### `HasUIAccess` (bool?)
**Concept:** UI privilege to bypass certain input isolation constraints.  
**What it is:** `TokenUIAccess`.  
**Why it matters:** UIAccess tokens can interact with higher-privilege windows in ways normal processes cannot (UIPI context).  
**Security relevance:** UIAccess is rare and powerful; unexpected UIAccess indicates either a legitimate accessibility/signed-application scenario or a design weakness worth investigation.

---

## 11. Sandboxing: AppContainer and capabilities

### `IsAppContainer` (bool?)
**Concept:** AppContainer sandbox membership.  
**What it is:** `TokenIsAppContainer`.  
**Why it matters:** AppContainer tokens represent a strongly sandboxed environment with explicit capabilities.  
**Security relevance:** Identifying AppContainer contexts is essential to understanding expected limitations. A sandboxed process exhibiting behaviors inconsistent with its capabilities may indicate a broker boundary issue or a policy defect.

### `AppContainerSid` (string?)
**Concept:** Sandbox identity.  
**What it is:** `TokenAppContainerSid` (SID).  
**Why it matters:** Provides stable identity for the container even if name resolution fails.

### `AppContainerName` (string?)
**Concept:** Human-readable sandbox identity.  
**What it is:** Best-effort name for the AppContainer SID.  
**Why it matters:** Reporting; not a decision primitive.

### `CapabilitiesSids` (IReadOnlyList<string>?)
**Concept:** Declared sandbox capabilities.  
**What it is:** Capability SIDs (`TokenCapabilities`).  
**Why it matters:** Capabilities determine what the AppContainer is allowed to access (e.g., specific device/resource classes).  
**Security relevance:** Overly broad or unexpected capabilities increase the attack surface. This is a meaningful signal in security reviews of sandboxed apps and their brokers.

---

## 12. Groups: discretionary access control inputs

### `Groups` (IReadOnlyList<TokenGroupInfo>?)
**Concept:** Group-based authorization.  
**What it is:** The group SID list with attributes (enabled, deny-only, mandatory, etc.).  
**Why it matters:** DACL evaluation frequently depends on group membership. Attributes are critical: “present” is not the same as “enabled”, and “deny-only” changes semantics.  
**Security relevance:** Misinterpreting group attributes is a common analytical error; the tool keeps attributes to enable correct reasoning.

### Convenience flags
These are derived to simplify rule writing and reporting, but they should be computed respecting group attributes.

#### `IsMemberOfAdministrators` (bool?)
**Concept:** Administrative group signal (effective).  
**Why it matters:** Admin membership drives many access decisions, but only when effectively enabled.

#### `IsLocalSystem` / `IsLocalService` / `IsNetworkService` (bool?)
**Concept:** Service identity classification.  
**Why it matters:** These identities have very different local privileges and network identities. Correctly identifying them is essential for trust boundary mapping and for understanding which principals can access which resources.

---

## 13. Privileges: kernel capabilities beyond ACLs

### `Privileges` (IReadOnlyList<TokenPrivilegeInfo>?)
**Concept:** Special rights that can bypass normal access logic.  
**What it is:** Token privileges with attributes (enabled, default-enabled, removed).  
**Why it matters:** Privileges are not “permissions in an ACL”; they are kernel-recognized capabilities (e.g., debug, impersonation). Enabled vs present is decisive.  
**Security relevance:** Privileges often determine whether an action is possible even when ACLs would otherwise prevent it. In trust boundary analysis, privileges are the fastest way to explain “why this should not be possible” or “why this becomes high risk”.

---

## 14. Restricted tokens: additional mandatory constraints

### `IsRestricted` (bool?)
**Concept:** Restricted-token model (additional deny constraints).  
**What it is:** Derived from presence of restricted SIDs (`TokenRestrictedSids`).  
**Why it matters:** Restricted tokens are intentionally constrained; they can behave like “less than the identity suggests.”  
**Security relevance:** When restricted contexts can influence unrestricted/high-trust contexts, it signals a boundary defect. Restricted tokens are also common in sandboxing and broker models.

### `RestrictedSids` (IReadOnlyList<string>?)
**Concept:** The exact restriction set.  
**What it is:** SID list used to enforce restrictions.  
**Why it matters:** Explains *how* the token is constrained, supporting precise investigation and reproducible writeups.

---

## 15. Linked tokens: UAC split-token relationships

### `HasLinkedToken` (bool?)
**Concept:** Existence of a paired token (UAC split).  
**What it is:** Whether `TokenLinkedToken` can be retrieved (indicating a linked counterpart).  
**Why it matters:** In UAC scenarios, a “limited” token may have a linked “full” token or vice-versa.  
**Security relevance:** This is critical for correctly understanding privilege boundaries under UAC. It also helps explain why a process is an admin identity but not operating with elevated privileges.

---

## 16. Provenance / correlation identifiers (forensics-friendly)

### `AuthenticationId` (string?)
**Concept:** Logon session correlation.  
**What it is:** LUID representing the logon session (`TokenStatistics.AuthenticationId`).  
**Why it matters:** Enables correlating multiple processes to the same logon session and distinguishing “same user, different logon session”.

### `TokenId` (string?)
**Concept:** Unique token instance identity.  
**What it is:** LUID uniquely identifying the token instance (`TokenStatistics.TokenId`).  
**Why it matters:** Helps track duplication, reuse, and token evolution across a run without relying on unstable external identifiers.

---

## 17. Collection metadata (trust boundary honesty)

### `CollectionError` (string?)
**Concept:** Visibility boundary indicator.  
**What it is:** A blocking failure to collect token data (e.g., AccessDenied).  
**Why it matters:** In a trust-boundary tool, inability to observe is meaningful. It reflects the current caller context and the system’s access controls.

### `CollectionWarnings` (IReadOnlyList<string>?)
**Concept:** Partial visibility/collection gaps.  
**What it is:** Non-fatal issues (e.g., a specific token info class not retrievable).  
**Why it matters:** Ensures the tool remains honest and explainable: results are reproducible and interpretation is grounded in what was actually observable.

---

## Appendix: interpreting results as security signals

PTTBM is designed to support principled reasoning such as:

- **Identity vs effective privilege:** `UserSid`/`Groups` vs `IsElevated`/`ElevationType`
- **Mandatory trust boundaries:** `IntegrityLevel` + `SessionId`
- **Delegation and impersonation risk:** `TokenType` + `ImpersonationLevel`
- **Sandbox constraints and capability drift:** `IsAppContainer` + `CapabilitiesSids`
- **Privilege-driven risk analysis:** `Privileges` (enabled vs present), especially rare/high-impact capabilities
- **Control-plane anomalies:** `OwnerSid` mismatch and linked-token presence as indicators of broker/service mediation

This schema is intentionally structured to make “why is this allowed?” answerable with evidence, rather than heuristics.

---
