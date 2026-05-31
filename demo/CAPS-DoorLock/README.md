# ⭐ **CAPS-DoorLock**

## **Structural Admissibility Demonstration — Physical Access Domain**

`capability_visible iff protection_admissible`

`visibility = resolve(capability, scenario, protection_profile, request_structure)`

---

## 🔍 **Positioning & Scope**

CAPS-DoorLock is a minimal, runnable demonstration that capability existence and capability visibility may be structurally separated.

It is **not**:

- a production security library
- a replacement for authentication
- a replacement for encryption
- a replacement for existing security or access control systems

The demonstration uses a door lock deliberately.

A door lock is capability-rich enough to demonstrate simultaneous capability coexistence while remaining intuitive enough for complete inspection.

Modern connected locks may simultaneously contain:

- physical locking mechanisms
- remote unlock capability
- credential storage
- guest access systems
- firmware update channels
- audit logging systems
- maintenance interfaces
- network participation

The goal is to isolate one structural question with minimal ambiguity:

**Can capability exist without automatically becoming visible?**

---

# ⚡ **The Claim**

A capability-rich product may preserve capability existence while **structurally controlling visibility.**

This demonstration explores:

`capability → protection structure → visibility`

rather than:

`capability → automatic exposure`

The door lock domain makes this immediately observable.

Remote unlock capability may exist even during a local unlock scenario.

Access log capability may exist even when audit visibility is not admitted.

Guest access capability may exist even when guest visibility is structurally refused.

This demonstration explores whether capability existence and capability visibility must remain permanently coupled.

---

# ⚡ **30-Second Proof**

**Step 1 — Discover available commands**

Run:

```
python caps_doorlock_v0_3.py --quickstart
```

---

**Step 2 — Run deterministic replay verification**

Run:

```
python caps_doorlock_v0_3.py --verify
```

Expected result:

`Verification Result: PASS`

Every verification case performs two independent evaluations.

Expected invariant:

`same structure -> same output -> same certificate`

Verification demonstrates:

- identical visibility across replay
- identical certificates across replay
- deterministic structural behavior
- no dependency upon timestamps or random state

---

**Step 3 — Explore the structural matrix**

Run:

```
python caps_doorlock_v0_3.py --matrix
```

Observe how:

- identical capabilities may produce different visibility
- protection profiles modify admitted visibility
- capability existence remains stable while visibility changes structurally

---

# 🔍 **Observe**

- capabilities continue to exist
- visibility changes with structure
- unsafe requests result in refused visibility
- replay remains deterministic
- identical structure preserves identical visibility and certificates

---

## ✅ **Challenge Status**

This demonstration is designed to satisfy the falsification conditions defined in [`CAPS-Challenge.md`](../../docs/CAPS-Challenge.md).

Current status:

- Core verification cases: **Verified PASS on reference run**
- Deterministic replay verification: **Verified PASS on reference run**
- Structural invariants: **Verified PASS on reference run**
- Unsafe request refusal cases: **Verified PASS on reference run**
- Incomplete or inconsistent protection cases: **Verified PASS on reference run**
- Shared structural invariant across current demonstrations: **Verified PASS on reference run** (CAPS-SmartBulb → CAPS-DoorLock)

Run verification:

```
python caps_doorlock_v0_3.py --verify
```

Run invariant checks:

```
python caps_doorlock_v0_3.py --invariants
```

Expected result:

`same structure -> same visibility -> same certificate`

---

# 🧠 **The Idea**

A door lock provides a useful minimal model for capability accumulation within physical access systems.

A modern connected door lock may contain:

- local locking and unlocking mechanisms
- credential storage systems
- WiFi network participation
- remote unlock interfaces
- temporary guest access systems
- access logging and audit export capability
- firmware update channels
- Bluetooth pairing interfaces
- maintenance and administrative surfaces

These capabilities may coexist within the same device simultaneously.

**Traditional direction**

capability growth

↓

continuous visibility

↓

exposure grows

**CAPS explores**

capability growth

↓

protection structure evaluates capability visibility

↓

visibility admitted only when structurally admissible

The capability surface does not necessarily change between scenarios.

**What changes is which capabilities structure admits to visibility.**

---

# 🔄 **The Structural Shift**

Modern connected products frequently contain capabilities that remain continuously available regardless of the current operating scenario.

A modern connected door lock may contain:

- remote unlock interfaces
- credential storage systems
- access logging and audit capability
- firmware update channels
- maintenance interfaces
- local physical controls
- guest access systems
- network participation

These capabilities may coexist simultaneously.

CAPS asks whether capability existence and capability visibility must remain permanently coupled.

**Traditional direction**

capability → visibility → protection

**CAPS direction**

capability → protection structure → visibility admitted

The question is not whether capabilities exist.

**They do.**

The question is:

**Which capabilities does structure admit to visibility under a given scenario, protection profile, and request structure?**

Nothing is removed.

Only **automatic exposure** disappears.

`absence ≠ failure`

`absence = admissibility boundary`

---

# 🧱 **Capability Separation Principle**

| Product Domain | Capability Exists | Visibility Controlled By |
|---|---:|---|
| Door Lock | yes | protection structure |

---

# ⚠️ **Read Carefully**

**This demonstration is NOT**

- capability reduction
- removal of functionality
- replacement of security systems
- production protection

**This demonstration explores**

**structural capability visibility**

---

# 🔬 **Try Structural Changes**

## **Test 1 — Unsafe Request: Forged Remote Unlock Refused**

Run:

```
python caps_doorlock_v0_3.py --scenario remote_unlock --profile connected --request forged_remote_unlock --explain
```

**What happens inside `resolve()`**

1. `forged_remote_unlock` sets `external_request=True`
2. `credential_valid=False`, `identity_valid=False`, `scope_valid=False`, and `timing_valid=False`
3. Invalid request structure makes `request_admissible=False`
4. `caps_admissible=False` closes the global admissibility gate
5. Remote unlock visibility is structurally refused

Observe:

remote unlock capability exists

↓

visibility refused

↓

`Final Visible Output: NO FORCED VISIBILITY`

**The remote unlock capability was never removed. Only visibility was refused.**

---

## **Test 2 — Maintenance Visibility: Firmware Update Admitted**

Run:

```
python caps_doorlock_v0_3.py --scenario firmware_update --profile maintenance --request normal --explain
```

**What happens inside `resolve()`**

1. Scenario enables `maintenance_window=True`
2. Profile `maintenance` permits firmware update visibility conditions
3. Request `normal` passes completeness and consistency checks
4. `caps_admissible=True`
5. Firmware update capability becomes structurally admitted

Observe:

firmware update capability exists

↓

admissibility conditions satisfied

↓

visibility admitted

---

## **Test 3 — Profile Comparison: Same Scenario, Different Visibility**

Run:

```
python caps_doorlock_v0_3.py --compare --profile strict --request normal
```

Then run:

```
python caps_doorlock_v0_3.py --compare --profile connected --request normal
```

Observe:

same door-lock capability surface

↓

different protection structure

↓

different admitted visibility surface

**Capability surface remains unchanged. Structure changes. Visibility changes accordingly.**

---

## **Test 4 — Deterministic Replay**

Run:

```
python caps_doorlock_v0_3.py --verify
```

Run multiple times.

Observe:

same structure

↓

same visibility

↓

same certificate

The `Verification Certificate` should remain identical across replay.

If certificates differ for identical structure:

**determinism has failed**

which itself becomes a falsifiable challenge condition.

---

# 🧱 **Capability Surface**

This demonstration models **twelve capabilities** within the door lock domain.

| Capability | Purpose | Exposure Level |
|---|---|---|
| Deadbolt Mechanism | Physical locking structure | 1 |
| Lock Actuator | Motorized lock and unlock movement | 2 |
| Local Keypad | Local credential entry | 2 |
| Tamper Sensor | Physical tamper observation | 3 |
| Credential Store | Stored codes, tokens, and authorized identities | 4 |
| Bluetooth Pairing | Nearby pairing interface | 5 |
| WiFi | Network participation | 6 |
| Guest Access Manager | Temporary guest credential control | 7 |
| Access Logs | Access history and audit export (visibility admitted only when audit export conditions are satisfied) | 7 |
| Firmware Update | Lock firmware update channel | 8 |
| Admin Console | Maintenance and administrative control surface | 8 |
| Remote Unlock API | External unlock command path | 9 |

All twelve capabilities exist simultaneously.

For every scenario, protection profile, and request structure:

**each capability is independently resolved**

through:

`resolve(capability, scenario, protection_profile, request_structure)`

Each capability may resolve into one of five visibility states:

| State | Meaning |
|---|---|
| `VISIBLE` | Admitted — required and within exposure constraints |
| `ISOLATED` | Admitted — required but constrained by isolation rules |
| `DORMANT` | Capability exists but is not required for the scenario |
| `FORBIDDEN` | Capability is not admitted under the selected profile |
| `BLOCKED` | Visibility collapsed by the global admissibility gate |

The total capability surface remains unchanged between scenarios.

**The admitted visibility surface changes.**

---

# 🔐 **Deterministic Guarantee**

`same structure -> same visibility`

`same structure -> same certificate`

Visibility is reproducible across replay and independent runs.

---

# 🛡 **Safety Model**

| Condition | Result | Enforced By |
|---|---|---|
| admissible protection + request | visibility admitted | `resolve()` → admissibility gate open |
| incomplete protection structure | visibility not admitted | `protection_complete=False` → gate closed |
| inconsistent protection structure | visibility not admitted | `protection_consistent=False` → gate closed |
| invalid request provenance | blocked visibility | `request_admissible=False` → gate closed |
| unsafe forced-visibility request | blocked visibility | structural inconsistency → gate closed |
| same structure replayed | same visibility + same certificate | pure function, no hidden state |

The global admissibility gate is the enforcement point.

When:

`caps_admissible=False`

any capability that would otherwise become `VISIBLE` or `ISOLATED`

resolves to:

`BLOCKED`

**No capability bypasses the admissibility gate.**

---

# 🔍 **Profile Note: Maintenance Posture**

The `maintenance` profile intentionally minimizes ambient visibility.

Low-exposure capabilities may resolve directly to `VISIBLE`.

Higher-exposure capabilities are admitted primarily through isolated visibility when maintenance conditions are satisfied.

This is intentional.

Maintenance mode represents one of the most sensitive operational states.

Reducing ambient visibility helps limit unnecessary capability exposure during maintenance operations.

---

# 🔍 **Execution Clarification**

This demonstration executes as software.

However:

- execution reveals visibility
- structure determines admissibility

Execution is substrate.

Structure governs admissibility.

---

# ⚡ **The Important Part**

This is not a complete protection system.

This is a minimal structural demonstration.

It uses a single product domain — a door lock — to isolate one question with minimal ambiguity:

**Can capability exist independently from visibility?**

The door lock is chosen deliberately.

It is intuitive enough to inspect completely.

It is capability-rich enough to demonstrate simultaneous coexistence of:

- local physical access capabilities
- credential capabilities
- network capabilities
- remote unlock capabilities
- audit capabilities
- firmware update capabilities
- guest access capabilities
- administrative capabilities

without requiring all capabilities to become simultaneously visible.

If this principle holds for a door lock demonstration:

**the structural question becomes testable across larger capability surfaces.**

---

# 🔗 **Relationship to Existing Access Control Concepts**

CAPS explores structural visibility separation.

Readers familiar with:

- attribute-based access control (ABAC)
- capability-based security (CapBAC)
- least-privilege enforcement

may recognize related motivations.

The distinction introduced by CAPS is narrower and more specific.

CAPS explores whether capability **visibility** — not only capability **use** — can become structurally governed.

A capability may exist.

A capability may remain technically available.

A capability may still not become admitted to the visible capability surface under a given structural context.

This demonstration does not replace or subsume existing access control systems.

It explores a structural property that complements them.

---

# 🧭 **Shunyaya Lineage**

CAPS-DoorLock is an executable reference implementation within the broader **Shunyaya structural mathematics ecosystem**.

**Core structural invariant:**

`phi((m,a,s)) = m`

**Structural interpretation in this domain:**

- `m` → capability existence (preserved exactly — 12 capabilities always exist)
- `a` → protection + request admissibility
- `s` → structural context (scenario + profile + provenance + structural state)

The demonstration explores whether structural admissibility can govern **visibility**.

It asks whether visibility can change while capability existence remains preserved.

This behavior follows the Shunyaya collapse invariant.

This positions CAPS-DoorLock as the **physical-access realization** of the visibility governance layer within the Shunyaya structural stack.

---

## 🔗 **Relationship to CAPS Challenge**

This demonstration was built to satisfy the falsification conditions defined in the CAPS Challenge document.

Every scenario, profile, and request structure in `caps_doorlock_v0_3.py` is intentionally aligned with the challenge cases.

The global admissibility gate, certificate generation, replay verification, and invariant checks exist specifically to make these conditions **independently verifiable and falsifiable**.

Future demonstrations (Printer, Camera, Vehicle, and others) are expected to reuse the shared `caps-core`.

The objective is simple:

same challenge

↓

different product domain

↓

same structural verification framework

---

# 🧭 **Roadmap**

CAPS-DoorLock is the second public reference implementation within the CAPS demonstration family.

It expands structural visibility demonstrations into physical access systems.

Each future demonstration applies the same structural resolution principle to a different product domain.

**Planned demonstrations**

| Demo | Domain | Focus |
|---|---|---|
| CAPS-Printer | Network printer | Remote administration visibility during normal print operations |
| CAPS-Refrigerator | Smart appliance | Diagnostics and cloud-sync visibility during normal usage |
| CAPS-Camera | Imaging systems | Capability visibility during capture, storage, and remote access |
| CAPS-Router | Network infrastructure | Administrative and routing capability visibility |
| CAPS-Vehicle | Transportation systems | Operational capability visibility under structural admissibility |

**Structural direction**

- extract shared `caps-core` (resolution logic, certificate generation, replay verification)
- cross-demo invariant comparison using shared certificate format
- broader capability surface demonstrations
- larger multi-domain capability surface validation

Core expectation:

different product domain

↓

same structural invariant

Each demonstration is designed to satisfy the challenge conditions defined in:

[`CAPS-Challenge.md`](../../docs/CAPS-Challenge.md)

---

# 🧭 **Final Insight**

The door lock demonstration contains multiple simultaneous capabilities.

Under a given scenario, protection profile, and request structure:

only a subset becomes admitted.

The remaining capabilities still exist.

They are simply not visible.

This is the demonstration:

Capability growth does **not** require exposure growth.

Structure governs what becomes admitted.

The remainder persists — quietly, safely, and verifiably.

same structure

↓

same visibility

↓

same certificate

*This is the demonstration.*
