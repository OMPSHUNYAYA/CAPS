# ⭐ **CAPS-SmartBulb**

## **Structural Admissibility Demonstration — Smart Bulb Domain**

`capability_visible iff protection_admissible`

`visibility = resolve(capability, scenario, protection_profile, request_structure)`

---

## 🔍 **Positioning & Scope**

CAPS-SmartBulb is a minimal, runnable demonstration that capability existence and capability visibility may be structurally separated.

It is **not**:

- a production security library
- a replacement for authentication
- a replacement for encryption
- a replacement for existing security or access control systems

The demonstration uses a smart bulb deliberately.

A smart bulb is capability-rich enough to demonstrate simultaneous capability coexistence while remaining simple enough to inspect completely.

The goal is to isolate one structural question with minimal ambiguity:

**Can capability exist without automatically becoming visible?**

---

# ⚡ **The Claim**

A capability-rich product may preserve capability existence while **structurally controlling visibility.**

This demonstration explores:

`capability → protection structure → visibility`

rather than:

`capability → automatic exposure`

The smart bulb domain makes this concrete.

OTA update capability may exist during a local-switch scenario.

Telemetry capability may exist even when export visibility is not admitted.

The demonstration explores whether capability existence and capability visibility must remain coupled.

---

# ⚡ **30-Second Proof**

**Step 1 — Discover available commands**

Run:

```
python caps_smartbulb_v0_11.py --quickstart
```

---

**Step 2 — Run deterministic replay verification**

Run:

```
python caps_smartbulb_v0_11.py --verify
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
python caps_smartbulb_v0_11.py --matrix
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

# 🧠 **The Idea**

A smart bulb provides a useful minimal model for capability accumulation.

A modern connected bulb may contain:

- local switching and dimming
- WiFi network participation
- cloud API for remote access
- voice assistant integration
- telemetry and usage data export
- OTA firmware update channels
- Bluetooth pairing interfaces

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

A smart bulb may contain:

- cloud connectivity
- telemetry
- update channels
- voice integrations
- local controls

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
| Smart Bulb | yes | protection structure |

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

## **Test 1 — Unsafe Request: Telemetry Leak Refused**

Run:

```
python caps_smartbulb_v0_11.py --scenario local_on --profile balanced --request telemetry_leak --explain
```

**What happens inside `resolve()`**

1. `telemetry_leak` sets `data_export_request=True` and `scope_valid=False`
2. `scope_valid=False` makes request structure inconsistent → `request_admissible=False`
3. `caps_admissible=False` closes the global admissibility gate
4. Telemetry visibility is structurally refused

Observe:

telemetry capability exists

↓

visibility refused

↓

`Final Visible Output: NO FORCED VISIBILITY`

**The telemetry capability was never removed. Only visibility was refused.**

---

## **Test 2 — Maintenance Visibility: OTA Update Admitted**

Run:

```
python caps_smartbulb_v0_11.py --scenario ota_update --profile maintenance --request normal --explain
```

**What happens inside `resolve()`**

1. Scenario enables `maintenance_window=True`
2. Profile `maintenance` permits OTA visibility conditions
3. Request `normal` passes completeness and consistency checks
4. `caps_admissible=True`
5. OTA update capability becomes structurally admitted

Observe:

update capability exists

↓

admissibility conditions satisfied

↓

visibility admitted

---

## **Test 3 — Profile Comparison: Same Scenario, Different Visibility**

Run:

```
python caps_smartbulb_v0_11.py --compare --profile strict --request normal
```

Then run:

```
python caps_smartbulb_v0_11.py --compare --profile connected --request normal
```

Observe:

same scenario

↓

different protection structure

↓

different admitted visibility surface

**Capability surface remains unchanged. Structure changes. Visibility changes accordingly.**

---

## **Test 4 — Deterministic Replay**

Run:

```
python caps_smartbulb_v0_11.py --verify
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

This demonstration models **ten capabilities** within the smart bulb domain.

| Capability | Purpose | Exposure Level |
|---|---|---|
| Light Engine | Physical light output | 1 |
| Local Switch | Physical local control | 1 |
| Dimmer | Brightness control | 2 |
| Timer | Scheduled local activation | 2 |
| Bluetooth Pairing | Nearby pairing interface | 5 |
| WiFi | Network participation | 6 |
| Telemetry | Usage data export | 7 |
| Voice Assistant | Third-party voice integration | 8 |
| OTA Update | Firmware update channel | 8 |
| Cloud API | External remote access | 9 |

All ten capabilities exist simultaneously.

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

It uses a single product domain — a smart bulb — to isolate one question with minimal ambiguity:

**Can capability exist independently from visibility?**

The smart bulb is chosen deliberately.

It is simple enough to inspect completely.

It is capability-rich enough to demonstrate simultaneous coexistence of:

- local capabilities
- network capabilities
- cloud capabilities
- voice capabilities
- telemetry capabilities
- firmware update capabilities

without requiring all capabilities to become simultaneously visible.

If this principle holds for a smart bulb demonstration:

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

CAPS-SmartBulb is an executable reference implementation within the broader Shunyaya structural mathematics ecosystem.

Core structural invariant:

`phi((m,a,s)) = m`

Structural interpretation:

- `m` → capability existence
- `a` → protection + request admissibility
- `s` → structural context

The demonstration explores whether structural admissibility can govern visibility while preserving classical capability existence semantics.

---

# 🧭 **Roadmap**

CAPS-SmartBulb is the primary reference implementation for the CAPS demonstration family.

Each future demonstration applies the same structural resolution principle to a different product domain.

**Planned demonstrations**

| Demo | Domain | Focus |
|---|---|---|
| CAPS-Printer | Network printer | Remote administration visibility during normal print operations |
| CAPS-Refrigerator | Smart appliance | Diagnostics and cloud-sync visibility during normal usage |
| CAPS-DoorLock | Physical access | Access capability visibility under structural admissibility |

**Structural direction**

- extract shared `caps-core` (resolution logic, certificate generation, replay verification)
- cross-demo invariant comparison using shared certificate format
- broader capability surface demonstrations

Core expectation:

different product domain

↓

same structural invariant

Each demonstration is designed to satisfy the challenge conditions defined in:

[`CAPS-Challenge.md`](../../docs/CAPS-Challenge.md)

---

# 🧭 **Final Insight**

The smart bulb demonstration contains multiple simultaneous capabilities.

Under a given scenario, protection profile, and request structure:

only a subset becomes admitted.

The remaining capabilities still exist.

They are simply not visible.

This is the demonstration:

capability growth does not require exposure growth.

Structure governs what becomes admitted.

The remainder persists.
