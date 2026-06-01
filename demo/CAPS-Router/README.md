# ⭐ **CAPS-Router**

## **Structural Admissibility Demonstration — Network Infrastructure Domain**

`capability_visible iff protection_admissible`

`visibility = resolve(capability, scenario, protection_profile, request_structure)`

---

## 🔍 **Positioning & Scope**

CAPS-Router is a minimal, runnable demonstration that capability existence and capability visibility may be structurally separated.

It is **not**:

- a production router firmware
- a production security library
- a replacement for authentication
- a replacement for encryption
- a replacement for existing network security systems

The demonstration uses a router deliberately.

A router is capability-rich enough to demonstrate simultaneous capability coexistence while remaining intuitive enough for complete inspection.

Modern routers may simultaneously contain:

- packet forwarding
- NAT
- stateful firewall
- DHCP services
- DNS resolution
- WiFi radios
- guest networking
- administrative interfaces
- firmware update channels
- VPN systems
- cloud management
- telemetry export
- traffic analytics
- mesh participation

The goal is to isolate one structural question with minimal ambiguity:

**Can capability exist without automatically becoming visible?**

---

# ⚡ **The Claim — Least Visibility Principle**

A capability-rich infrastructure product may preserve **full capability existence** while **structurally controlling visibility.**

**Traditional assumption (pre-CAPS):**

`capability growth -> continuous visibility -> exposure growth`

**CAPS direction (structural):**

`capability growth -> protection structure evaluates visibility -> visibility admitted only when structurally admissible`

**Core Principle (Shunyaya-aligned):**

`capability_visible iff admissibility_conditions_satisfied`

where admissibility is structurally governed through:

- protection structure completeness
- protection structure consistency
- request structure completeness
- request structure consistency

The router domain makes this immediately observable.

Remote administration capability may exist even during normal browsing.

Telemetry capability may exist even when telemetry visibility is not admitted.

VPN capability may exist even when VPN visibility is structurally refused.

Cloud management capability may exist even when cloud visibility is not admitted.

Nothing is removed.

Only **automatic exposure** disappears.

`absence != failure`

`absence = admissibility boundary`

This is the **Least Visibility Principle**:

**capability existence may remain constant while admitted visibility changes structurally**

This demonstration explores whether capability existence and capability visibility must remain permanently coupled.

---

# ⚡ **30-Second Proof**

**Step 1 — Discover available commands**

Run:

```
python caps_router_v0_2.py --quickstart
```

---

**Step 2 — Run deterministic replay verification**

Run:

```
python caps_router_v0_2.py --verify
```

Expected result:

```
Verification Result: PASS
Verification Certificate: 402d397da9eee6f1

Deterministic replay confirmed.
```

Expected invariant:

`same structure -> same output -> same certificate`

Verification demonstrates:

- identical visibility across replay
- identical certificates across replay
- deterministic structural behavior
- no dependency upon timestamps or random state

---

**Step 3 — Run challenge mode**

Run:

```
python caps_router_v0_2.py --challenge
```

Expected:

`Challenge Result: PASS`

---

**Step 4 — Explore visibility surface**

Run:

```
python caps_router_v0_2.py --surface
```

Observe:

- identical capabilities produce different visibility
- protection profiles modify admitted visibility
- capability existence remains stable while visibility changes structurally

---

# 📋 **CLI Quick Reference**

| Command | Purpose |
|---|---|
| `--quickstart` | List all recommended commands |
| `--verify` | Deterministic replay verification |
| `--verify --json` | Verification output as machine-readable JSON |
| `--challenge` | Run falsification-oriented challenge checks |
| `--surface` | Compare admitted visibility across key scenarios |
| `--matrix` | All scenarios across all profiles |
| `--compare --profile <p> --request <r>` | All scenarios under one profile and request |
| `--request-compare --scenario <s> --profile <p>` | All request structures under one scenario and profile |
| `--invariants` | Run focused structural invariant checks |
| `--manifest` | Print release manifest and release certificate |
| `--manifest --json` | Manifest as machine-readable JSON |
| `--profiles` | List available protection profiles |
| `--requests` | List available request structures |
| `--scenario <s> --profile <p> --request <r> --explain` | Resolve and explain one structural scenario |

---

# 🔍 **Observe**

- capabilities continue to exist
- visibility changes with structure
- unsafe requests result in refused visibility
- replay remains deterministic
- identical structure preserves identical visibility and certificates

---

## ✅ **Challenge Status**

This demonstration is designed to satisfy the falsification conditions defined in:

[`CAPS-Challenge.md`](../../docs/CAPS-Challenge.md)

Current status:

- Core verification cases: Verified PASS on reference run
- Deterministic replay verification: Verified PASS on reference run
- Structural invariants: Verified PASS on reference run
- Challenge mode: Verified PASS on reference run
- Unsafe request refusal cases: Verified PASS on reference run
- Shared structural invariant across demonstrations: Verified PASS on reference run

Run:

```
python caps_router_v0_2.py --verify
```

Run:

```
python caps_router_v0_2.py --challenge
```

Expected:

`same structure -> same visibility -> same certificate`

---

# 🧠 **The Idea**

A router provides a useful model for capability accumulation within infrastructure systems.

Modern routers may contain:

- local routing capability
- firewall systems
- remote administration
- cloud management
- firmware update paths
- VPN capability
- telemetry systems
- diagnostics
- mesh systems
- guest segmentation

These capabilities may coexist simultaneously.

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

Modern routers frequently contain capabilities that remain continuously available regardless of the current scenario.

A router may simultaneously contain:

- remote administration
- VPN infrastructure
- firmware update systems
- telemetry systems
- cloud management
- guest networks
- local routing capability
- diagnostic interfaces

These capabilities coexist simultaneously.

CAPS asks whether capability existence and capability visibility must remain permanently coupled.

**Traditional direction**

capability -> visibility -> protection

**CAPS direction**

capability -> protection structure -> visibility admitted

The question is not whether capabilities exist.

**They do.**

The question becomes:

**Which capabilities does structure admit to visibility under a given scenario, protection profile, and request structure?**

Nothing is removed.

Only automatic exposure disappears.

`absence != failure`

`absence = admissibility boundary`

---

# 🧱 **Capability Separation Principle**

| Product Domain | Capability Exists | Visibility Controlled By |
|---|---:|---|
| Router | yes | protection structure |

Additional product domain rows will be added as CAPS demonstrations expand across the ecosystem.

---

# ⚠️ **Read Carefully**

**This demonstration is NOT**

- capability reduction
- removal of functionality
- replacement of router security
- replacement of firewall systems
- production protection

**This demonstration explores**

**structural capability visibility**

---

# 🔬 **Try Structural Changes**

## **Test 1 — Unsafe Remote Administration Refused**

```
python caps_router_v0_2.py --scenario remote_admin --profile maintenance --request wan_probe --explain
```

Observe:

remote admin capability exists

↓

visibility refused

↓

`Final Visible Output: NO FORCED VISIBILITY`

---

## **Test 2 — VPN Admission**

```
python caps_router_v0_2.py --scenario vpn_access --profile connected --request normal --explain
```

Observe:

VPN capability exists

↓

structure satisfied

↓

visibility admitted

---

## **Test 3 — Firmware Update Admission**

```
python caps_router_v0_2.py --scenario firmware_update --profile maintenance --request normal --explain
```

Observe:

firmware update exists

↓

maintenance structure satisfied

↓

visibility admitted

---

## **Test 4 — Deterministic Replay**

```
python caps_router_v0_2.py --verify
```

Repeated execution should preserve:

`same structure -> same visibility -> same certificate`

---

# 🧱 **Capability Surface**

This demonstration currently models **twenty capabilities**.

**Note:**

The capability count is version-specific.

Future releases may expand the capability surface.

The `--manifest` command prints the authoritative count for the current version.

Examples:

- Packet Forwarding
- NAT
- Stateful Firewall
- DHCP
- DNS
- WiFi
- Guest Network
- QoS
- Local Administration
- Mesh Pairing
- VPN
- Firmware Update
- Remote Administration
- Cloud Management
- Telemetry Export

All capabilities coexist simultaneously.

Each capability resolves through:

`resolve(capability, scenario, protection_profile, request_structure)`

Visibility states:

| State | Meaning |
|---|---|
| `VISIBLE` | Admitted capability |
| `ISOLATED` | Admitted but constrained |
| `DORMANT` | Exists but unnecessary |
| `FORBIDDEN` | Not admitted |
| `BLOCKED` | Collapsed by admissibility gate |

---

### **Capability Surface Visualization (Planned for Future Releases)**

Future releases may introduce additional visualization tooling for structural observability.

Examples include:

- `--surface-graph` -> visualize capability surfaces and admitted visibility paths
- `--posture-heatmap` -> compare visibility ratios across scenarios and protection profiles
- certificate-aware structural replay visualization
- visibility surface comparison across posture changes

The goal is simple:

make structural governance **visually observable**

so capability surfaces, admissibility boundaries, and visibility changes become easier to inspect.

Expected structural direction:

`same capability surface`

↓

`different posture`

↓

`different admitted visibility`

↓

`same certificates`

---

# 🔐 **Deterministic Guarantee**

`same structure -> same visibility`

`same structure -> same certificate`

---

# 🔁 **Invariant Checks**

Run:

```bash
python caps_router_v0_2.py --invariants
```

Expected:

`Invariant Result: PASS`

Invariant checks verify:

- identical structures preserve visibility
- capability existence remains preserved
- protection changes modify visibility only
- deterministic replay remains stable

---

# 🛡 **Safety Model**

| Condition | Result |
|---|---|
| admissible protection + request | visibility admitted |
| incomplete protection | visibility refused |
| inconsistent protection | visibility refused |
| invalid provenance | blocked visibility |
| unsafe forced visibility | blocked visibility |

The global admissibility gate is the enforcement point.

When:

`caps_admissible=False`

capabilities that would otherwise become visible collapse to:

`BLOCKED`

---

# 🔍 **Profile Note: Maintenance Posture**

The `maintenance` profile intentionally minimizes ambient visibility.

Lower exposure capabilities may become directly visible.

Higher exposure capabilities primarily resolve through isolated visibility.

This is intentional.

Maintenance windows represent sensitive infrastructure states.

Reducing ambient visibility helps reduce unnecessary capability exposure during maintenance operations.

---

# 🔍 **Profile Note: QoS and Analytics Coupling**

The `qos_engine` capability visibility is governed by the `allow_analytics` profile flag.

This coupling is intentional.

QoS classification requires traffic observation capability.

A profile that refuses analytics visibility also refuses QoS classification visibility, since QoS operation depends on the same structural traffic-observation surface.

If future releases introduce a dedicated `allow_qos` flag, this note will be updated accordingly.

---

# 🔥 **Challenge Mode**

Run:

```
python caps_router_v0_2.py --challenge
```

Challenge mode tests:

- remote admin visibility during normal browsing
- telemetry visibility during normal browsing
- VPN visibility without VPN structure
- guest escape attempts
- WAN probes
- cloud takeover attempts
- firmware forcing attempts

If unsafe visibility appears:

**the demonstration fails**

---

# 🧾 **Release Manifest**

Run:

```
python caps_router_v0_2.py --manifest
```

Manifest mode prints:

- version
- capability count
- scenario count
- profile count
- request count
- verification result
- invariant result
- challenge result
- release certificate

Manifest mode exists to simplify external replay, release verification, and deterministic reproduction.

Manifest mode also prints the Shunyaya structural mapping and current capability-surface version to simplify external verification, replay, and release comparison.

---

# 🔍 **Execution Clarification**

Execution reveals visibility.

Structure governs admissibility.

---

# ⚡ **The Important Part**

This is not a complete protection system.

This is a focused structural demonstration.

It uses a router because routers contain large capability surfaces while remaining understandable.

The question being isolated is:

**Can capability exist independently from visibility?**

The router is chosen deliberately.

It is infrastructure-rich enough to demonstrate simultaneous coexistence of:

- routing capability
- administration capability
- cloud capability
- firmware capability
- VPN capability
- telemetry capability
- diagnostics capability
- network segmentation capability

without requiring all capabilities to become simultaneously visible.

If this principle holds for router infrastructure:

**the structural question becomes testable across larger infrastructure surfaces.**

---

# 🔗 **Relationship to Existing Access Control Concepts**

CAPS explores structural visibility separation.

Readers familiar with:

- attribute-based access control (ABAC)
- capability-based security (CapBAC)
- least privilege

may recognize related motivations.

The distinction introduced by CAPS is narrower.

CAPS explores whether capability **visibility** itself can become structurally governed.

A capability may exist.

A capability may remain technically available.

A capability may still not become admitted into the visible capability surface under a given structural context.

This demonstration does not replace existing access-control systems.

It explores a structural property that complements them.

---

# 🧭 **Shunyaya Lineage**

CAPS-Router is an executable reference implementation within the broader Shunyaya structural mathematics ecosystem.

Core invariant:

`phi((m,a,s)) = m`

Interpretation:

- `m` -> capability existence
- `a` -> admissibility
- `s` -> structural context

This demonstration explores whether visibility changes while capability existence remains preserved.

CAPS-Router represents the **network infrastructure realization** of the visibility governance layer.

---

# 🧬 **Shunyaya Structural Mapping**

CAPS-Router acts as a direct executable realization of the Shunyaya collapse invariant.

```bash
phi((m,a,s)) = m
```

## **Structural Mapping**

| Symbol | CAPS-Router Interpretation | Preserved? |
|---|---|---:|
| `m` | Capability existence | Always |
| `a` | Admissibility lane (`protection + request`) | Governed |
| `s` | Structural posture (`scenario + profile + certificate state`) | Governed |

Interpretation:

Capability existence (`m`) remains preserved.

Protection structure and request structure govern admissibility (`a`).

Scenario posture, profile posture, and certificate posture contribute to structural state (`s`).

The router capability surface remains unchanged.

Only the admitted visibility surface changes.

This creates a network infrastructure realization of structural visibility governance.

`same capability surface`

↓

`different structural posture`

↓

`different admitted visibility`

↓

`same deterministic collapse`

This section connects router infrastructure behavior directly back to the collapse guarantee:

`phi((m,a,s)) = m`

---

## 🔗 **Relationship to CAPS Challenge**

This demonstration was built to satisfy:

[`CAPS-Challenge.md`](../../docs/CAPS-Challenge.md)

Future demonstrations are expected to reuse:

`caps-core`

Goal:

same challenge

↓

different product domain

↓

same structural verification framework

---

# 🧭 **Roadmap & Ecosystem Direction**

CAPS-Router v0.2 is the **third public reference implementation** within the CAPS demonstration family.

**Future ecosystem direction includes:**

- shared `caps-core` package (resolver, certificate engine, invariant harness)
- stronger structural posture modeling (`s` layer evolution)
- cross-demo certificate comparison
- visibility surface visualization layers
- larger multi-domain capability validation

**Planned Demonstrations**

| Demo | Domain | Focus |
|---|---|---|
| CAPS-Printer | Network printer | Administrative visibility during print operations |
| CAPS-Refrigerator | Smart appliance | Cloud and diagnostic visibility governance |
| CAPS-Camera | Imaging systems | Capture and remote-access visibility |
| CAPS-Vehicle | Transportation | Operational capability visibility |

Each planned demonstration is expected to reuse the same structural invariant and challenge framework.

The capability surface changes.

The structural verification framework remains.

**Structural Direction**

- one shared `caps-core`
- cross-demo certificate comparison
- cross-demo posture comparison
- broader capability surfaces
- unified ecosystem posture exploration
- larger multi-domain validation

Longer-term direction:

a shared structural posture may eventually allow multiple demonstrations to operate under common visibility constraints.

Example:

maintenance posture

↓

high-exposure surfaces across multiple products become simultaneously constrained

↓

visibility remains structurally governed

Core expectation:

different product domain

↓

same structural invariant

↓

same replayable visibility logic

---

## 🚀 **vNext Preview — From Demonstration to Ecosystem**

Future releases aim to evolve CAPS from a **single-product demonstration layer** toward a broader **cross-domain structural governance framework**.

Potential ecosystem direction includes:

- shared `caps-core` so new demonstrations inherit common resolution, certificates, and invariants
- stronger posture modeling across structural contexts
- unified posture commands spanning multiple demonstrations
- visibility-surface visualization layers for structural inspection
- larger cross-domain certificate comparisons

Example direction:

shared posture

↓

router + smart bulb + door lock operate under common visibility constraints

↓

capabilities persist

↓

visibility remains structurally governed

Long-term goal:

make

`same structure -> same visibility -> same certificate`

portable across increasingly larger structural ecosystems.

---


# 🧭 **Final Insight**

The router demonstration currently models **twenty simultaneous capabilities**.

Only a subset is admitted.

The remaining capabilities **still exist**.

They are simply not visible.

**Capability growth no longer requires exposure growth.**

**Structure governs admission.**

same structure

↓

same visibility

↓

same certificate

↓

same replayable truth

This is not a security patch.

This is a **structural grammar for infrastructure visibility**.

A network realization of the broader Shunyaya idea:

> New insight. Preserved capability. Classical truth preserved.

The capability surface persists.

Visibility is admitted.

`capabilities persist -> visibility admitted -> structure governs`
