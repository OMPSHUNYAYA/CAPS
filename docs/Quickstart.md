# ⭐ **CAPS — Quickstart**

## **Capability Admissibility Protection System**

**Deterministic • Structure-Based • Capability Separation • Visibility Control • Protection Driven**

Minimal demonstrations — reusable capability visibility patterns.

**Capability exists.**

**Visibility is structurally admitted.**

---

## ⚡ **30-Second Proof**

Open any demonstration folder and run the script:

```
python demo/<demo-folder>/<demo_script>.py
```

Example:

```
python demo/CAPS-SmartBulb/caps_smartbulb_v0_11.py --quickstart
```

---

## 🔍 **What To Observe**

- capability may exist without becoming automatically visible
- visibility changes when structure changes
- unsafe requests refuse visibility
- deterministic replay remains stable
- same structure produces identical visibility

---

## 🧠 **Conclusion**

Different structures

↓

Different visibility

Same structure

↓

Same visibility

---

## 🚫 **What CAPS Does NOT Do**

CAPS does not:

- remove capabilities
- automatically expose capabilities
- force visibility
- guarantee production security
- guess missing structure

---

## ✅ **What CAPS Does**

CAPS:

- separates capability from visibility
- structurally admits visibility
- blocks unsafe visibility
- produces deterministic visibility behavior
- enables replay verification

---

## ⚙️ **Minimum Requirements**

- Python 3.9+
- Standard library only
- No external dependencies
- Runs fully offline

---

## 📁 **Repository Structure**

```
CAPS/

├── README.md
├── LICENSE

├── demo/
│   ├── CAPS-SmartBulb/
│   │   ├── README.md
│   │   └── caps_smartbulb_v0_11.py
│   │
│   ├── CAPS-DoorLock/
│   ├── CAPS-Camera/
│   ├── CAPS-Printer/
│   ├── CAPS-Router/
│   ├── CAPS-Vehicle/
│   ├── CAPS-Refrigerator/
│   ├── CAPS-AI-Agent/
│   └── ...

├── docs/   
│   ├── Quickstart.md  
│   ├── FAQ.md  
│   ├── Proof-Sketch.md  
│   ├── CAPS-Architecture-Notes.md  
│   ├── CAPS-Challenge.md  
│   ├── CAPS-Visibility-Scenario-Examples.md  
│   ├── Dependency-Elimination-Framework.png  
│   ├── Shunyaya-Structural-Stack.png  
│   └── CAPS_Diagram.png
```

More demonstrations will be added progressively.

---

## 🧭 **Visual Context**

See:

`docs/CAPS_Diagram.png`

`docs/Dependency-Elimination-Framework.png`

`docs/Shunyaya-Structural-Stack.png`

---

## ✅ **Expected Behavior**

- admissible structure → visibility admitted
- unsafe request → blocked visibility
- invalid request -> blocked visibility
- same structure → same visibility
- same structure → same certificate

---

## 🔁 **Determinism Check**

Run multiple times:

```
python demo/CAPS-SmartBulb/caps_smartbulb_v0_11.py --verify
```

Expected:

- identical visibility
- identical certificates
- replay stability
- deterministic outputs

---

## 🔐 **Deterministic Guarantee**

Visibility is admitted through:

`protection_admissible`

where:

`protection_admissible = protection_complete AND protection_consistent AND request_admissible`

`request_admissible = request_complete AND request_consistent`

Visibility does not depend upon:

- capability count
- request ordering
- execution repetition
- replay count
- infrastructure complexity

---

## 🔁 **Structural Invariant**

`S1 = S2 -> Visibility1 = Visibility2`

`Visibility1 != Visibility2 -> structure differs`

---

## ⚡ **Structural Behavior**

| Condition | Result |
|---|---|
| admissible protection | visibility admitted |
| incomplete protection | visibility refused |
| invalid request structure | blocked visibility |
| unsafe request | visibility refused |

---

## 🧠 **Core Insight**

Capabilities do not automatically create visibility.

**Structure admits visibility.**

---

## ⚠️ **What CAPS Does NOT Claim**

CAPS does not claim:

- production security guarantees
- replacement of existing security systems
- universal applicability
- elimination of infrastructure
- protection against all compromise scenarios

CAPS introduces a structure-first capability visibility model.

---

## 🧭 **Shunyaya Lineage**

CAPS is a practical capability visibility demonstration within the broader Shunyaya structural mathematics ecosystem.

Core structural invariant:

`phi((m,a,s)) = m`

where:

- `m` → capability existence
- `a` → admissibility
- `s` → structural context

Capability existence is preserved.

Structure governs what becomes admitted.

This Quickstart provides a hands-on demonstration that structural visibility principles can be explored within real product domains.

---

## 🚀 **Next Steps**

1. Run verification using `--verify`
2. Explore unsafe scenarios using `--explain`
3. Experiment with different profiles and requests
4. Explore additional demonstrations using identical structural invariants

---

## ⭐ **One-Line Summary**

CAPS demonstrates that capability existence and capability visibility may be separated structurally through protection and admissibility — enabling capability growth without automatic exposure growth.

---

## 🔥 **Final Line**

Capabilities may grow.

**Visibility does not need to.**

**Structure first. Truth always.**
