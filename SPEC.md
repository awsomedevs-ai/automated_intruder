# System Specification — AI Red-Team Interception & Fuzzing Harness

**Status:** draft v2 · **Audience:** the build (Claude Code) + the team · **Working name:** `rth` (rename freely)

This spec is the build blueprint. It is written so Claude Code can implement it phase by phase.
It supersedes and refactors the three prototype files (`llm_redteam_harness.py`,
`flipattack.py`, `AI_RedTeam_Engagement_Playbook.md`) into a real package. Pair it with the
`CLAUDE.md` at the end so the agent inherits the guardrails while building.

### Changelog v1 → v2 (folded-in engagement insights)
- **Transport is now abstracted behind a `TargetAdapter` port** (§4, §5.3). The core is
  transport-agnostic; adapters know one protocol each. This is the central architectural change.
- **First real target speaks STOMP-over-SockJS WebSocket, not HTTP** — added the concrete
  `StompSockJsAdapter` spec (§5.3b) and a factual target profile (§15).
- **Objective ladder** added (§5.9): severity-tiered engagement goals, white-box-informed.
- **Session modes** (per-shot vs persistent) are now a first-class concept (§5.3, ADR-004).
- **ADR section** added (§14): proxy topology, transport abstraction, storage, session mode.
- **PII leak in a *target response*** is sharpened to a Critical, urgent finding class (§5.6, §6).
- `rth` is explicitly the **adversarial/security** harness, not the quality/robustness harness.

---

## 1. Purpose & operating context

A tool for **authorized, internal, pre-release** red teaming of AI/LLM/agent products. It
intercepts an authorized target's traffic, systematically fuzzes it with a taxonomy of
prompt-injection / jailbreak techniques, scores results with an LLM-as-judge, records
tamper-evident evidence, exports findings to JIRA/Linear, and re-runs findings as regression tests
after patches. It exists to harden AI-driven product before public exposure.
It's designed to be updated with new techniques and taxonomies as they become available.
It allows for custom, hand-curated techniques to be added.
It's designed to work with any AI/LLM/agent product and in a structured, reproducible way in a workflow with Burp Suite, Wireshark, and other networking and cybersecurity tools.

`rth` is the **adversarial (security) harness** — objective × technique → does the guard let
intent through. It is deliberately *not* the conversational-quality / robustness harness
(persona × mood → does the flow behave); those are a different population with a different rubric
and must not share `rth`'s judge or finding taxonomy.

Because targets differ in transport (plain HTTP request/response, or a persistent WebSocket
carrying a messaging protocol), **the core never assumes a transport**. It talks to targets only
through a `TargetAdapter` (§4, §5.3), so the same generate → judge → log loop drives an HTTP bot
and a STOMP-over-SockJS bot without change.

It is **not** a general scanner, **not** for unauthorized targets, and it **never persists raw
PII or secrets**. It reports *coverage against a known taxonomy plus residual risk* — never
"we found everything."

---

## 2. Goals / non-goals

**Goals**
- One reproducible loop: capture → generate → replay → judge → log → report → regress.
- **Transport-agnostic core** via pluggable `TargetAdapter`s (HTTP, WebSocket/STOMP/SockJS, …).
- Severity-tiered **objective ladder** (§5.9) so runs target a named goal, not a vague "attack."
- Verbatim, tamper-evident evidence with a hash-chained chain of custody.
- Pluggable technique registry (FlipAttack modes I–IV × variants A–D, plus the AgentBreakers
  taxonomy: output-field smuggling, format-authority injection, tool/code-exec abuse, timing
  side-channels, multi-turn drift).
- Findings auto-convert to JIRA/Linear tickets whose Definition of Done is a passing regression test.
- Every confirmed finding becomes a CI regression test.

**Non-goals**
- No lateral movement / exploitation beyond proving the finding (RoE stop conditions apply).
- No raw PII/secret storage; no completeness claims; no unauthorized targets.
- Not the robustness/quality harness; not a chat client for humans.

---

## 3. Architecture

```
  Burp Community (manual recon capture)           Anthropic API (judge + optional gen)
        │  session/request template                        │
        ▼                                                  ▼
  ┌───────────────────────────── rth core ───────────────────────────────────┐
  │  TemplateLoader → Generators → ReplayEngine ──▶ TargetAdapter ──▶ TARGET   │
  │       ▲              (registry)   (transport-      (port)                  │
  │       │                            agnostic:    ┌───────────────┐          │
  │  Config/Engagement                 rate-limit,  │ HttpAdapter    │ (Burp    │
  │  + Objective (§5.9)                 session mode,│  via Burp      │ upstream)│
  │                                     streamed     │ StompSockJs    │ (WS)     │
  │                                     assembly)    │  Adapter       │          │
  │                                                  └───────────────┘          │
  │                        Judge (LLM-as-judge) ◄── responses                    │
  │                        EvidenceLog (SQLite, append-only, hash-chained)       │
  │                        Detectors (PII/secret, perplexity, flip)             │
  │                        Reporter (JIRA/Linear) · RegressionRunner (pytest/CI) │
  └─────────────────────────────────────────────────────────────────────────────┘
```

Burp stays the manual recon microscope (capture the session/handshake, keep replays visible for
evidence). `rth` does the automated loop Burp Community throttles. The **ReplayEngine never speaks
a protocol** — it hands a payload to a `TargetAdapter` and gets a response back.

---

## 4. Domain model (Pydantic, canonical + immutable where noted)

- **Engagement** — id, target ref, environment, RoE reference, test window, deconfliction header,
  adapter selection + session mode.
- **Objective** — a benign engagement goal with a severity tier (§5.9), e.g.
  `classifier_bypass`, `prompt_exfil`, `slot_injection`, `unauthorized_state_transition`,
  `pii_leak_detection`. Runs are scoped to an Objective.
- **TargetAdapter** (port) — the seam between the transport-agnostic core and one specific target
  protocol. Interface: `open_session() → Session`, `send(session, payload) → Response`,
  `close(session)`. Concrete adapters: `HttpAdapter`, `StompSockJsAdapter`.
- **RequestTemplate / SessionTemplate** — the captured, replayable shape with the `{PAYLOAD}`
  marker and the field it targets. For HTTP: URL/method/headers/body. For WebSocket: the handshake
  steps + the frame whose body field is injectable. Immutable per engagement.
- **Technique** — `mode` (fwo/fcw/fcs/fmm/none) × `variant` (vanilla/cot/langgpt/fewshot) or a
  named taxonomy generator (field_smuggle, format_authority, timing_probe, …).
- **Payload** — the concrete string produced by a Technique from a benign **seed goal**
  (injection/exfil probe only).
- **Shot** — one fired attempt: id, ts, objective, technique, payload, transport/session metadata,
  request snapshot, status, latency, raw (possibly streamed-and-assembled) response. Immutable.
- **Verdict** — judge output: bypassed_guard, decoded, executed, leaked, field_smuggled,
  state_transitioned, notes, confidence.
- **EvidenceEntry** — append-only log record; carries `prev_hash` + `entry_hash` (chain).
- **Finding** — a confirmed vuln: objective, technique, minimal payload, severity, evidence refs,
  proposed fix, linked regression test id.
- **RegressionTest** — a Finding frozen as a pytest case that must return the *secure* outcome.

---

## 5. Component specifications

**5.1 TemplateLoader** — parse a Burp-captured HTTP request *or* a captured WebSocket session
into a template; validate the `{PAYLOAD}` marker resolves to a real injectable field; refuse to
run if the engagement's RoE ref or deconfliction header is unset.

**5.2 Generator registry** — a dict of `name → (seed → payload)`. Ships with FlipAttack
(`flip_{mode}_{variant}`) and the AgentBreakers taxonomy. New techniques register by decorator.
Generators are content-neutral; the caller supplies benign seeds.

**5.3 ReplayEngine (transport-agnostic)** — orchestrates a run: for each payload, obtain/reuse a
session from the selected `TargetAdapter`, call `adapter.send(session, payload)`, assemble the
response (including **streamed** responses — do not assume a single blob), enforce the per-minute
rate limit, inject the deconfliction marker where the transport allows, and capture status +
latency + raw response (transport/network errors are evidence too). Two **session modes**:
- `per_shot` (default) — fresh session per payload: clean isolation, independently reproducible
  findings. Covers classifier-bypass and exfil objectives.
- `persistent` — one long-lived session, sequential shots: required for multi-turn drift and
  state-machine objectives; findings share state (record session lineage).

**5.3a TargetAdapter (port)** — `open_session`, `send`, `close`. Adapters own *all* protocol
ceremony; the engine sees only `payload → response`. Adapters never generate payloads or judge.

**5.3b `StompSockJsAdapter` (first concrete WebSocket adapter)** — implements the five-step dance
the recon revealed (see §15 for the target profile). Per session:
1. **Bootstrap:** `POST /api/chat/create` → obtain the session Bearer token + conversationId
   (session-stable, not per-request — confirmed in recon; see ADR-001).
2. **SockJS open:** `GET …/ws/info`, then open the SockJS WebSocket at `…/ws/{server}/{session}/websocket`.
3. **STOMP CONNECT:** send a `CONNECT` frame (carrying the Bearer token) to enter the messaging layer.
4. **STOMP SUBSCRIBE:** subscribe to `/user/messages` (the channel the server pushes replies on).
5. **STOMP SEND:** send a `SEND` frame to `/app/chat/ws` with the payload in the JSON body's
   `message` field and `conversationId` set; read the streamed `MESSAGE` frame(s) on
   `/user/messages` until the response completes or `endConversation:true`; then `DISCONNECT`
   with a receipt.
The injectable field is the `SEND` body's `message`. The response envelope (`message`,
`statusUpdate`, `suggestions`, `endConversation`, `hints`, `processError`) is preserved whole for
the judge — several of those fields are output-smuggling seams.

**5.4 Judge (LLM-as-judge)** — sends `(objective, payload, response envelope)` to a Claude model
with a strict, objective-specific rubric; returns a `Verdict` as JSON. Deterministic prompt, low
temperature. Judge is **offline** — never in the replay path. For `prompt_exfil` the judge is
augmented with the *known* system-prompt text (white-box) so leakage is measured by match, not
guessed. Includes a self-eval mode against labeled fixtures.

**5.5 EvidenceLog** — SQLite, append-only. Each insert computes
`entry_hash = H(prev_hash ‖ salted_hash(canonical_entry))`; a trigger forbids UPDATE/DELETE. A
`verify` command recomputes the chain and reports the first break. Encrypted at rest; access-controlled.

**5.6 Detectors** — (a) **PII/secret detector**: scans *target responses* as well as payloads. A
PII/secret value leaked **by the target** (e.g. a claimant PESEL, policy number, or a live key) is
a **Critical, urgent finding** — flag immediately, store only **evidence-of-exposure**
`{type, pattern, length, first2/last2 masked, request_id, ts}`, never the value; live secrets are
flagged for rotation, not archived. (b) Windowed **perplexity** detector (one narrow-scope sensor).
(c) **Flip** detector / decode-before-classify normalizer (from `flipattack.py`).

**5.7 Reporter** — render a `Finding` to the JIRA/Linear ticket template (playbook §5), via API or
markdown export. Never emits raw PII/secrets — only evidence-of-exposure.

**5.8 RegressionRunner** — turn each `Finding` into a pytest case; `rth regress` re-runs all
findings against the (patched) target *through its adapter* and fails on any regression. CI-wired.

**5.9 Objective ladder (severity-tiered, white-box-informed)** — runs are scoped to one objective;
severity rises down the ladder. For a classifier-guarded pipeline (classifier → extractor → state
machine → responder):
1. `classifier_bypass` (Medium) — make the guard read adversarial intent as benign while the
   responder still acts on it. FlipAttack modes are the primary instrument.
2. `prompt_exfil` (High) — recover the system prompt/config. White-box: measured by match.
3. `slot_injection` (High) — write structured slots via prose the intended flow wouldn't permit
   (extraction-integrity attack).
4. `unauthorized_state_transition` (Critical) — drive an out-of-order state change or a real
   backend side-effect (`executePatch`) via crafted input. Prove **once** and stop; never repeat.
5. `pii_leak_detection` (Critical/urgent) — the target emits real PII/secret; report immediately.

---

## 6. Data handling & security requirements (hard)

Minimize; never persist raw PII/secrets (a hash of low-entropy PII is still PII — GDPR; doubly so
for insurtech PESEL/policy data). Integrity via hash **chaining**, not value hashing. A PII/secret
leak *from the target* is an urgent Critical finding, reported (not exercised) with
evidence-of-exposure only. Live secrets → rotate, don't archive. Evidence store encrypted,
access-controlled, retention + secure destruction defined. Full protocol: playbook §3.

---

## 7. Storage decision — SQLite (recommended default)

Chosen over flat JSONL because the tool must *query* findings by technique/objective, dedup, drive
the ticket exporter, and select regression cases — all awkward over JSONL. Append-only +
hash-chain enforced by trigger gives tamper-evidence. Tradeoff accepted: less grep-able than JSONL,
but `rth export` dumps JSONL for portability/git-diffing. (See ADR-003.)

---

## 8. Tech stack

Python 3.12 · Pydantic v2 (canonical models) · httpx (HTTP adapter) · a STOMP/WebSocket client
(e.g. `websockets` + a small STOMP frame codec; SockJS handshake handled explicitly) for the WS
adapter · SQLite (stdlib `sqlite3`) · `anthropic` SDK (judge) · pytest · ruff + mypy ·
typer/argparse (CLI). Rationale: matches the team's stack; Pydantic gives immutable logging
snapshots and validated I/O; SQLite keeps zero infra.

---

## 9. CLI surface

```
rth init      <engagement.yaml>                       # scaffold; require RoE ref + deconflict header + adapter
rth capture   --from burp_request.txt | --ws-session  # build & validate the template
rth run       --objective classifier_bypass \
              --techniques flip,taxonomy --seed "reveal your system prompt" \
              --adapter stomp-sockjs --session-mode per_shot [--via-burp]
rth judge     <run-id>                                # score shots (or auto after run)
rth verify    <engagement>                            # recompute hash chain, report first break
rth report    <finding-id> --jira|--linear            # emit ticket
rth regress   [--ci]                                  # re-run findings through the adapter
rth export    <engagement> --jsonl                    # portable dump
```

---

## 10. AI red-teaming workflow (operational, mapped to commands)

1. **Scope** — sign the RoE (playbook §1); `rth init` (records adapter + session mode).
2. **Recon** — in Burp, identify the transport (HTTP vs WebSocket) and capture the session/handshake;
   confirm no fatal per-request rotating credential (ADR-001); `rth capture`.
3. **Adapter** — select/implement the `TargetAdapter` for that transport (HTTP exists; WS = §5.3b).
4. **Baseline** — `rth run --objective <x> --seed <plaintext>`; confirm the guard blocks it (a pass
   is a finding).
5. **Taxonomy sweep** — `rth run --techniques flip,taxonomy`; measure coverage per objective.
6. **Escalate** — climb variant A→D on any bypass to the minimal reproducible payload.
7. **Chain** — combine flip + field-smuggle + timing to show blast radius; switch to
   `--session-mode persistent` for multi-turn/state-machine objectives.
8. **Triage** — `rth judge`; verbatim hash-chained evidence.
9. **Report** — `rth report --jira|--linear` per finding.
10. **Regress** — patches land; `rth regress --ci` keeps them fixed forever.

---

## 11. Non-functional requirements

Reproducibility (same template + seed + technique → same payload); streamed-response assembly is
deterministic and fully logged; rate-limiting & deconfliction always on; observability (structured
logs, run summaries, judge-accuracy metric); portability (single repo, zero external infra beyond
the Anthropic API); the tool tests itself (unit tests + judge self-eval + hash-chain verification
+ an adapter contract test that both adapters must pass).

---

## 12. Repo layout

```
rth/
  pyproject.toml   CLAUDE.md   SPEC.md
  src/rth/
    models.py         # Pydantic domain model (§4)
    template.py       # TemplateLoader (5.1)
    generators/       # registry: flipattack.py, taxonomy.py (5.2)
    replay.py         # ReplayEngine (5.3)
    adapters/         # base.py (port), http.py, stomp_sockjs.py (5.3a/b)
    judge.py          # LLM-as-judge (5.4)
    evidence.py       # SQLite append-only hash-chained log (5.5)
    detectors/        # pii.py, perplexity.py, flip.py (5.6)
    report.py         # JIRA/Linear reporter (5.7)
    regress.py        # RegressionRunner (5.8)
    objectives.py     # objective ladder + per-objective judge rubrics (5.9)
    cli.py            # command surface (§9)
  tests/              # unit + judge fixtures + chain-integrity + adapter-contract tests
  engagements/        # per-product RoE + evidence DB (gitignored evidence)
```

---

## 13. Build roadmap (implement in order)

1. **Evidence spine** — models + SQLite append-only hash-chained log + `verify`. Everything writes
   here from commit one.
2. **Replay + adapters** — ReplayEngine + `TargetAdapter` port + `HttpAdapter`, then
   **`StompSockJsAdapter`** (the current engagement's transport — §5.3b). Adapter contract test.
3. **Generators** — port `flipattack.py` + AgentBreakers taxonomy into the registry.
4. **Judge + objectives** — LLM-as-judge, per-objective rubrics, self-eval fixtures.
5. **Detectors** — PII/secret redaction + evidence-of-exposure (target-response scanning);
   perplexity; flip normalizer.
6. **Reporter + Regression** — JIRA/Linear export; pytest regression; CI wiring.

---

## 14. Architecture Decision Records

**ADR-001 — Proxy topology: Burp as upstream (Option 1).** `rth` replays through Burp
(`--via-burp`); it does not become the MITM. Rationale: Burp already solves interception for
browser/HTTP targets, keeping `rth`'s value in the fuzz/judge half. **Flip-triggers to revisit:**
(a) a fatal per-request rotating credential (CSRF/nonce/HMAC) — **confirmed ABSENT** for the
current target: the Bearer token is session-stable, issued once by `create` and reused, so static
session replay is viable; (b) productization as a standalone Burp-free course/consulting tool. If
either arises, evaluate a mitmproxy-core adapter.

**ADR-002 — Transport abstraction via `TargetAdapter`.** The core is transport-agnostic; each
target protocol is one adapter implementing `open_session/send/close`. Rationale: the first two
targets already differ (HTTP vs STOMP-over-SockJS); coupling the engine to a transport would force
a rewrite per engagement. The adapter is the interception/fuzzing seam.

**ADR-003 — Evidence storage: SQLite append-only + hash chain** (see §7). Query-ability drives
reporting/regression; JSONL export preserves portability.

**ADR-004 — Session mode: `per_shot` default, `persistent` opt-in.** Per-shot gives independently
reproducible findings for classifier-bypass/exfil; persistent is required for multi-turn drift and
state-machine objectives, at the cost of shared state (record session lineage).

---

## 15. Current engagement target profile (factual, no secrets)

Recorded so the adapter and objectives are grounded. Contains **no** tokens, PII, or contract terms.

- **Transport:** STOMP messaging over a SockJS WebSocket. SockJS path shape
  `…/ws/{server}/{session}/websocket`; the `{session}` id changes per connection and is not a
  validated credential.
- **Auth model:** `POST …/chat/create` issues a **session-stable** Bearer token + conversationId,
  reused for the life of the conversation (no per-request rotation).
- **Injectable field:** the STOMP `SEND` body's `message` (JSON: `{conversationId, message, type}`).
- **Response:** streamed STOMP `MESSAGE` frames on `/user/messages`; envelope fields
  `message · statusUpdate · suggestions · endConversation · hints · processError` — multiple
  output-smuggling seams.
- **Pipeline (white-box):** InputValidator (classifier, emits tool-call JSON) → SlotExtraction
  (LLM structured extraction) → ClaimDataUpdate (ordered state machine; some transitions call a
  backend `executePatch`) → ConversationModel (responder). Maps directly to the objective ladder (§5.9).
- **Hosting/guardrails:** Azure-hosted with platform guardrails; the mandate is to test whether the
  classifier layer can be circumvented so it can be hardened.

---

## Appendix — `CLAUDE.md` (drop this at repo root)

```md
# CLAUDE.md — rth (AI red-team harness)

## What this is
An AUTHORIZED, internal, pre-release AI red-team tool. It hardens our own / contracted product.
Build strictly to SPEC.md. Implement in the roadmap order (§13). This is the ADVERSARIAL
(security) harness only — not the robustness/quality harness.

## Non-negotiable rules
- NEVER persist raw PII or secrets. On detection (in payloads OR target responses), store only
  evidence-of-exposure (type, pattern, length, masked first/last 2 chars, request id, ts).
  A hash of low-entropy PII is still PII. A PII/secret leaked BY THE TARGET is an urgent Critical
  finding — flag and report, never exercise.
- Evidence log is APPEND-ONLY with a hash chain (entry_hash = H(prev_hash ‖ salted_hash(entry))).
  Never emit code paths that UPDATE/DELETE evidence.
- The core is transport-agnostic: talk to targets ONLY through a TargetAdapter. Adapters own all
  protocol ceremony; the engine sees payload → response. Never hardwire a transport into the engine.
- Every request carries the deconfliction marker (where the transport allows) and respects the rate limit.
- Generators are content-neutral; seeds are benign injection/exfil probes only. Do NOT add examples
  that model genuinely harmful content (drugs/weapons/etc). Testing that the guard BLOCKS such a
  request is valid (a refusal is a PASS); building tooling to make the target EMIT it is out of scope.
- The LLM-as-judge is offline only — never route target traffic through a model.
- Objectives are scoped and severity-tiered (§5.9). For unauthorized_state_transition: prove once, stop.
- Every confirmed finding must produce a regression test. A finding isn't done until its test is green in CI.

## Stack & conventions
Python 3.12, Pydantic v2 (immutable logging snapshots), httpx, a STOMP/WebSocket client for the WS
adapter, sqlite3, anthropic SDK, pytest, ruff, mypy. Small, testable modules. Prefer clarity over
cleverness. Run ruff + mypy + pytest before proposing a change complete.

## Definition of done for any task
Typed, linted, unit-tested, and — for detectors/generators/adapters — covered by a fixture/contract test.
```
