# Mohar — design document (v0.1)

*Author: Saddam Malik · github.com/malikdevhunk/mohar · MIT licensed*
*Status of this document: design draft, written 19 Nov 2026. Nothing below is built yet.*

---

## 0. Name

**Mohar** (मुहर) — Hindi/Urdu for *seal* or *stamp*: the mark that says "this was approved, and by whom".
Pronounced "MO-har". File extension `.mo`, CLI `mohar`, sealed artifact `.mohar`.

Name checks done on 19 Nov 2026:

| Check | Result |
|---|---|
| `github.com/malikdevhunk/mohar` | 404 (free) — checked with WebFetch and curl |
| Well-known language called Mohar | None found. A few tiny unrelated repos use the word (an expense tracker, an exam-paper custody tool, a UNIX timestamp helper). |
| crates.io `mohar`, npm `mohar`, PyPI `mohar` | all free |
| mohar.dev / .io / .sh / .rs | already registered by someone else → use `malikdevhunk.github.io/mohar` or a `saddammalik.com/mohar` page |

Names looked at and dropped: *Sanad* (PyPI package and sanad.dev are both AI-agent products, plus a GitHub Actions tool), *Kavach* (thousands of repos, one is an AI-agent governance kernel), *Sigil*, *Vigil* (a 3k-star language already), *Mandate* (an "agent-native language" repo exists), *Strata*, *Rune*, *Kryos* (all taken by close cousins, see §2). Free fallbacks if Mohar ever has a problem: **Gupt**, **Dhaal**, **Ghera** (all free on GitHub, crates.io, npm, PyPI today).

---

## 1. The pitch

**One line:**
> Mohar is a small language where secrets, authority and untrusted input are types — and the compiler hands you a post-quantum-signed *seal* that states exactly what the program can touch.

**Paragraph:**
Most security tooling checks a program after it is written, or fences it in with a runtime config that nobody reads. Mohar moves the three questions that matter into the type system: *What can this code read, write and call?* (capabilities), *Where can this value go?* (secrecy and trust labels), and *Which cryptography does it rely on, and will that survive quantum computers?* (built-in post-quantum primitives with a crypto policy). From those types the compiler derives a short, human-readable authority report, binds it to the exact build hash, and signs it with ML-DSA (FIPS 204). A host — a CI job, a server, or the runtime around an AI agent — verifies the seal before it runs anything. If an LLM agent writes a Mohar plan, the person approving it reads three lines of generated authority instead of 300 lines of code, and the runtime enforces exactly those three lines.

Slogan candidates (pick one, don't use all): "Code with a receipt." · "Know what it can touch." · "Seal it before you run it."

---

## 2. Landscape and the honest gap

I looked at what exists so that Mohar does not claim novelty it hasn't earned. Facts below come from project pages, papers and registries checked on 19 Nov 2026; star counts are from the GitHub API that day.

### 2.1 General-purpose and smart-contract languages

| Language | What it is good at | Relation to Mohar |
|---|---|---|
| **Rust** | Memory safety via ownership; no GC | Implementation language. No capability, effect or information-flow types. Libraries such as `secrecy` and `subtle` help but are conventions, not type-system rules. |
| **Zig** | Explicit allocators, `comptime`, C interop | Culture of "pass the allocator in" is a cousin of "pass the capability in". No safety or label system. |
| **Mojo** | Python-style syntax with systems performance for accelerators; open-sourced, stable 1.2.0 on 22 Oct 2026 | Different goal (AI compute speed). Nothing on authority or secrecy. |
| **Move** | Linear *resource* types for on-chain assets; bytecode verifier; `copy/drop/store/key` abilities | Closest in spirit for "types as security", but it models assets, not authority or information flow, and lives inside blockchains. |
| **Cairo** | Provable computation (STARKs) for Starknet | Proves *that* something ran; says nothing about what it could access. |
| **Noir** | DSL for zero-knowledge circuits; private inputs | "Private" here means hidden from the verifier in a proof, not information-flow checking of a running program. |
| **Vale** | Generational references, region borrowing | Memory-safety research language. (Not to be confused with Project Everest's Vale for verified assembly.) |
| **Pony** | Reference capabilities for data-race freedom; stdlib uses `AmbientAuth`/`FileAuth`-style tokens for authority | One of the few mainstream-ish languages with object-capability *authority* in its standard library. No labels, no PQC. |
| **Austral** | Linear types plus capability-based security, deliberately small spec | Very close in philosophy for authority. No information-flow labels, no PQC, no signed manifest. |
| **Koka** | Row-polymorphic algebraic effects, Perceus reference counting | Effects for control flow, not a security policy. |
| **Hylo** | Mutable value semantics, safe systems programming | Memory model research. |
| **Unison** | Content-addressed code, *abilities* (effects), distributed computing | Content hashing of code is related to Mohar's deterministic build hash. Abilities are not a permission policy. |
| **Roc** | Apps talk to the world only through a *platform*; pure functional; still pre-0.1 | The platform/app split is a coarse sandbox. No labels or crypto. |
| **Gleam** | Friendly, type-safe, BEAM/JS | No effect or security system. |

### 2.2 Research and security-focused building blocks

- **Object-capability languages and systems:** E, Joe-E, Caja, Monte, Wyvern; **Scala 3 capture checking** (tracked capabilities, "local purity"); **Effekt** (capability-style effects).
- **Information-flow type systems:** Jif (Java), FlowCaml, Paragon, Haskell LIO. Mature research; rarely used in products.
- **Constant-time crypto languages:** **FaCT** (secret/public labels, compiler rewrites secret branches into constant-time code), **Jasmin** (flow-sensitive constant-time checker, used for verified implementations), **CT-Wasm** (secret `s32/s64` types and secret memories in WebAssembly), Cryptol.
- **Protocol languages:** **Owl** (information-flow + refinement types with a cryptographic soundness proof, extracts to Verus/Rust).
- **Attenuable credentials (tokens, not languages):** Macaroons, Biscuit, UCAN.
- **Supply chain:** Sigstore, SLSA provenance, CycloneDX CBOM (cryptographic bill of materials). Today these are mostly scanners and signing flows with classical keys.
- **Runtime sandboxes:** Deno permissions, WASI capabilities, WebAssembly component model.

### 2.3 Post-quantum cryptography status (checked 19 Nov 2026)

- NIST published **FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA)** on 13 Aug 2024. NIST IR 8547 plans to deprecate quantum-vulnerable algorithms and remove them from its standards by 2035, with high-risk systems moving earlier. FIPS 203 has a noted erratum that will go into a future revision.
- RustCrypto crates: `ml-kem` 0.3.4 (31 Oct 2026), `ml-dsa` 0.1.2 (31 Oct 2026), `slh-dsa` 0.1.0 stable / 0.2.0-rc.5 prerelease. **All three say in their READMEs that they have never been independently audited.** Mohar must repeat that warning, not hide it.
- `aws-lc-rs` 1.19 offers ML-KEM (stable since 1.12) and ML-DSA-44/65/87 — a second, FIPS-track backend worth supporting behind the same trait.
- `x-wing` 0.1.1 implements the X-Wing hybrid (X25519 + ML-KEM-768) but targets an older IETF draft than the current one (-11), so treat it as experimental.
- Chrome ships X25519MLKEM768 by default since Nov 2024, so hybrid key exchange is already normal on the web.

### 2.4 LLM-agent sandboxing

- **CaMeL** (Google DeepMind / ETH, 2025): a privileged model writes a restricted Python plan; an interpreter tracks provenance and allowed readers on every value and checks tool policies. Runtime-tracked, Python-based; solved 67% of AgentDojo tasks with provable security in the paper's strict setting.
- **"Securing Agents With Tracked Capabilities"** (ACM conf. on AI and Agentic Systems, 2026): agents write Scala 3 with capture checking; capabilities and local purity prevent leaks statically.
- Industry practice today is mostly containers, tool allow-lists and human approval prompts — configuration outside the code.

### 2.5 The closest neighbours — and they are real

I started this research expecting an empty field. It is not empty. These young projects already sell part of the same story, and Mohar's launch material must acknowledge them:

| Project | Stars (19 Nov) | Overlaps | Does not (from their docs) |
|---|---|---|---|
| **Strata** (beardedeagle/strata) | 5 | Capability-typed systems language, explicit authority, effects, optional IFC and constant-time profiles, ML-DSA/ML-KEM obligations, signed artifacts, provenance, reproducibility. The most similar design on paper. | A large systems language + runtime (Mantle) aimed at distributed systems; not a small agent-plan language; I found no authority-report-for-humans workflow, no integrity (trust) label for prompt injection, no CBOM output. |
| **Rune** (TheOdinheim/rune-lang) | 2 | Governance-first language: effects, capabilities, IFC labels, "AI security". | Classical crypto in stdlib (Ed25519, X25519, AES-GCM, ChaCha); no PQC listed; no signed manifest. |
| **Kryos** (NORTHTEK Labs) | n/a | Capabilities in function signatures, deny-by-default, `Tracked<T>` provenance, framed around AI-agent code. | No secrecy labels or constant-time rules found; no PQC; no seal. |
| **Verum** (verum-lang) | 14 | Refinement/dependent types, capability contexts, built-in ML-KEM/ML-DSA/SLH-DSA — but its own docs state the PQ backends are not implemented in the current build. | No information-flow types. |
| **CaMeL** | — | The agent-provenance idea itself. | Python, runtime-checked, not a language. |
| **Owl** | — | IFC + crypto soundness. | No PQC built-ins, protocols only, Coq-style proof workflow. |

### 2.6 What is genuinely new — stated carefully

Every individual ingredient in Mohar has prior art. I'm not claiming a new type theory. After searching, I did **not** find a language that ships *all* of these together:

1. **Two label axes in one small type system** — *secrecy* (secret ⊐ public) and *integrity* (untrusted ⊐ trusted) — so the same mechanism blocks "key leaks to the log" **and** "text from a web page steers a trusted tool call" (prompt injection).
2. **Capability scopes in the type** — `FsRead<"./inbox">` — so the full authority of a program can be read off its types and *statically extracted*, with runtime checks only as a backstop.
3. **A compiler-generated authority report bound to the artifact hash and signed with ML-DSA**, which a host must verify before running (`mohar run --require-seal`). The authority report is written for a human approver, with a diff against what the host is willing to grant.
4. **Crypto policy as a compile-time rule** — ML-KEM / ML-DSA / SLH-DSA / hybrid built in, algorithms chosen by a policy file (crypto agility), quantum-vulnerable algorithms flagged with a NIST IR 8547-based timeline, and a **CBOM** emitted from the compiler's knowledge of what the program actually calls (not a scanner guessing).
5. **Constant-time restrictions on secret values enforced by the type checker** (FaCT/Jasmin style), delivered as part of a general-purpose-ish language rather than a crypto-only DSL.
6. **Deterministic, reproducible builds** with the hash of source + std + compiler inside the seal.

Honest framing for the README: *"Mohar combines ideas from object-capability languages, information-flow typing, constant-time crypto DSLs and post-quantum standards into one small language, and adds a signed, human-readable authority seal. Strata, Kryos, Rune and CaMeL explore neighbouring ground."* Do **not** write "world's first", "unhackable", "quantum-proof" or "most secure". Re-run the landscape search the week before launch — this space moves quickly.

---

## 3. Three concepts and the pick

### Concept A — **Mohar**: sealed-authority language
Small expression-oriented language; secrecy+integrity labels; scoped capabilities; PQC built-ins with crypto policy; compiler emits a signed authority seal; `plan` profile for AI-agent programs.

### Concept B — **Rotor**: crypto-agility protocol DSL
A DSL for describing handshake/messaging protocols that compiles to Rust, with algorithm negotiation, hybrid KEMs and a CBOM. Very useful for the PQC migration. But it overlaps heavily with Owl and with existing protocol generators, it is narrow (not a "programming language" people will try for fun), and testing correctness of generated protocols is a time sink.

### Concept C — **Tether**: total plan language for agents
A deliberately non-Turing-complete language (no recursion, bounded loops) whose only job is to express an agent's tool plan with taint tracking. Ships in one week and is easy to understand. But it competes directly with CaMeL, the Scala-tracked-capabilities work, Kryos and "agent-native language" repos, and it is too small to attract language people.

### Scoring (1–5, higher is better)

| | Novelty (honest) | Real usefulness | Solo v0.1 in 2–3 weeks | Story / shareability | Total |
|---|---|---|---|---|---|
| A. Mohar | 4 | 5 | 3 | 5 | **17** |
| B. Rotor | 2 | 4 | 3 | 2 | 11 |
| C. Tether | 2 | 4 | 5 | 3 | 14 |

**Pick: A.** Concept C's best idea survives as Mohar's `#[profile(plan)]` (total, bounded, no ambient authority). Concept B's best idea survives as Mohar's crypto policy and CBOM. Risk with A is scope; §7.7 has a cut line that keeps v0.1 credible even if the third week slips.

---

## 4. Language overview

Rust-flavoured syntax on purpose: people can read it in 5 minutes. Expression-oriented, statically typed, no null, no exceptions, no floats in v0.1 (determinism and constant-time simplicity), no global mutable state, no ambient authority.

### 4.1 Core
- Types: `bool`, `u8 u16 u32 u64 i64`, `Text` (UTF-8), `Bytes`, `[T; N]`, `List<T>`, `Option<T>`, `Result<T, E>`, `struct`, `enum`, tuples, `Unit`.
- Items: `fn`, `struct`, `enum`, `use`, `const`.
- Statements: `let`, assignment to `let mut`, `if`, `match`, `for i in a..b`, `while` (non-plan profiles), `return`, `?` for `Result`.
- Lambdas: non-capturing only in v0.1 (`|x| x + 1`). They are pure by construction.
- Generics: only on built-in types in v0.1. User generics come in v0.3.

### 4.2 Label qualifiers
Two optional qualifiers in front of any type:

```
secret   T     // confidentiality: must never reach a public sink
untrusted T    // integrity: must never steer a trusted sink
secret untrusted T   // both
```
Default is `public trusted`. Literals in program text are trusted and public.

### 4.3 Capabilities
Authority is a value you hold. There is no `open()` you can just call. `main` receives `caps: Caps`, the set the host *granted*. Everything else is derived from it by narrowing.

```
caps.console()                      -> Console
caps.fs_read::<"./inbox">()         -> FsRead<"./inbox">
caps.fs_write::<"./out">()          -> FsWrite<"./out">
caps.net::<"api.example.com:443">() -> Net<"api.example.com:443">
caps.tool::<"mail.send">()          -> Tool<"mail.send">
caps.model()                        -> Model        // quarantined: no tools, no files
caps.rand()                         -> Rand
caps.clock()                        -> Clock
```
The scope in `<...>` must be a compile-time string constant in the `sealed` build profile. A function that takes no capability parameters and captures none is **pure**: it cannot read, write, call or leak.

### 4.4 Profiles
- `default` — normal programs.
- `sealed` — scopes must be constants, `declassify`/`endorse` need explicit caps, fuel limit mandatory. Required by `--require-seal`.
- `plan` — `sealed` + total: no recursion, no `while`, only `for` over bounded ranges/lists. Intended for programs an AI agent writes.

---

## 5. Example programs

### 5.1 Hello, with authority visible

```mohar
// hello.mo
fn main(caps: Caps) {
    let out = caps.console();
    out.println("namaste, duniya");
}
```
`mohar review hello.mo` prints:
```
authority:  Console (write)
files:      none
network:    none
crypto:     none
verdict:    nothing beyond printing to the terminal
```

### 5.2 Constant-time tag check

```mohar
use std.ct;

// `expected` is secret. Comparing it to the attacker-supplied `given`
// must not leak how many bytes matched.
fn tag_ok(expected: secret [u8; 32], given: [u8; 32]) -> bool {
    ct::verify_eq(expected, given)      // trusted declassifier: reveals only 1 bit
}
```
What the checker does **not** allow:
```mohar
fn bad(expected: secret [u8; 32], given: [u8; 32]) -> bool {
    if expected == given { true } else { false }
}
// error[E101]: branch condition depends on a secret value
//   --> bad.mo:2:8
//   help: use std.ct::select or std.ct::verify_eq; secret-dependent branches leak timing
```
Other rules in the same family: `E102` secret used as an array index, `E103` secret as a loop bound, `E104` variable-time operation (`/`, `%`) on a secret.

### 5.3 A secret trying to reach the log — rejected, then fixed

```mohar
use std.aead;

fn main(caps: Caps) {
    let log  = caps.console();
    let key: secret [u8; 32] = caps.rand().secret_bytes::<32>();

    log.println(key.to_hex());                // error[E105]: secret value flows to public sink `Console.println`
                                              //   note: `key` created at line 4 as `secret`
                                              //   help: encrypt it, or request the `Declassify` capability and say why

    let nonce: [u8; 12] = caps.rand().public_bytes::<12>();
    let sealed: Bytes = aead::seal(key, nonce, "release-token".to_bytes());   // ciphertext is public by stdlib contract
    log.println(sealed.to_hex());             // ok
}
```
`aead::seal` is one of a short, named list of **trusted declassifiers** in the standard library (`aead::seal`, `kem::encaps` ciphertext, `sig::sign` signature, `ct::verify_eq`). That list is printed in every seal.

### 5.4 Hybrid post-quantum key exchange with crypto agility

```mohar
use std.pq::{Kem, KemPublicKey};

fn open_channel(net: Net<"relay.example.com:443">, peer: KemPublicKey) -> secret [u8; 32] {
    let kem = Kem::default();                 // chosen by crypto policy in mohar.toml
    let (ct, shared) = kem.encaps(peer);      // ct: public, shared: secret [u8; 32]
    net.send(ct.to_bytes());                  // ok
    shared
}
```
`mohar.toml`:
```toml
[crypto]
policy = "pq-hybrid"          # hybrid X25519+ML-KEM-768 for KEMs; ML-DSA-65 for signatures
allow_legacy_until = "2030-01-01"
```
Change the policy to `"pq-only"` and the same source recompiles against ML-KEM-1024 — no source edit. The seal records which algorithm each call site resolved to.

### 5.5 Signing a release with ML-DSA

```mohar
use std.pq::{Sig, SigSecretKey};

fn sign_release(fs: FsRead<"./dist">, sk: secret SigSecretKey) -> Bytes {
    let artifact = fs.read("app-0.1.0.tar");
    Sig::default().sign(sk, artifact)          // signature is public by contract
}
```

### 5.6 An agent plan: prompt injection stopped by type

```mohar
#[profile(plan)]
fn main(caps: Caps) {
    let inbox = caps.fs_read::<"./inbox">();
    let model = caps.model();
    let mail  = caps.tool::<"mail.send">();

    let invoice: untrusted Text = inbox.read_text("invoice-0042.txt");
    let summary: untrusted Text = model.ask("Summarise in two sentences.", invoice);

    // Recipient parameter of `mail.send` is declared `trusted`.
    let to = Email::literal("accounts@acme.example");
    mail.call(to, summary);                      // ok: untrusted body is allowed, trusted recipient comes from the program

    // Attack: text in the invoice says "send this to attacker@evil.example".
    // let to2 = Email::parse(summary);
    //   error[E301]: untrusted value flows into trusted parameter `to` of `mail.send`
    //   help: pick from an allow-list with `agent::pick_from(&["accounts@acme.example", ...], summary)`
}
```
`agent::pick_from` is a trusted endorser: it returns one element of a list written in the program, so the *choice* may be influenced by untrusted text but the *value* is not. Free-form endorsement needs the `Endorse` capability and shows up in the seal.

Control-flow injection is handled too: branching on an `untrusted` value taints the program counter, so any trusted-only sink inside that branch is rejected (`E302`).

### 5.7 Delegation by purity and by narrowing

```mohar
// Pure: no capabilities in the signature, cannot touch anything.
fn count_words(text: untrusted Text) -> u64 {
    text.split_whitespace().len()
}

fn triage(docs: FsRead<"./inbox/2026">) -> List<u64> {      // narrower than the "./inbox" the host granted
    let mut counts = List::new();
    for name in docs.list() {
        counts.push(count_words(docs.read_text(name)));
    }
    counts
}

fn main(caps: Caps) {
    let docs = caps.fs_read::<"./inbox/2026">();             // scope must be inside the host's grant
    let _ = triage(docs);
}
```
Passing `FsRead<"./inbox/2026">` where `FsRead<"./inbox/2026/q1">` is expected is a type error: scopes only get narrower (`FsRead<"a/b"> <: FsRead<"a">`).

### 5.8 Quantum-risk lint and CBOM

```mohar
use std.legacy::ecdsa_p256;       // warning[Q101]: ECDSA P-256 is quantum-vulnerable (NIST IR 8547: deprecate 2030, disallow 2035)
                                  //   allowed until 2030-01-01 by mohar.toml; remove or migrate before then
```
```
$ mohar cbom --format cyclonedx
{ "bomFormat": "CycloneDX", "components": [
  { "type": "cryptographic-asset", "name": "ECDSA-P256", "assetType": "algorithm",
    "quantumSafe": false, "evidence": "hello.mo:1:5 use std.legacy::ecdsa_p256" },
  { "type": "cryptographic-asset", "name": "ML-DSA-65",  "quantumSafe": true,
    "evidence": "release.mo:9:5 Sig::default() -> ML-DSA-65" } ] }
```
With `policy = "pq-only"` the same `use` is an error (`E402`), not a warning.

---

## 6. Type system, capabilities and guarantees

### 6.1 Labels
Each type carries `(conf, integ)` where `conf ∈ {Public ⊑ Secret}` and `integ ∈ {Trusted ⊑ Untrusted}`. Join of two labels is componentwise max. Flow rule, in plain words: *a secret value never goes to a public slot, and an untrusted value never goes to a trusted slot.* The other directions are fine (public → secret slot, trusted → untrusted slot). Formally, `(c, i)` may flow to `(c', i')` iff `c ⊑ c'` and `i ⊑ i'`.

Program-counter label: branching on `untrusted` raises the pc integrity; sinks that require trusted arguments or trusted pc are rejected inside. Branching on `secret` is **not allowed at all** in v0.1 (simplest sound rule). v0.2 can add FaCT-style rewriting of secret `if` into constant-time selects for pure arms.

Arithmetic, comparison and indexing rules for secrets: only operations that map to constant-time instructions (`+ - * & | ^ << >>` by public amounts, `ct::select`, `ct::eq`, `ct::lt`). Division, modulo, secret shift amounts, secret indices, secret loop bounds are errors.

Declassification (`declassify(x, reason)`) needs the `Declassify` capability and a string reason that is copied into the seal. Endorsement (`endorse`) needs `Endorse`. A `sealed` program that never receives either capability provably contains neither.

### 6.2 Capabilities
- Unforgeable: only `main`'s `Caps` argument and `narrow`-style derivation produce them; there is no constructor and no cast.
- Scoped by types: `FsRead<"./inbox">`; subtyping by prefix for paths, by suffix for hosts, equality for tool names.
- Explicit: a function's authority is exactly the capability-typed values it receives. The call graph from `main` gives the program's total authority → this is what the seal reports.
- No closures capturing capabilities in v0.1, so there are no hidden authority paths.
- Runtime backstop: every capability operation re-checks its scope in the host (defence in depth against checker bugs), including path normalisation (`..`, symlinks refused by default).

### 6.3 Crypto model
- Algorithms are opaque types (`Kem`, `Sig`, `Aead`, `Hash`, `Kdf`) resolved by policy at compile time.
- Defaults: KEM = X-Wing hybrid *or* ML-KEM-768 hybrid-with-X25519 depending on backend maturity; Signature = ML-DSA-65; Hash = SHA3-256; AEAD = ChaCha20-Poly1305 (symmetric crypto is not the quantum problem; AES-256 and SHA-2/3 remain acceptable).
- SLH-DSA is available as an optional second signature (dual-signing the seal) as a hedge against a lattice break.
- **No home-made cryptography.** Mohar's standard library is thin glue over audited-or-widely-reviewed crates behind one backend trait. Today that means RustCrypto (`ml-kem`, `ml-dsa`, `slh-dsa`, `chacha20poly1305`, `sha3`, `hkdf`, `x25519-dalek`) as the default and `aws-lc-rs` as an alternative backend. Versions are pinned; see §7.6 for the audit caveat.

### 6.4 The seal
`mohar build` → `app.mhr` (canonical IR). `mohar seal app.mhr --key release.key` → `app.mohar`:

```json
{
  "format": "mohar-seal/0",
  "artifact": { "ir_sha3_256": "…", "source_sha3_256": "…", "std_sha3_256": "…", "compiler": "mohar 0.1.0" },
  "profile": "plan",
  "authority": [
    { "cap": "FsRead", "scope": "./inbox", "ops": ["read", "list"] },
    { "cap": "Tool",   "scope": "mail.send" },
    { "cap": "Model" }
  ],
  "flows": { "declassify": [], "endorse": [],
             "trusted_declassifiers_used": ["aead::seal"], "trusted_endorsers_used": ["agent::pick_from"] },
  "crypto": [ { "call_site": "main.mo:14", "algorithm": "ML-DSA-65", "quantum_safe": true } ],
  "limits": { "fuel": 5000000, "memory_mib": 64 },
  "signatures": [ { "alg": "ML-DSA-65", "key_id": "…", "sig": "…" } ]
}
```
Serialised with RFC 8785 canonical JSON, so the bytes that are signed are unambiguous. `mohar run --require-seal --trust trusted-keys.toml app.mohar` refuses to start unless (1) a signature verifies against a trusted key, (2) the IR hash matches, and (3) the authority is a subset of the host's grant file. `mohar review app.mohar --against grant.toml` prints the human diff.

### 6.5 Guarantees — and their limits

What v0.1 aims to guarantee **for well-typed Mohar code**:

| # | Guarantee | How | Evidence in v0.1 |
|---|---|---|---|
| G1 | No ambient authority: code can only use capabilities it was handed | No global I/O, capability values unforgeable | Type checker + negative test corpus |
| G2 | Authority report is complete w.r.t. the source | Derived from the same call graph the interpreter runs | Differential test: run with capability tracing, compare to seal |
| G3 | No secret reaches a public sink without a *named* declassifier | Label flow rules | Property tests (§8) — same program, two secrets, equal public traces |
| G4 | No untrusted value reaches a trusted parameter without a *named* endorser | Integrity labels + pc label | Same |
| G5 | Secret-dependent branches, indices, loop bounds, variable-time ops are rejected | Type checker | Negative corpus |
| G6 | Build is reproducible: same inputs → same hash | Canonical IR, no floats, no wall-clock, sorted maps, pinned deps | CI builds twice on two OSes and compares |
| G7 | A seal can't be altered without detection | ML-DSA signature over canonical bytes | Tamper tests |

What it does **not** guarantee (say this in the README):

1. **Not a proof.** v0.1 has a typed semantics on paper and tests, not a mechanised soundness proof. A proof sketch for noninterference of the label rules is a v0.3 goal; Coq/Lean mechanisation is outside the scope of a solo project.
2. **Constant-time is at the language level only.** Rejecting secret branches does not make the interpreter, a JIT, the OS or the CPU constant-time. Real timing claims need a native or CT-Wasm-style backend plus verification of the output (planned, not v0.1). The PQC crates are not audited by third parties and don't promise side-channel freedom on every platform.
3. **Termination, timing and resource channels are not covered** by the label system (termination-insensitive noninterference). Fuel and memory limits bound but do not hide resource use.
4. **Declassifiers and endorsers are trusted code.** The short named list in `std` is the trusted base; a bug there is a bug in the guarantee.
5. **A seal says who approved it, not that the approver was right.** Least privilege limits blast radius; it cannot tell whether a granted action was a good idea.
6. **Prompt injection is constrained, not cured.** A model can still be talked into a *bad plan inside its granted authority*, or into harmful *content* in an untrusted body. Mohar prevents untrusted text from choosing trusted arguments and from widening authority.
7. **Host and key compromise are out of scope.** If the machine running `mohar run` or the signing key is compromised, the seal is worthless.
8. **Hardware side channels** (speculation, power, EM, cache) and fault injection are out of scope.
9. **Crypto agility is a policy convenience**, not a downgrade protection protocol; protocol-level negotiation (to prevent downgrade attacks) remains the application's job.
10. **Quantum timelines are uncertain.** "Post-quantum" means "based on standards designed to resist known quantum attacks", not "proven quantum-proof".

---

## 7. Implementation plan for v0.1

### 7.1 Toolchain and workspace
Rust 2024 edition, stable toolchain, MSRV 1.87 (the PQC crates need it). Cargo workspace:

| Crate | Responsibility |
|---|---|
| `mohar-syntax` | Hand-written lexer, Pratt/recursive-descent parser, AST, spans |
| `mohar-diag` | Diagnostics (`miette` or `ariadne`), error codes (`E1xx` flow, `E2xx` capability, `E3xx` integrity, `E4xx` crypto policy, `Q1xx` quantum lints) |
| `mohar-types` | Name resolution, bidirectional type checker, label lattice, capability scope subtyping, profile rules |
| `mohar-ir` | Typed, labelled ANF-style IR ("MIR"); canonical serialisation; hashing |
| `mohar-interp` | Tree/MIR interpreter, fuel counter, capability host, tracing |
| `mohar-std` | Built-ins: `ct`, `aead`, `hash`, `pq`, `agent`, `legacy`; backend trait for crypto |
| `mohar-seal` | Authority extraction, CBOM, seal format, sign/verify, grant files |
| `mohar-cli` | `mohar check / run / build / seal / review / cbom / fmt / repl` |
| `mohar-wasm` | `wasm-bindgen` wrapper of check + interpret for the playground |

Key dependencies (pin exact versions; re-check APIs at implementation time): `clap`, `miette`, `serde`, `serde_jcs`, `sha3`, `sha2`, `hkdf`, `chacha20poly1305`, `subtle`, `zeroize`, `ml-kem`, `ml-dsa`, `slh-dsa`, `x25519-dalek`, optionally `x-wing` (experimental) and `aws-lc-rs`; dev: `insta`, `proptest`, `criterion`, `cargo-fuzz`, `dudect-bencher`.

### 7.2 Front end
- Lexer: UTF-8, spans, no regex generator.
- Parser: recursive descent + Pratt for expressions; error recovery to report several errors per run; `mohar fmt` comes from the same AST (v0.2).
- Name resolution: modules are files; `use` paths; no cycles.

### 7.3 Type checker
- Bidirectional: function signatures fully annotated; locals inferred.
- Types = base type + `(conf, integ)` label + (for capabilities) a scope literal.
- Checks, in order: types → labels → pc → capabilities/scopes → profile rules → crypto policy.
- Error messages are part of the product: every `E1xx/E3xx` points at the *source of the label* ("`key` was created secret here") like Rust points at borrows.

### 7.4 IR
Typed ANF with labels preserved on every temporary. Canonical form: deterministic ordering, no floats, no host addresses, no timestamps. `sha3_256(canonical_ir)` is the artifact hash.

### 7.5 Backends
- **v0.1 — interpreter over MIR.** Safe, easy to audit, runs in the browser via WASM for the playground. Slow by design (target: within ~50× of native on arithmetic loops; crypto built-ins run at native speed).
- **v0.2 — WebAssembly codegen** with `wasm-encoder`; runs on `wasmtime`; secrets lower only to a CT-Wasm-like instruction subset; gives a real sandbox boundary and a path to the browser without the interpreter.
- **v0.3 — Cranelift AOT/JIT** for native speed, plus an output checker for constant-time (inspired by Jasmin's checker and dudect-style timing tests).

### 7.6 Standard library scope for v0.1
- `core`: Option/Result/List/Bytes/Text, integer helpers with checked and wrapping ops, `fmt`.
- `ct`: `select`, `eq`, `lt`, `verify_eq`, `zeroize`.
- `hash`: SHA3-256, SHA-256, HKDF.
- `aead`: ChaCha20-Poly1305 (`seal`/`open`).
- `pq`: `Kem` (ML-KEM-768/1024, hybrid with X25519), `Sig` (ML-DSA-44/65/87, optional SLH-DSA), key generation via `Rand` capability.
- `agent`: `model.ask`, `pick_from`, `Email/Url/Id` smart constructors with validation, `tool.call` (JSON-RPC to host), schema-checked parsing that yields `trusted` only on exact enum/regex-anchored matches.
- `legacy`: `ecdsa_p256`, `rsa_pss` — compile with warnings so the quantum lint has something to say.
- Not in v0.1: floats, networking beyond a mock `Net`, threads, FFI, user generics, macros.

**Crypto rule:** no hand-written primitives anywhere. Everything calls RustCrypto (or `aws-lc-rs`) through `trait CryptoBackend`. The README and the seal list the backend and crate versions. Because the RustCrypto PQ crates say they have never been independently audited, Mohar's docs say "use the `aws-lc-rs` backend or another audited library if you need assurance", and the CLI prints a one-time notice when the default backend is selected.

### 7.7 Milestones (three weeks, one developer)
**Week 1 — language core.** Repo, CI, lexer/parser/AST, diagnostics, base type checker, MIR, interpreter, `mohar run hello.mo`, golden tests. *Exit:* fib, string/bytes programs, struct/enum/match run.
**Week 2 — the security core.** Label lattice and pc rules, capability types with scopes, authority extraction, `ct` and `hash`/`aead` built-ins, negative corpus (40+ must-fail programs), property tests for noninterference, deterministic IR hashing. *Exit:* 5.2, 5.3, 5.6, 5.7 behave exactly as written.
**Week 3 — PQC, seal, packaging.** `pq` built-ins, crypto policy + `Q1xx/E4xx`, CBOM, seal/verify/review, reproducible-build CI, WASM playground (check + interpret), docs, README, examples, `v0.1.0` tag, `cargo install mohar-cli`.

**Cut line if time slips** (drop in this order): playground → SLH-DSA → X-Wing/hybrid → CBOM CycloneDX export → `fmt`. Never cut: labels, capabilities, seal/verify, negative corpus, honest limits section.

### 7.8 Definition of done for v0.1
1. All eight programs in §5 behave as documented (valid ones run; invalid ones fail with the stated error code).
2. `mohar seal` → `mohar run --require-seal` works end-to-end; tampering with either the artifact or the manifest is rejected.
3. Two builds of the same source on Linux and macOS give identical hashes in CI.
4. ≥ 40 negative tests and ≥ 20 positive tests pass; fuzzing ran ≥ 1 hour on lexer and parser with no panics.
5. README states the guarantees *and* the limits from §6.5 and the unaudited-crate warning.

---

## 8. Tests and benchmarks

### 8.1 Tests
- **Positive programs** (`tests/ok/*.mo`) with expected output — golden files via `insta`.
- **Negative corpus** (`tests/leaks/*.mo`) — every file must fail with one specific error code and span. Cover: secret branch/index/loop/divide; secret to console/net/fs/tool; secret via struct field, tuple, enum payload, list element; secret through function return; untrusted to trusted parameter; control-flow injection; capability forging; scope widening; use of `declassify` without the cap; `..` and symlink escapes; recursion in `plan` profile.
- **Property tests** (`proptest`): generate small well-typed programs; run twice with different secret inputs; public output traces must be identical (termination-insensitive noninterference, bounded fuel). Same idea for integrity with untrusted inputs and trusted sinks.
- **Authority differential:** run with capability tracing and assert the observed set ⊆ sealed authority; assert sealed authority ⊆ what static analysis predicted.
- **Crypto known-answer tests:** NIST ACVP / FIPS vectors for ML-KEM, ML-DSA, SLH-DSA through the Mohar built-ins; cross-check hybrid shared secrets.
- **Seal tests:** tamper with one byte of manifest, artifact, signature, key id; wrong key; downgraded algorithm; replayed older seal; expect rejection.
- **Fuzzing:** `cargo-fuzz` on lexer, parser, type checker, and seal verifier (structure-aware JSON).
- **Reproducibility:** CI job builds twice (Linux, macOS) and diffs hashes.
- **Timing sanity:** `dudect-bencher` on `ct::eq` / `verify_eq` to catch gross mistakes. Documented as a smoke test, **not** proof.

### 8.2 Benchmarks (publish raw numbers, whatever they are)
| Benchmark | Why |
|---|---|
| `fib(30)`, nested loops, byte-array xor 1 MiB | interpreter baseline vs Python/Lua/native Rust |
| SHA3-256 over 1 MiB; ChaCha20-Poly1305 1 MiB | built-in marshalling overhead vs raw Rust crate (goal < 5%) |
| ML-KEM-768 keygen/encaps/decaps ×10k; ML-DSA-65 sign/verify ×1k | PQC cost through the language vs direct crate use |
| Type-check and manifest generation for a 1k-line program | compile-time cost of labels and capabilities |
| Seal / verify latency | overhead of the seal path |
| Binary/WASM size of playground | adoption friction |

Methodology: `criterion`, pinned CPU governor, 3 machines if possible, scripts in `bench/`, results in `bench/RESULTS.md` with hardware listed. The README's performance claim in v0.1 is deliberately modest: **"crypto runs at native speed; the interpreter is slow; the WASM backend is next."**

---

## 9. Repository layout

```
mohar/
├── Cargo.toml                  # workspace
├── LICENSE                     # MIT, Copyright (c) 2026 Saddam Malik
├── README.md                   # pitch, 60-second demo, honest limits
├── SECURITY.md                 # how to report, supported versions, threat model link
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── CHANGELOG.md
├── mohar.toml.example
├── crates/
│   ├── mohar-syntax/  mohar-diag/  mohar-types/  mohar-ir/
│   ├── mohar-interp/  mohar-std/   mohar-seal/   mohar-cli/  mohar-wasm/
├── examples/                   # the eight programs from DESIGN §5, runnable
├── tests/
│   ├── ok/  leaks/  seals/  kat/
├── fuzz/                       # cargo-fuzz targets
├── bench/                      # criterion benches + RESULTS.md
├── docs/
│   ├── book/                   # mdBook: tutorial, reference, threat model, guarantees & limits
│   ├── rfcs/                   # design notes for v0.2+
│   └── prior-art.md            # the honest landscape (adapted from DESIGN §2)
├── playground/                 # static site + wasm build
└── .github/
    ├── workflows/ci.yml        # fmt, clippy, test, fuzz-smoke, repro-build, deny, audit
    ├── ISSUE_TEMPLATE/
    └── dependabot.yml
```
Supply-chain hygiene for the project itself: `cargo-deny`, `cargo-audit`, `Cargo.lock` committed, pinned CI actions by SHA, signed tags.

---

## 10. License

`LICENSE` (MIT):

```
MIT License

Copyright (c) 2026 Saddam Malik

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
Author and committer for every commit: `Saddam Malik <350492721+malikdevhunk@users.noreply.github.com>`, no co-author trailers. `Cargo.toml` `authors = ["Saddam Malik"]`.

---

## 11. Roadmap after v0.1
- **v0.2** — WASM backend, `mohar fmt`, FaCT-style rewriting of secret `if` for pure arms, named labels (`secret<"api_key">`) and per-label declassification policy, networking over a real `Net`.
- **v0.3** — Cranelift backend, output constant-time checker, user generics, LSP, proof sketch of noninterference in the docs.
- **v0.4** — attenuable *delegation tokens* (Biscuit/UCAN-style) so a sealed program can hand a narrower, signed grant to another process; remote attestation hooks.
- **Later** — formal model in Lean or Coq if a collaborator appears; independent security review of the std crypto glue.

## 12. Open questions to settle early
1. Seal key format: raw ML-DSA key files vs PKCS#8-style containers (check what RustCrypto finalises).
2. Whether `Text` indexing by byte or by scalar is allowed on secrets (probably neither).
3. Exact wording of the `E105` notes — most of the language's first impression is its error messages; budget time for them.
4. Whether `plan` should forbid user-defined functions entirely in v0.1 (simpler totality argument) or allow non-recursive ones.
