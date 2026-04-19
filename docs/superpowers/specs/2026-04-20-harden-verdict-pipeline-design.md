# Harden Verdict Pipeline — Design

Date: 2026-04-20
Scope: single design, single iteration (bundled A).
Related issues: #15 (hosting-only yields false DETECTED in RU space), #37 (TUN probe success marks DETECTED without mismatch).

## 1. Goals

1. Fix #37: a successful TUN active probe must not mark the run as DETECTED just because `vpnIp != null`.
2. Fix #15: a lone GeoIP hosting/proxy signal inside RU-confirmed location must not yield DETECTED.
3. Enforce module isolation promised by the README: one checker's exception must not abort the whole run.
4. Add a cross-checker IP consensus layer: collect every public IP observed per channel (DIRECT / VPN / PROXY / CDN), dedupe, compare across channels and geography, surface mismatches to the verdict engine and to the user.
5. Extend the TUN probe to query both an RU and a non-RU target so geo-divergence inside the VPN channel is observable.
6. Replace the current 3-bit verdict matrix with explicit, ordered rules; break GeoIP into typed facts (`outsideRu`, `hosting`, `proxyDb`, `fetchError`).

## 2. Architecture

### 2.1 New units

- `model/IpConsensus.kt` — `IpConsensusResult`, `ObservedIp`, `Channel`, `TargetGroup`, `UnparsedIp`, `AsnInfo`.
- `model/CategoryResult.kt` (edit) — add `geoFacts: GeoIpFacts? = null`. New `GeoIpFacts` data class.
- `checker/ipconsensus/IpConsensusBuilder.kt` — pure aggregator. Deps: checker results + an injected `AsnResolver`.
- `checker/ipconsensus/AsnResolver.kt` — lazy per-IP country/ASN lookup with in-memory cache (per run), using the existing `ResolverNetworkStack`.

### 2.2 Edited units

- `GeoIpChecker` — populate `geoFacts`. Existing `CategoryResult.detected`/`needsReview` semantics preserved for UI compatibility; `VerdictEngine` stops consuming them.
- `UnderlyingNetworkProber` — probe both an RU target and a non-RU target; return `PerTargetProbe` for each.
- `DirectSignsChecker.reportTunActiveProbe` — no longer raises `detected=true` on mere probe success; raises only on `dnsPathMismatch`. Otherwise emits `needsReview` evidence and lets the verdict engine decide via consensus.
- `VerdictEngine` — rewritten as ordered rules R1..R7, reads `IpConsensusResult` and `GeoIpFacts` directly.
- `VpnCheckRunner` — `coroutineScope` → `supervisorScope`; each child wrapped with `safeAsync(fallback)`; adds a consensus stage before `VerdictEngine.evaluate`; emits `CheckUpdate.IpConsensusReady`.
- `CheckResult` — new field `ipConsensus: IpConsensusResult`.

### 2.3 Flow

```
GeoIpChecker ─────────────┐
IpComparisonChecker ──────┤
CdnPullingChecker ────────┼──► IpConsensusBuilder ──► VerdictEngine ──► Verdict
UnderlyingNetworkProber ──┤          ▲
BypassChecker ────────────┘          │
                                 AsnResolver (lazy, bounded)
```

`IpConsensusBuilder` depends only on model types and the `AsnResolver` interface. No back-references to checkers. Pure-testable.

## 3. Data model

### 3.1 `GeoIpFacts`

```kotlin
data class GeoIpFacts(
    val ip: String?,              // normalized; null if fetchError
    val countryCode: String?,     // ISO-3166-1-alpha2, uppercase; null if blank/missing
    val asn: String?,             // pretty-formatted, as today
    val outsideRu: Boolean,       // countryCode != null && != "RU"
    val hosting: Boolean,         // snapshot.isHosting
    val proxyDb: Boolean,         // snapshot.isProxy
    val fetchError: Boolean,      // both providers failed / noProvider
)
```

`CategoryResult` gets `val geoFacts: GeoIpFacts? = null`. All other checkers leave it null.

### 3.2 `IpConsensusResult`

```kotlin
enum class Channel { DIRECT, VPN, PROXY, CDN }
enum class TargetGroup { RU, NON_RU }

data class AsnInfo(val asn: String?, val countryCode: String?)

data class ObservedIp(
    val value: String,               // normalized
    val family: IpFamily,            // V4 | V6
    val channel: Channel,
    val sources: Set<String>,        // e.g. "geoip:ipapi.is", "underlying-prober.ru.vpn"
    val countryCode: String?,        // from GeoIpFacts or AsnResolver
    val asn: String?,
    val targetGroup: TargetGroup?,   // non-null only for probe-derived IPs
)

data class UnparsedIp(val raw: String, val source: String)

data class IpConsensusResult(
    val observedIps: List<ObservedIp>,
    val unparsedIps: List<UnparsedIp>,
    val channelIps: Map<Channel, Set<String>>,
    val channelConflict: Set<Channel>,         // ≥2 distinct IPs inside one channel, same family
    val crossChannelMismatch: Boolean,         // ≥2 channels with disjoint IP sets in same family
    val dualStackObserved: Boolean,
    val foreignIps: Set<String>,               // countryCode known && != "RU"
    val geoCountryMismatch: Boolean,           // ≥2 IPs with different known countryCodes
    val sameAsnAcrossChannels: Boolean,
    val warpLikeIndicator: Boolean,            // PROXY IP not in DIRECT∪VPN
    val probeTargetDivergence: Boolean,        // VPN: ru.vpnIp != nonRu.vpnIp, same family, both present
    val probeTargetDirectDivergence: Boolean,  // DIRECT: ru.directIp != nonRu.directIp, same family
    val needsReview: Boolean,                  // source errors / timeouts / unparsed IPs
) {
    companion object { fun empty(needsReview: Boolean = false): IpConsensusResult = … }
}
```

### 3.3 `UnderlyingNetworkProber.ProbeResult` (evolved)

```kotlin
data class ProbeResult(
    val vpnActive: Boolean,
    val ruTarget: PerTargetProbe,
    val nonRuTarget: PerTargetProbe,
    val vpnError: String?,                      // first non-blank across targets
    val tunProbeDiagnostics: TunProbeDiagnostics?,  // aggregated; `vpnPath` reflects ruTarget by default, nonRuTarget exposed via `tunProbeDiagnostics.secondaryPath` (new nullable field)
    // deprecated compat shims (computed):
    val vpnIp: String? get() = ruTarget.vpnIp ?: nonRuTarget.vpnIp,
    val directIp: String? get() = ruTarget.directIp ?: nonRuTarget.directIp,
    val vpnIpComparison: VpnIpComparison? get() = ruTarget.comparison ?: nonRuTarget.comparison,
)

data class PerTargetProbe(
    val targetHost: String,
    val targetGroup: TargetGroup,
    val directIp: String?,
    val vpnIp: String?,
    val comparison: VpnIpComparison?,
    val error: String?,
)
```

Target selection: pick one already-used RU endpoint from the existing RU group of `IpComparisonChecker` and one from the non-RU group. Both are already validated by the app.

## 4. Channel attribution

| Source | Channel | Target group |
|---|---|---|
| `geoIp.geoFacts.ip` | DIRECT | — |
| `ipComparison.ruGroup.responses[].ip` | DIRECT | — |
| `ipComparison.nonRuGroup.responses[].ip` | DIRECT | — |
| `cdnPulling.responses[].observedIp` | CDN | — |
| `underlyingProbe.ruTarget.directIp` | DIRECT | RU |
| `underlyingProbe.ruTarget.vpnIp` | VPN | RU |
| `underlyingProbe.nonRuTarget.directIp` | DIRECT | NON_RU |
| `underlyingProbe.nonRuTarget.vpnIp` | VPN | NON_RU |
| `bypass.directIp` | DIRECT | — |
| `bypass.vpnNetworkIp` | VPN | — |
| `bypass.underlyingIp` | DIRECT | — |
| `bypass.proxyIp` | PROXY | — |

## 5. Normalization and dedup

1. Trim, lowercase for IPv6.
2. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) → IPv4.
3. Strict numeric parse (no DNS); invalid → `unparsedIps`, contributes to `needsReview=true`.
4. `family` derived post-normalization.
5. Dedup key: `(normalizedValue, channel)`. Same IP in different channels remains two records (required for cross-channel mismatch logic). Within a channel, `sources` sets merge.

## 6. Flag derivation (order)

1. `channelConflict[C]` — channel C has ≥2 distinct IPs in one family. Pure dual-stack is not a conflict.
2. `dualStackObserved` — any channel has both V4 and V6.
3. `crossChannelMismatch` — exists pair (C1, C2), C1 ≠ C2, same family, disjoint and both non-empty.
4. `foreignIps` — `{ ip : countryCode(ip) != null && != "RU" }`.
5. `geoCountryMismatch` — ≥2 IPs with different known countries.
6. `sameAsnAcrossChannels` — for IPs that participate in a cross-channel mismatch, ASNs coincide.
7. `warpLikeIndicator` — PROXY ∖ (DIRECT ∪ VPN) non-empty.
8. `probeTargetDivergence` — VPN: `ruTarget.vpnIp != nonRuTarget.vpnIp`, both non-null, same family.
9. `probeTargetDirectDivergence` — DIRECT: `ruTarget.directIp != nonRuTarget.directIp`, both non-null, same family.
10. `needsReview` — source error / timeout / unparsed IP.

## 7. AsnResolver

- Called only for IPs that enter the consensus and lack country/asn from GeoIp.
- Parallel batch, overall 5 s timeout, per-request 3 s.
- Hard cap: 6 IPs per run (excess is suppressed and flagged to `needsReview`).
- In-memory cache keyed by normalized IP, lifetime = single scan.
- Backed by `ResolverNetworkStack` with the scan's `DnsResolverConfig`.

## 8. DirectSignsChecker changes

### 8.1 `reportTunActiveProbe` (per target, applied once per `PerTargetProbe`)

For each `PerTargetProbe` where `vpnIp != null`:
- Always append an informational finding ("TUN probe returned X for {target group}"). Not evidence.
- If `comparison.dnsPathMismatch == true` → evidence `TUN_ACTIVE_PROBE` with `detected=true, confidence=HIGH` (the direct DNS-path leak is authoritative locally).
- Else → evidence `TUN_ACTIVE_PROBE` with `detected=false, needsReview=true, confidence=MEDIUM`. Final DETECTED promotion is the verdict engine's job, based on `IpConsensusResult`.

Aggregated `SignalOutcome`:
- `detected = any(target has dnsPathMismatch)`.
- `needsReview = any(target has vpnIp && !dnsPathMismatch)`.

### 8.2 Other direct signals (unchanged)

`TRANSPORT_VPN`, `IS_VPN`, `VpnTransportInfo`, known-port proxy detection — preserved as today. They remain `detected=true` locally.

## 9. GeoIpChecker changes

- `check()` still returns `CategoryResult`. Field `geoFacts` is always populated:
  - On success: facts derived from merged snapshot. `countryCode` uppercased, empty → null.
  - On `noProviderResult` / `errorResult`: `GeoIpFacts(fetchError=true)`, all booleans false, IP/country/ASN null.
- `CategoryResult.detected`/`needsReview` semantics preserved so existing UI does not regress.
- `EvidenceItem(source=GEO_IP)` keeps being emitted for UI but is no longer consumed by the verdict engine.

## 10. VerdictEngine rewrite

New signature:

```kotlin
fun evaluate(
    geoIp: CategoryResult,
    directSigns: CategoryResult,
    indirectSigns: CategoryResult,
    locationSignals: CategoryResult,
    bypassResult: BypassResult,
    ipConsensus: IpConsensusResult,          // non-null; .empty() when network disabled
    nativeSigns: CategoryResult = emptyCategoryResult(),
): Verdict
```

Ordered rules, first match wins:

**R1 — Hard-detect bypass.** Any detected bypass evidence with source in `{SPLIT_TUNNEL_BYPASS, XRAY_API, VPN_GATEWAY_LEAK, VPN_NETWORK_BINDING}` → DETECTED.

**R2 — Hard-detect direct locals.** Any detected direct evidence with source in `{DIRECT_NETWORK_CAPABILITIES, SYSTEM_PROXY}` → DETECTED. (This is a behavior change: today the 3-bit matrix could suppress these without a geo hit.)

**R3 — IP consensus detect.**
Evaluate in order, first match wins:
- R3a. `probeTargetDivergence` (with or without `geoCountryMismatch`, same-country or different-country) → DETECTED. Rationale: VPN returning different public IPs for RU vs non-RU targets is explicit split-routing; authoritative on its own.
- R3b. `probeTargetDirectDivergence && (geoCountryMismatch || foreignIps.isNotEmpty())` → DETECTED. DIRECT channel hitting different exit nodes for RU vs non-RU targets combined with any foreign geo signal.
- R3c. `crossChannelMismatch && (foreignIps.isNotEmpty() || geoCountryMismatch || warpLikeIndicator)` → DETECTED. Generic case: channels disagree and at least one IP is foreign / warp-like.

**R4 — Location vs Geo.**
Let `locationConfirmsRussia` derive as today from `locationSignals.findings` (network_mcc_ru/cell_country_ru/location_country_ru).
Let `geo = geoIp.geoFacts`.
- If `locationConfirmsRussia && geo?.outsideRu == true` → DETECTED.
- Else if `locationConfirmsRussia && (geo?.hosting == true || geo?.proxyDb == true) && geo?.outsideRu != true && !anyOtherSignal` → NEEDS_REVIEW. (Issue #15 regression target.)

Where `anyOtherSignal` = any detected direct or indirect evidence OR `crossChannelMismatch` OR `probeTargetDivergence` OR `probeTargetDirectDivergence`.

**R5 — Matrix (2-bit: geo × indirect).**
- `geoHit = geo?.outsideRu == true` (hosting/proxyDb/fetchError do not count here).
- `indirectHit = indirectSigns.evidence.any { it.detected && it.source in MATRIX_INDIRECT_SOURCES } || nativeSigns.evidence.any { it.source in MATRIX_INDIRECT_SOURCES && it.detected }`.
- `(false, false)` → NOT_DETECTED; `(false, true)` → NOT_DETECTED; `(true, false)` → NEEDS_REVIEW; `(true, true)` → DETECTED.

**R6 — Needs-review fallbacks.** If R5 yielded NOT_DETECTED and any of:
- `bypassResult.needsReview`
- `hasActionableCallTransportLeak` (as today)
- `nativeReviewHit` (as today)
- `ipConsensus.needsReview`
- `ipConsensus.channelConflict.isNotEmpty()`
- `directSigns.evidence.any { !it.detected && it.needsReview && it.source == TUN_ACTIVE_PROBE }`

→ NEEDS_REVIEW.

**R7 — Default.** NOT_DETECTED.

Retired: `MATRIX_DIRECT_SOURCES` (R2 subsumes), old `foreignGeoSignal` computation (GeoIP evidence no longer consulted).

## 11. VpnCheckRunner changes

- `coroutineScope { … }` → `supervisorScope { … }`.
- Each `async { dependencies.Xcheck(...) }` replaced by `safeAsync(fallback = Fallbacks.xxx) { ... }`.
- `CancellationException` is always rethrown inside `safeAsync`. Any other `Throwable` is caught and replaced by the fallback result.
- After all checkers resolve, run:

```kotlin
val ipConsensus = runCatching {
    IpConsensusBuilder.build(
        geoIp, ipComparison, cdnPulling, tunProbeResult, bypassResult,
        asnResolver = AsnResolver.default(context, settings.resolverConfig),
    )
}.getOrElse { IpConsensusResult.empty(needsReview = true) }

onUpdate?.invoke(CheckUpdate.IpConsensusReady(ipConsensus))
```

- `VerdictEngine.evaluate(..., ipConsensus = ipConsensus, ...)`.
- `CheckResult` carries `ipConsensus`.
- New `CheckUpdate` subtype: `data class IpConsensusReady(val result: IpConsensusResult) : CheckUpdate`.

Fallback table:

| Checker | Fallback value |
|---|---|
| `geoIpCheck` | `CategoryResult(name="GeoIP", detected=false, findings=[Finding(msg, isError=true)], geoFacts=GeoIpFacts(fetchError=true, …))` |
| `ipComparisonCheck` | `IpComparisonResult(detected=false, summary=err, ruGroup=empty, nonRuGroup=empty)` |
| `cdnPullingCheck` | `CdnPullingResult.empty()` |
| `underlyingProbe` | `ProbeResult(vpnActive=false, ruTarget=PerTargetProbe(..., error=err), nonRuTarget=PerTargetProbe(..., error=err), vpnError=err.message, tunProbeDiagnostics=null)` |
| `directCheck` | `CategoryResult(name=direct_category, detected=false, needsReview=true, findings=[err])` |
| `indirectCheck` | `CategoryResult(name=indirect_category, detected=false, needsReview=true, findings=[err])` |
| `locationCheck` | `CategoryResult(name=location_category, detected=false, needsReview=false, findings=[err])` |
| `nativeCheck` | `CategoryResult(name=native_category, detected=false, needsReview=false, findings=[err])` |
| `bypassCheck` | `BypassResult(proxyEndpoint=null, proxyOwner=null, directIp=null, proxyIp=null, vpnNetworkIp=null, underlyingIp=null, xrayApiScanResult=null, findings=[err], detected=false, needsReview=true)` |

## 12. UI changes (minimum for this iteration)

- New block on results screen below existing category cards: "IP channels". Table of `channel → IP(+family, countryCode, asn, targetGroup?)`. Highlight rows/groups when `crossChannelMismatch` / `warpLikeIndicator` / `geoCountryMismatch` / `channelConflict[C]` / `probeTargetDivergence` / `probeTargetDirectDivergence` are set.
- Hidden when `observedIps.isEmpty()`.
- Wired via `CheckUpdate.IpConsensusReady` (live) and final `CheckResult.ipConsensus` (persisted).
- Export (existing, commit `fb612e0`) serializes `ipConsensus` JSON/text.

## 13. Testing

### 13.1 New test files

- `IpConsensusBuilderTest.kt`:
  - matching direct IPs merge into one observed entry;
  - cross-channel mismatch same family → `crossChannelMismatch=true`;
  - DIRECT v4 and VPN v6 → `dualStackObserved=true`, `crossChannelMismatch=false`;
  - RU-group vs non-RU-group different IPs → `channelConflict[DIRECT]=true`;
  - PROXY IP absent from DIRECT∪VPN → `warpLikeIndicator=true`;
  - two IPs with different `countryCode` → `geoCountryMismatch=true`;
  - mismatched IPs with shared ASN → `sameAsnAcrossChannels=true`;
  - IPv4-mapped IPv6 normalization;
  - invalid IP in input → `unparsedIps` populated, `needsReview=true`, builder does not throw;
  - AsnResolver timeout → `needsReview=true`, other flags still computed;
  - empty input (network disabled) → `.empty(needsReview=false)`;
  - `probeTargetDivergence` flagged (ru vs non-ru VPN IP);
  - `probeTargetDirectDivergence` flagged independently;
  - `targetGroup` preserved in observed entries.

- `AsnResolverTest.kt`:
  - cache hit does not hit the network;
  - batch respects the IP cap;
  - per-request timeout surfaces as `null` entry, not an exception.

### 13.2 Edited test files

- `DirectSignsCheckerTest`:
  - rename `check marks tun probe success as detected direct signal` → `check marks tun probe success as needs review without mismatch`, flip expectations (`detected=false`, `needsReview=true`);
  - add `check marks tun probe success as detected when dns path mismatches`;
  - add `check emits informational finding per probe target` — verifies RU + non-RU get their own info findings.

- `GeoIpCheckerTest` (or equivalent):
  - `populates geoFacts on successful merge`;
  - `populates geoFacts with fetchError=true when both providers fail`.

- `UnderlyingNetworkProberTest`:
  - both targets succeed, IPs equal → `probeTargetDivergence=false` downstream;
  - VPN IPs differ across targets → downstream flag flips;
  - RU target fails, non-RU succeeds → run continues, `ruTarget.error` populated.

- `VerdictEngineTest`: delete old 000..111 matrix tests. Add:
  - R1: split tunnel evidence → DETECTED;
  - R2: TRANSPORT_VPN alone → DETECTED (behavior change from today);
  - R3a: `probeTargetDivergence && geoCountryMismatch` → DETECTED;
  - R3a: `probeTargetDivergence` alone (same country) → DETECTED;
  - R3b: `probeTargetDirectDivergence && foreignIps` → DETECTED;
  - R3b: `probeTargetDirectDivergence` alone (no geo axis) → falls through (handled by R5/R6);
  - R3c: `crossChannelMismatch && foreignIps` → DETECTED;
  - R3c: `crossChannelMismatch && warpLikeIndicator` → DETECTED;
  - R3c: `crossChannelMismatch` without geo/warp axis → falls through (dual-stack shouldn't trigger);
  - R4: `locationConfirmsRussia && geo.outsideRu` → DETECTED;
  - R4: `locationConfirmsRussia && geo.hosting` only → NEEDS_REVIEW (#15 regression);
  - R5: `geo.outsideRu` alone → NEEDS_REVIEW;
  - R5: `geo.outsideRu` + indirect → DETECTED;
  - R6: `channelConflict` promotes NOT_DETECTED to NEEDS_REVIEW;
  - R6: TUN probe `needsReview` without consensus promotion → NEEDS_REVIEW;
  - R7: no signals → NOT_DETECTED.

- `VpnCheckRunnerTest`:
  - `run survives geoIpCheck throwing and produces partial result` — mock `geoIpCheck` to throw `IOException`, verify siblings finish, verdict computed, geoIp has error finding;
  - `run propagates CancellationException from any checker`;
  - `run builds ipConsensus and passes it to verdict engine` — mock builder, verify result is forwarded.

## 14. Build order

1. Models: `model/IpConsensus.kt`, `GeoIpFacts` in `model/CategoryResult.kt`, update `CheckResult`.
2. `GeoIpChecker` — populate `geoFacts`; tests.
3. `AsnResolver` — module + tests.
4. `IpConsensusBuilder` — pure tests (no live network).
5. `UnderlyingNetworkProber` — dual-target probing; tests.
6. `DirectSignsChecker.reportTunActiveProbe` — rewrite; test migration.
7. `VerdictEngine` — rewrite; test migration.
8. `VpnCheckRunner` — `supervisorScope`, `safeAsync`, consensus stage, new `CheckUpdate`; tests.
9. `CheckResult` plumbing + export.
10. UI: "IP channels" block.
11. Full build: `./gradlew assembleDebug`, `./gradlew lint`, `./gradlew test`.

## 15. Risks and explicit assumptions

- **R2 behavior change.** `TRANSPORT_VPN`/known-proxy-port alone now yields DETECTED even without a foreign geo hit. Rationale: for a "RKN circumvention check" application, an active system VPN is itself the answer. Users on corporate/internal VPN with RU geo will observe this as DETECTED.
- **AsnResolver network budget.** Up to 6 IPs × (≤3 s each, ≤5 s batch) added to a scan. Respects `resolverConfig` (DoH, etc.).
- **CheckResult data-class change.** New field with default — safe for nominal construction. Any positional destructuring must be updated (grep before touching).
- **UnderlyingNetworkProber compat shims.** `vpnIp` / `directIp` / `vpnIpComparison` become derived properties preferring `ruTarget`. `BypassChecker` and other consumers keep working; if any consumer expected both targets merged, the new per-target API is available.
- **Probe request count doubles.** Up to 4 HTTP probes (2 targets × {via VPN, via underlying}). Timeouts unchanged. Per-target failures are isolated.

## 16. Non-goals

- No changes to `IpComparisonChecker`, `CdnPullingChecker`, `BypassChecker`, `NativeSignsChecker`, `LocationSignalsChecker` logic — consensus adapts to their current results.
- No on-disk ASN cache, no custom GeoIP provider, no new user-facing configuration.
- No attempt to redesign `Dependencies`/DI beyond adding the `AsnResolver` argument to the builder.
