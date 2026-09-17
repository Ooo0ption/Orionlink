// Shared machinery for E3 — the AAKA-interface stress test (paper Fig. 8).
//
// The three E3 scripts differ only in which endpoint they hit; everything else
// (RPS staging, fixture bootstrap, tagging, summary export) lives here so the
// three lines of the figure are produced under identical conditions.
//
// Configuration is entirely environment-driven — no hardcoded address survives
// in the scripts (NDSS AE "Functional" forbids hardcoded paths/addresses):
//
//   ORION_IDP_URL / ORION_BROKER_URL / ORION_RP_URL   endpoints (defaults :3000/1/2)
//   ORION_E3_RPS          comma-separated request rates      (default 10,200)
//   ORION_E3_DURATION     seconds held at each rate          (default 60)
//   ORION_E3_WARMUP       seconds discarded at each stage    (default 10)
//   ORION_E3_COOLDOWN     idle seconds between stages        (default 20)
//   ORION_E3_FIXTURES     request bodies pre-generated       (default 20)
//   ORION_E3_ASSUMED_MS   latency guess used to size the VU pool (default 50)
//   ORION_E3_MAX_WAIT_S   queueing a saturated stage may use up (default 2)
//   ORION_E3_VU_CAP       hard ceiling on the VU pool             (default 1500)
//   ORION_E3_OUT_DIR      where the JSON report is written   (default benchmark/results)
//   ORION_PROFILE         recorded in the report; the stack must run bench
import http from 'k6/http';
import exec from 'k6/execution';
import { b64decode, b64encode } from 'k6/encoding';
import { Rate, Trend } from 'k6/metrics';

export const IDP_URL = __ENV.ORION_IDP_URL || 'http://localhost:3000';
export const BROKER_URL = __ENV.ORION_BROKER_URL || 'http://localhost:3001';
export const RP_URL = __ENV.ORION_RP_URL || 'http://localhost:3002';

const num = (name, dflt) => {
  const raw = __ENV[name];
  if (raw === undefined || raw === '') return dflt;
  const v = Number(raw);
  if (!Number.isFinite(v) || v < 0) throw new Error(`${name}=${raw} is not a non-negative number`);
  return v;
};

// The two top stages of the paper's ladder (500 / 1000 RPS) are deliberately
// not the default: AAKA is pairing-bound, and on a reviewer-sized machine they
// only measure the queue. Ask for them explicitly on hardware that sustains
// them: ORION_E3_RPS=10,200,500,1000 (or --rps).
export const RATES = (__ENV.ORION_E3_RPS || '10,200')
  .split(',')
  .map((s) => Number(s.trim()))
  .filter((n) => Number.isFinite(n) && n > 0);
export const DURATION_S = num('ORION_E3_DURATION', 60);
export const WARMUP_S = num('ORION_E3_WARMUP', 10);
export const COOLDOWN_S = num('ORION_E3_COOLDOWN', 20);
export const FIXTURES = Math.max(1, num('ORION_E3_FIXTURES', 20));
const ASSUMED_MS = num('ORION_E3_ASSUMED_MS', 50);
const MAX_WAIT_S = num('ORION_E3_MAX_WAIT_S', 2);
const VU_CAP = Math.max(50, num('ORION_E3_VU_CAP', 1500));
const OUT_DIR = __ENV.ORION_E3_OUT_DIR || 'benchmark/results';
const PROFILE = __ENV.ORION_PROFILE || 'demo';

if (WARMUP_S >= DURATION_S) {
  throw new Error(`ORION_E3_WARMUP (${WARMUP_S}s) must be shorter than ORION_E3_DURATION (${DURATION_S}s)`);
}

// Only the measured phase feeds these; warm-up requests are still sent (the
// arrival rate must not dip) but land in the *_warmup metrics instead.
export const latency = new Trend('aaka_latency_ms'); // http_req_duration equivalent
export const serverLatency = new Trend('aaka_server_ms'); // http_req_waiting: server time
export const errorRate = new Rate('aaka_errors');

const stageName = (rate) => `rps_${rate}`;

// One constant-arrival-rate scenario per rate, run back to back with an idle
// gap between them so a stage's queue backlog cannot bleed into the next.
export function buildOptions() {
  const scenarios = {};
  let offset = 0;
  for (const rate of RATES) {
    // VUs must cover rate x latency (Little's law) or k6 grows the pool
    // mid-stage and VU init cost shows up as latency. 1.5x is the headroom.
    const preAllocatedVUs = Math.max(20, Math.ceil((rate * ASSUMED_MS * 1.5) / 1000));
    // The ceiling has to absorb a saturated stage too, otherwise k6 runs out of
    // VUs and drops iterations for its own reasons — indistinguishable, in the
    // report, from the server failing to keep up. Sized for MAX_WAIT_S of
    // queueing, capped so the VU pool cannot exhaust the load generator's RAM.
    const maxVUs = Math.min(VU_CAP, Math.max(preAllocatedVUs * 4, Math.ceil(rate * MAX_WAIT_S)));
    scenarios[stageName(rate)] = {
      executor: 'constant-arrival-rate',
      rate,
      timeUnit: '1s',
      duration: `${DURATION_S}s`,
      preAllocatedVUs,
      maxVUs,
      startTime: `${offset}s`,
      // Bounded by the cooldown: in-flight requests of a saturated stage must
      // drain inside the idle gap, never into the next stage's window.
      gracefulStop: `${Math.max(1, COOLDOWN_S)}s`,
      tags: { rps: String(rate) },
    };
    offset += DURATION_S + COOLDOWN_S;
  }

  const thresholds = {
    // Real pass/fail. dropped_iterations is the one that matters: when the
    // system cannot keep up, k6 drops scheduled iterations and the latency
    // curve stays flattering. A dropped iteration invalidates the stage.
    http_req_failed: ['rate<0.01'],
    aaka_errors: ['rate<0.01'],
    dropped_iterations: ['count==0'],
  };
  // Non-gating declarations: a sub-metric only appears in handleSummary() if a
  // threshold names it, so these exist to make the per-stage numbers readable.
  for (const rate of RATES) {
    for (const m of ['aaka_latency_ms', 'aaka_server_ms']) {
      thresholds[`${m}{rps:${rate},phase:measure}`] = ['p(95)>=0'];
    }
    thresholds[`http_reqs{rps:${rate},phase:measure}`] = ['count>=0'];
    thresholds[`aaka_errors{rps:${rate},phase:measure}`] = ['rate>=0'];
    thresholds[`dropped_iterations{scenario:${stageName(rate)}}`] = ['count>=0'];
  }

  return {
    scenarios,
    thresholds,
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max', 'count'],
  };
}

// Tags for the request about to be sent. Warm-up is decided from wall time
// against the scenario's own start, so it is per stage, not per test.
export function currentTags() {
  const rps = (exec.scenario.name.match(/rps_(\d+)/) || [])[1] || 'unknown';
  const elapsedS = (Date.now() - exec.scenario.startTime) / 1000;
  return { rps, phase: elapsedS < WARMUP_S ? 'warmup' : 'measure' };
}

// Records one response. Checks are deliberately not k6 `check()`s: those add a
// group metric per stage without adding information beyond the error rate.
export function record(res, tags) {
  const ok = res.status === 200 && (res.body || '').length > 0;
  errorRate.add(!ok, tags);
  if (tags.phase === 'measure') {
    latency.add(res.timings.duration, tags);
    serverLatency.add(res.timings.waiting, tags);
  }
  return ok;
}

const JSON_HEADERS = { headers: { 'Content-Type': 'application/json' }, timeout: '60s' };

function mustJSON(res, what) {
  if (res.status !== 200) {
    throw new Error(
      `${what} returned ${res.status}: ${String(res.body).slice(0, 200)}\n` +
        `  Is the stack up with ORION_PROFILE=bench? (load-test endpoints are off in demo)`
    );
  }
  return res.json();
}

// sigma_1' || sigma_2' — the flat compressed-G1 concatenation PSSignMsg.ToJSON()
// produces and RP/aaka.go decodes with FromJSON. The broker's randomize endpoint
// hands the two points back separately, so they are re-joined here.
function joinG1(b64a, b64b) {
  const a = new Uint8Array(b64decode(b64a, 'std', 'b'));
  const b = new Uint8Array(b64decode(b64b, 'std', 'b'));
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return b64encode(out.buffer, 'std');
}

// Builds request bodies against the *running* IdP's keys, so nothing is
// captured by hand and nothing goes stale when the stack regenerates keys.
//
//   1. Broker /randomizeRPIDForTest  -> (sigma_1', sigma_2', t)
//   2. RP     /test/aake/fixture     -> M = (sign1, sign2, C, R, Z, E2EE)
//
// Step 2 uses the bench-only fixture endpoint, not the production one: it does
// the same PoK + X3DH work but persists no K_S and remembers no session, so a
// load test leaves no trace in the RP's stored state. (/test/aake/pok — the RP
// line's own measured path — deliberately skips the X3DH half, so its response
// is not a valid IdP body.)
export function bootstrapFixtures(count = FIXTURES) {
  const fixtures = [];
  for (let i = 0; i < count; i++) {
    const rnd = mustJSON(
      http.get(`${BROKER_URL}/ssso/randomizeRPIDForTest`, JSON_HEADERS),
      'broker /ssso/randomizeRPIDForTest'
    );
    if (!rnd.sigma1 || !rnd.sigma2 || !rnd.t) {
      throw new Error(`broker randomize returned an unexpected shape: ${JSON.stringify(rnd)}`);
    }
    const pokRequest = { rSig1: joinG1(rnd.sigma1, rnd.sigma2), t: rnd.t, state: `e3-fixture-${i}` };
    const pok = mustJSON(
      http.post(`${RP_URL}/ssso/test/aake/fixture`, JSON.stringify(pokRequest), JSON_HEADERS),
      'RP /ssso/test/aake/fixture'
    );
    fixtures.push({
      pokRequest,
      tokenRequest: Object.assign({}, pok, { code: `e3-fixture-${i}` }),
    });
  }
  return fixtures;
}

// Round-robins the fixture pool so no two consecutive requests replay the same
// randomization, without making body construction part of the measured path.
export function pickFixture(fixtures) {
  return fixtures[exec.scenario.iterationInTest % fixtures.length];
}

const val = (data, name, stat) => {
  const m = data.metrics[name];
  return m && m.values && m.values[stat] !== undefined ? m.values[stat] : null;
};
const round = (x) => (x === null ? null : Math.round(x * 1000) / 1000);

// Writes the per-stage table the figure is drawn from. One file per endpoint;
// the three files together are Fig. 8's three lines.
export function e3Summary(data, meta) {
  const measuredS = DURATION_S - WARMUP_S;
  const stages = RATES.map((rate) => {
    const sel = `{rps:${rate},phase:measure}`;
    const requests = val(data, `http_reqs${sel}`, 'count');
    return {
      rps: rate,
      requests,
      achieved_rps: requests === null ? null : round(requests / measuredS),
      error_rate: round(val(data, `aaka_errors${sel}`, 'rate')),
      dropped_iterations: val(data, `dropped_iterations{scenario:${stageName(rate)}}`, 'count'),
      latency_ms: {
        med: round(val(data, `aaka_latency_ms${sel}`, 'med')),
        p90: round(val(data, `aaka_latency_ms${sel}`, 'p(90)')),
        p95: round(val(data, `aaka_latency_ms${sel}`, 'p(95)')),
        p99: round(val(data, `aaka_latency_ms${sel}`, 'p(99)')),
        avg: round(val(data, `aaka_latency_ms${sel}`, 'avg')),
        max: round(val(data, `aaka_latency_ms${sel}`, 'max')),
      },
      server_ms: {
        med: round(val(data, `aaka_server_ms${sel}`, 'med')),
        p95: round(val(data, `aaka_server_ms${sel}`, 'p(95)')),
        p99: round(val(data, `aaka_server_ms${sel}`, 'p(99)')),
      },
    };
  });

  const report = {
    experiment: 'E3',
    paper_figure: 'Fig. 8 — Stress test of the AnonyAKA interface',
    line: meta.line,
    endpoint: meta.endpoint,
    profile: PROFILE,
    generated_at: new Date().toISOString(),
    config: {
      rates: RATES,
      duration_s: DURATION_S,
      warmup_s: WARMUP_S,
      cooldown_s: COOLDOWN_S,
      fixtures: FIXTURES,
      measured_window_s: measuredS,
    },
    // p95 of latency_ms is the figure's y-axis; server_ms.p95 is the same
    // measurement minus connect/queue time, i.e. what the role itself costs.
    stages,
  };

  const path = `${OUT_DIR}/e3-${meta.script}-${PROFILE}.json`;
  const out = {};
  out[path] = JSON.stringify(report, null, 2);
  out.stdout = textTable(report, path);
  return out;
}

function textTable(report, path) {
  const pad = (s, n) => String(s).padStart(n);
  const lines = [
    '',
    `E3 — ${report.line}: ${report.endpoint}  (profile=${report.profile})`,
    '  target   achieved    p50      p95      p99   server p95   errors   dropped',
  ];
  for (const s of report.stages) {
    lines.push(
      [
        pad(s.rps, 8),
        pad(s.achieved_rps === null ? '-' : s.achieved_rps.toFixed(1), 10),
        pad(s.latency_ms.med === null ? '-' : s.latency_ms.med.toFixed(2), 7),
        pad(s.latency_ms.p95 === null ? '-' : s.latency_ms.p95.toFixed(2), 8),
        pad(s.latency_ms.p99 === null ? '-' : s.latency_ms.p99.toFixed(2), 8),
        pad(s.server_ms.p95 === null ? '-' : s.server_ms.p95.toFixed(2), 12),
        pad(s.error_rate === null ? '-' : (s.error_rate * 100).toFixed(2) + '%', 9),
        pad(s.dropped_iterations === null ? '-' : s.dropped_iterations, 10),
      ].join('')
    );
  }
  const dropped = report.stages.some((s) => s.dropped_iterations > 0);
  if (dropped) {
    lines.push('', '  WARNING: iterations were dropped — the offered rate was not sustained.');
    lines.push('           Those stages are not valid points on the curve.');
  }
  lines.push('', `  wrote ${path}`, '');
  return lines.join('\n');
}
