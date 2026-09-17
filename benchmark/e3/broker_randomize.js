// E3 / Broker line — load on the broker's RP-identity randomization.
//
// Endpoint: Broker GET /ssso/randomizeRPIDForTest (Broker/bench_support.go).
// Randomizes the registered RP's DomainCred and returns (sigma_1', sigma_2', t),
// which is the broker's per-session AAKA work.
//
//   k6 run benchmark/e3/broker_randomize.js      (see benchmark/run-e3.sh)
//
// No fixture is needed here (the endpoint takes no body), but the bootstrap is
// still run once as a precondition check: it fails loudly if the stack is not in
// bench profile or the RP has not registered, instead of producing a curve of
// 400s.
import http from 'k6/http';
import { BROKER_URL, buildOptions, bootstrapFixtures, currentTags, record, e3Summary } from './lib/common.js';

const ENDPOINT = `${BROKER_URL}/ssso/randomizeRPIDForTest`;

export const options = buildOptions();

export function setup() {
  bootstrapFixtures(1);
  return {};
}

export default function () {
  const tags = currentTags();
  const res = http.get(ENDPOINT, { timeout: '60s', tags });
  record(res, tags);
}

export function handleSummary(data) {
  return e3Summary(data, { line: 'broker', script: 'broker_randomize', endpoint: `GET ${ENDPOINT}` });
}
