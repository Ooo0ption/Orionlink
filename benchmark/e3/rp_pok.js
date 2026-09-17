// E3 / RP line — load on the RP's AAKA PoK construction.
//
// Endpoint: RP POST /ssso/test/aake/pok (RP/bench_support.go). Same code path as
// the production /ssso/login/aake/pok minus the AAKA-state save, so a load test
// can drive PoK construction without a session.
//
//   k6 run benchmark/e3/rp_pok.js      (see benchmark/run-e3.sh)
import http from 'k6/http';
import { RP_URL, buildOptions, bootstrapFixtures, pickFixture, currentTags, record, e3Summary } from './lib/common.js';

const ENDPOINT = `${RP_URL}/ssso/test/aake/pok`;

export const options = buildOptions();

export function setup() {
  return { fixtures: bootstrapFixtures() };
}

export default function (data) {
  const tags = currentTags();
  const body = JSON.stringify(pickFixture(data.fixtures).pokRequest);
  const res = http.post(ENDPOINT, body, {
    headers: { 'Content-Type': 'application/json' },
    timeout: '60s',
    tags,
  });
  record(res, tags);
}

export function handleSummary(data) {
  return e3Summary(data, { line: 'rp', script: 'rp_pok', endpoint: `POST ${ENDPOINT}` });
}
