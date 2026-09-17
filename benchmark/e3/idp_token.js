// E3 / IdP line — load on the IdP's AAKA verification and token issuance.
//
// Endpoint: IdP POST /ssso/token/test (IdP/bench_support.go). Verifies the NIZK,
// derives K_S via X3DH and issues the encrypted tokens, skipping only the
// authorization-code lookup — the request's `code` field is not read.
//
//   k6 run benchmark/e3/idp_token.js      (see benchmark/run-e3.sh)
import http from 'k6/http';
import { IDP_URL, buildOptions, bootstrapFixtures, pickFixture, currentTags, record, e3Summary } from './lib/common.js';

const ENDPOINT = `${IDP_URL}/ssso/token/test`;

export const options = buildOptions();

export function setup() {
  return { fixtures: bootstrapFixtures() };
}

export default function (data) {
  const tags = currentTags();
  const body = JSON.stringify(pickFixture(data.fixtures).tokenRequest);
  const res = http.post(ENDPOINT, body, {
    headers: { 'Content-Type': 'application/json' },
    timeout: '60s',
    tags,
  });
  record(res, tags);
}

export function handleSummary(data) {
  return e3Summary(data, { line: 'idp', script: 'idp_token', endpoint: `POST ${ENDPOINT}` });
}
