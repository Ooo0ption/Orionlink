import { defineConfig, devices } from '@playwright/test';

// OrionLink end-to-end tests. The whole docker-compose stack must already be
// up before invoking `npm test` from this directory — we deliberately do NOT
// auto-launch it via Playwright's `webServer` because docker-compose state
// outlives a single test run and tearing it down between runs is wasteful.
//
// Stack URLs come from the same ORION_* variables the servers use (see
// .env.example), so pointing the suite at a relocated deployment needs no source
// edit — the "no hardcoded addresses" requirement applies to the tests too.
//   IdP    ORION_IDP_URL     default http://localhost:3000
//   Broker ORION_BROKER_URL  default http://localhost:3001
//   RP     ORION_RP_URL      default http://localhost:3002   (= baseURL)
//   TCA    ORION_TCA_URL     default http://localhost:3003   (independent TCA origin — central to OrionLink's threat model)
export const ORION = {
  idp: process.env.ORION_IDP_URL || 'http://localhost:3000',
  broker: process.env.ORION_BROKER_URL || 'http://localhost:3001',
  rp: process.env.ORION_RP_URL || 'http://localhost:3002',
  tca: process.env.ORION_TCA_URL || 'http://localhost:3003',
};

export default defineConfig({
  testDir: './perf',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: 'line',
  use: {
    baseURL: ORION.rp,
    trace: 'on-first-retry',
    headless: true,
    ignoreHTTPSErrors: true,
  },
  projects: [
    // The latency harnesses for paper Table 4, and currently the only suite
    // here:
    //
    //   perf/login_latency.spec.ts       SSO Flow rows
    //   perf/authorization_mgmt.spec.ts  Extension / Authorization management
    //   perf/token_refresh.spec.ts       Extension / Token refresh, through the
    //                                    live RP -> Broker -> IdP path
    //
    // The functional regression suite that used to live in ./tests has been
    // moved to tmp/e2e-tests (see tmp/README.md); restoring it means moving the
    // directory back and re-adding a project for it here.
    //
    // Serialised (workers: 1): concurrent logins would contend for CPU and
    // inflate every figure the suite exists to report.
    {
      name: 'perf',
      testDir: './perf',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
