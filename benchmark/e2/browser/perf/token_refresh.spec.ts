import { expect, Page, test } from '@playwright/test';
import { Human, humanConfig } from '../human';
import { runLogin } from '../lib/flow';
import { ITERATIONS, PROFILE, summarizeAll, writeReport } from '../lib/report';

// Paper Table 4, Extension / Token refresh.
//
// Login is untimed setup. Every measured iteration is an authenticated browser
// fetch to the running RP's /ssso/refresh endpoint. The request therefore takes
// the production path:
//
//   browser -> RP -> Broker -> IdP -> Broker -> RP -> browser
//
// `token_refresh_ms` comes from the browser's same-origin Resource Timing entry,
// from fetch start through the complete response body. In particular, this is
// not the old loopback Go microbenchmark: tc/netem on the service containers is
// on the measured path.

interface RefreshSample extends Record<string, number> {
    token_refresh_ms: number;
    refresh_ttfb_ms: number;
    refresh_download_ms: number;
    fetch_to_json_ms: number;
}

async function refreshOnce(page: Page): Promise<RefreshSample> {
    return page.evaluate(async () => {
        performance.clearResourceTimings();
        const refreshURL = new URL('/ssso/refresh', window.location.href).href;
        const fetchStart = performance.now();
        const response = await fetch(refreshURL, {
            credentials: 'include',
            cache: 'no-store',
        });
        const body = await response.text();
        const fetchEnd = performance.now();

        if (!response.ok) {
            throw new Error(`live RP refresh returned HTTP ${response.status}: ${body}`);
        }
        let payload: { access_token?: string };
        try {
            payload = JSON.parse(body);
        } catch {
            throw new Error(`live RP refresh returned non-JSON data: ${body.slice(0, 200)}`);
        }
        if (!payload.access_token) throw new Error('live RP refresh returned an empty access token');

        const entry = (performance.getEntriesByType('resource') as PerformanceResourceTiming[])
            .findLast((candidate) => candidate.name === refreshURL);
        if (!entry || entry.responseEnd <= 0 || entry.responseStart <= 0) {
            throw new Error('no complete Resource Timing entry for the live RP refresh request');
        }

        return {
            // The Table 4 figure: complete, real HTTP request/response latency.
            token_refresh_ms: entry.duration,
            // Diagnostic components retained in the JSON report.
            refresh_ttfb_ms: entry.responseStart - entry.startTime,
            refresh_download_ms: entry.responseEnd - entry.responseStart,
            fetch_to_json_ms: fetchEnd - fetchStart,
        };
    });
}

test.describe('Table 4 — live token refresh latency', () => {
    test.setTimeout(Math.ceil(60_000 + ITERATIONS * 30_000));

    test('authenticated browser -> RP -> Broker -> IdP', async ({ browser }) => {
        const context = await browser.newContext();
        const human = new Human();
        const rows: RefreshSample[] = [];

        try {
            // Untimed setup. One session is intentionally reused: refresh is a
            // ratchet and consecutive calls must advance the live protocol state.
            const { page } = await runLogin(context, human);

            for (let i = 0; i < ITERATIONS; i++) {
                const sample = await refreshOnce(page);
                expect(sample.token_refresh_ms, `iteration ${i + 1} did not complete`).toBeGreaterThan(0);
                rows.push(sample);
            }
        } finally {
            await context.close();
        }

        writeReport('e2-token_refresh', {
            table4_rows: ['Extension / Token refresh = token_refresh_ms'],
            profile: PROFILE,
            iterations: ITERATIONS,
            generated_at: new Date().toISOString(),
            human: humanConfig(),
            transport:
                'authenticated browser fetch -> live RP -> live Broker -> live IdP -> Broker -> RP -> browser',
            stages: summarizeAll(rows),
        });
    });
});
