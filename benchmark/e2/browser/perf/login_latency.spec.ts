import { test, expect } from '@playwright/test';
import { Human, humanConfig } from '../human';
import { runLogin } from '../lib/flow';
import { ITERATIONS, PROFILE, summarizeAll, summarize, writeReport } from '../lib/report';

// Paper Table 4 (tab:latency-breakdown), "SSO Flow" group, OrionLink column.
// The stage boundaries, and why total is not the sum of the three, are
// documented in ../lib/flow.ts.
//
// Which column backs which row — the three stages are machine time, the total is
// what the user waits:
//
//   Click "Login"                 -> click_login_machine_ms
//   Consent check                 -> consent_check_ms   (no interaction inside it)
//   Authorization code exchange   -> code_exchange_machine_ms
//   Login successful (Total)      -> total_ms           (simulated delay included)
//
// This is a deliberate mixed basis, chosen to match the shape of the published
// table rather than to be internally tidy. What the paper says about its own
// driver is ambiguous — "under realistic user interactions" (§6) against "User
// interactions are automated using Playwright to deterministically trigger click
// events" (§6) — and it never states an interaction model at all. Its numbers
// settle it well enough for this purpose:
//
//   - its stage rows are machine time. Click "Login" is 392.10 ms at RTT=0,
//     *below* this harness's own machine-speed 502.34 ms, so no meaningful
//     think time can be sitting inside that row;
//   - its total is not. 1574.50 ms against a stage sum of 681.84 ms leaves
//     892.66 ms in no row at all — six times the corresponding gap here — which
//     is where any think time it had must live, i.e. between the stages.
//
// So the three stages are reported machine-only and the total is reported with
// the simulated interaction left in. The other variants of each column stay in
// the report as the audit trail; ORION_HUMAN=0 collapses them together.
//
// Consequence to keep in mind when reading a report: the four designated figures
// are on two different bases, so they decompose even less than before. They did
// not sum before either (three stages do not tile the login), and neither do the
// paper's.
//
// Sub-millisecond intervals inside the TCA (blind, verify, unblind, D_enc) are
// reported too, from the TCA's own performance.mark timeline rather than from
// Playwright's clock — see ../lib/flow.ts on cross-window timing.

test.describe('Table 4 — SSO Flow latency', () => {
    test.setTimeout(Math.ceil(ITERATIONS * (30_000 + Human.estimatePerLoginMs()) * 1.5));

    test('login stage breakdown', async ({ browser }) => {
        const rows = [];
        const tcaSamples = new Map<string, number[]>();
        const human = new Human();

        for (let i = 0; i < ITERATIONS; i++) {
            // A fresh context per iteration: a warm session skips consent and
            // would silently measure a different, shorter flow.
            const context = await browser.newContext();
            const { stages, tcaMeasures } = await runLogin(context, human);
            rows.push(stages);
            for (const [name, d] of Object.entries(tcaMeasures)) {
                const list = tcaSamples.get(name) || [];
                list.push(d);
                tcaSamples.set(name, list);
            }
            await context.close();
        }

        expect(tcaSamples.size, 'no orion.* measures were recorded').toBeGreaterThan(0);
        for (const r of rows) {
            expect(Number.isFinite(r.consent_check_ms), 'TCA consent marks missing').toBe(true);
        }

        writeReport('e2-login_latency', {
            // Row -> the column that backs it, so a report says on its face
            // which figure is the reported one and on which basis.
            table4_rows: [
                'SSO Flow / Click "Login" = click_login_machine_ms',
                'SSO Flow / Consent check = consent_check_ms',
                'SSO Flow / Authorization code exchange = code_exchange_machine_ms',
                'SSO Flow / Login successful (Total) = total_ms (with interaction)',
            ],
            profile: PROFILE,
            iterations: ITERATIONS,
            generated_at: new Date().toISOString(),
            human: humanConfig(),
            stages: summarizeAll(rows),
            measures: Object.fromEntries(
                [...tcaSamples.entries()].map(([n, s]) => [n, summarize(s)]),
            ),
        });
    });
});
