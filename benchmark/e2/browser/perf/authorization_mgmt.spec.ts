import { test, expect } from '@playwright/test';
import { ORION } from '../playwright.config';
import { Human, humanConfig } from '../human';
import { CREDS, runLogin, tcaFrame } from '../lib/flow';
import { ITERATIONS, PROFILE, summarize, summarizeAll, writeReport } from '../lib/report';

// Paper Table 4 (tab:latency-breakdown), Extension row "Authorization
// management" — the user reviewing what they have authorized.
//
// The flow: IdP /ssso/revoke renders the user's encrypted authorization record
// (D_enc) and embeds the TCA's dvf_authorize.html from its own origin. The user
// enters their PIN there; the TCA blinds it, the IdP evaluates the OPRF, and
// the TCA unblinds to K_m, decrypts D_enc, and renders the RP domain and acid
// *inside its own frame only* — the IdP-served page never receives them, which
// is the point of putting this step on a separate origin.
//
// The reported row is the *server's* time: how long the IdP takes to answer the
// PIN-OPRF request, taken as first-byte minus request-sent from Resource
// Timing. That is the only server-side work in this flow, and it is what the
// paper's figure is comparable to — its RTT sweep grows by a clean 2 RTTs per
// step while the 0 ms value is ~2 ms, which no browser-side ristretto255
// operation can be.
//
// The browser-side cost is reported alongside as client_total_ms, with its
// breakdown from the TCA's own timeline (orion.tca.authz_*) — read from there
// rather than timed from outside, since each part is well under the 100 ms
// quantum of Playwright's assertion polling:
//
//   authz_pin_to_plaintext  PIN submit -> D/acid decrypted (= client_total_ms)
//   authz_blind             H(PIN) hash-to-curve + blinding scalar mult
//   authz_oprf_rtt          the round trip to the IdP, from the TCA's view
//   authz_unblind_decrypt   unblind to K_m, then AES-GCM decrypt of D_enc
//
// A login must precede it in the same browser context: /ssso/revoke has nothing
// to render until the user has an authorization record, and the IdP session
// cookie is what identifies them. That login is setup, and is not timed here.

const IDP_REVOKE = ORION.idp + '/ssso/revoke';

test.describe('Table 4 — Authorization management latency', () => {
    test.setTimeout(Math.ceil(ITERATIONS * (45_000 + 2 * Human.estimatePerLoginMs()) * 1.5));

    test('PIN-to-plaintext authorization record', async ({ browser }) => {
        const rows: Record<string, number>[] = [];
        const sub = new Map<string, number[]>();
        const human = new Human();

        for (let i = 0; i < ITERATIONS; i++) {
            const context = await browser.newContext();

            // The server's share: how long the IdP takes to answer the PIN-OPRF
            // request. Measured as first-byte minus request-sent from the
            // browser's own Resource Timing, so it is server processing plus
            // one loopback round trip (sub-millisecond here).
            //
            // Registered before the login below, but only the revoke flow's own
            // beta request is kept: the login makes one too, and it is setup.
            let idpOprfMs = NaN;
            let loginDone = false;
            context.on('requestfinished', (req) => {
                if (!loginDone || Number.isFinite(idpOprfMs)) return;
                let pathname: string;
                try {
                    pathname = new URL(req.url()).pathname;
                } catch {
                    return;
                }
                if (!pathname.endsWith('/ssso/authorize/beta')) return;
                const t = req.timing();
                if (t.requestStart >= 0 && t.responseStart >= 0) {
                    idpOprfMs = t.responseStart - t.requestStart;
                }
            });

            // Setup (untimed): one full login, so an authorization record and
            // an IdP session exist for this context.
            await runLogin(context, human);
            loginDone = true;

            const page = await context.newPage();
            const resp = await page.goto(IDP_REVOKE, { waitUntil: 'domcontentloaded' });
            expect(
                resp?.status(),
                'revoke page did not render — no authorization record for the demo user?',
            ).toBe(200);

            // The TCA frame enables the button only after the parent has posted
            // it the D_enc blob and uid, so this wait also asserts that
            // handshake succeeded.
            const tca = page.frameLocator('#iframe_container iframe');
            const pinBtn = tca.locator('#submit_pin_btn');
            await expect(pinBtn).toBeEnabled({ timeout: 20_000 });

            human.reset();
            // dvf_authorize.html names its field rather than giving it an id —
            // #pin_input belongs to dvf.html, the login-side TCA page.
            await human.type(tca.locator('input[name=pin]'), CREDS.pin);
            await human.click(pinBtn);

            // Decryption renders the RP domain inside the TCA frame; the
            // IdP-served page only ever sees a contentless 'decryption_done'.
            await expect(tca.locator('#Domain')).not.toBeEmpty({ timeout: 20_000 });

            const frame = tcaFrame(page, '/dvf_authorize.html');
            const measures: Record<string, number> = await frame.evaluate(() =>
                Object.fromEntries(
                    performance
                        .getEntriesByType('measure')
                        .filter((e) => e.name.startsWith('orion.tca.authz_'))
                        .map((e) => [e.name, e.duration]),
                ),
            );
            expect(
                measures['orion.tca.authz_pin_to_plaintext'],
                'TCA did not report authz_pin_to_plaintext',
            ).toBeGreaterThan(0);

            expect(
                Number.isFinite(idpOprfMs),
                'no /ssso/authorize/beta request was seen during the revoke flow',
            ).toBe(true);

            // No human_ms column: both intervals start at or after the PIN
            // submit, so no simulated delay falls within either.
            rows.push({
                // The row as the paper reports it: the server's own time.
                authorization_mgmt_ms: idpOprfMs,
                // What the user waits for, on the browser side. Dominated by
                // ristretto255 in JS — see the authz_* sub-measures.
                client_total_ms: measures['orion.tca.authz_pin_to_plaintext'],
            });
            for (const [n, d] of Object.entries(measures)) {
                const list = sub.get(n) || [];
                list.push(d);
                sub.set(n, list);
            }

            await context.close();
        }

        writeReport('e2-authorization_mgmt', {
            table4_rows: ['Extension / Authorization management'],
            profile: PROFILE,
            iterations: ITERATIONS,
            generated_at: new Date().toISOString(),
            human: humanConfig(),
            stages: summarizeAll(rows),
            measures: Object.fromEntries([...sub.entries()].map(([n, s]) => [n, summarize(s)])),
        });
    });
});
