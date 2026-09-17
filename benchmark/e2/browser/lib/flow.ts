import { expect, BrowserContext, Frame, Page } from '@playwright/test';
import { Human } from '../human';
import { ORION } from '../playwright.config';

// One place where the browser-side flows are driven, so the three perf
// harnesses under perf/ and the functional specs under tests/ cannot drift on
// what "a login" or "a revoke" means.
//
// Stage boundaries follow paper §6's own enumeration of the login flow
// (Article/6-Implementation and Evaluation.tex), which is what the rows of
// Table 4 (tab:latency-breakdown) are:
//
//   (1) redirecting to the IdP consent page after the user clicks "Login"
//         -> click_login: the click, until the redirect that leads to the consent
//            page has been followed and the browser starts fetching it
//            (the consent document's fetchStart — see consentNavTiming on why
//            not its timeOrigin). "Redirecting to" is where it ends — the consent
//            page's own load and render are not part of getting there, and are
//            reported separately as consent_page_load_ms.
//            Authenticating at the IdP is inside this stage: the RP redirect to
//            the broker, the broker opening the popup, the IdP login page
//            loading, the credentials being submitted, and the IdP checking them
//            and answering 302.
//            That this row spans several round trips is visible in the paper's
//            own RTT sweep: it grows by 197.44 / 438.82 / 930.30 ms at 40 / 100
//            / 200 ms RTT, i.e. by 4.4-4.9 RTTs — a single-hop stage could not.
//            The credential typing inside it is simulated interaction, so
//            click_login_machine_ms is the reported figure — see the header of
//            ../perf/login_latency.spec.ts on why the stages are reported as
//            machine time while the total is not.
//   (2) user consent with frontend execution of the TCA
//         -> consent_check: the consent page finishing its render, until the
//            TCA has finished verifying the RP's credential. Ending at
//            verifycred_end rather than verifycred_start is deliberate — the
//            check belongs inside the row named for it.
//            Note the TCA iframe is already being fetched when this stage
//            opens: the consent page kicks it off from a script at the end of
//            <body>, which runs before DOMContentLoaded. So part of that fetch
//            falls in consent_page_load_ms rather than here.
//            Waiting for the user afterwards is not counted; that span is
//            reported separately as pin_entry_ms.
//            Nor is anything after the PIN submit — the OPRF, D_enc, and its
//            encrypted storage at the IdP are authorization *management*, and
//            belong to the Extension group.
//   (3) authorization code exchange by the RP
//         -> code_exchange: the user starting to enter their PIN, until the RP
//            has decrypted the tokens. The whole span, PIN entry and code
//            issuance included.
//            The end point is RP /ssso/callback's response, and that is not an
//            approximation: that handler (RP/aaka.go handleCallback) redeems
//            the code at the broker, takes K_S from the AAKE state, decrypts
//            the id_token's sub/name/email, saves the session, and only then
//            redirects to /ssso/home. Its first response byte is therefore the
//            moment the RP holds plaintext tokens.
//
//            Four browser round trips, strictly serial, none removable: OPRF
//            evaluation (/ssso/authorize/beta), redeeming D_enc for a code
//            (/ssso/authorize/code), handing the code to the broker
//            (/ssso/codetoken), and the RP's own callback. The first two cannot
//            be merged — D_enc is encrypted under K_m, which only exists after
//            beta comes back and is unblinded locally; that gap is the OPRF.
//   (4) successful login completion
//         -> total: the click, until the RP home page greets the user by name.
//            Reported with the simulated interaction left in, unlike (1)-(3).
//            Not "the document is ready": the login is over when the user can
//            see they are signed in. The greeting also only renders if the RP
//            decrypted id_token.name under K_S, so the wait for it doubles as
//            the assertion that the whole chain worked.
//
// The three stages do not tile the login. Three spans belong to no Table 4 row
// and are reported on their own so the decomposition can still be checked:
// consent_page_load_ms (fetching and parsing the consent document, between
// stages 1 and 2), pin_entry_ms (waiting for the user to start typing, after
// verification) and render_home_ms (the RP rendering /ssso/home after
// decryption). The stages are now strictly ordered — none overlaps another. This is also
// why total is not the sum of (1)-(3) — nor is the paper's own total the sum of
// its three stages (392.10 + 76.16 + 213.58 != 1574.50).
//
// Identity the harness asserts every iteration:
//   click_login + consent_page_load + consent_check + pin_entry + code_exchange
//     + render_home = total
//
// Cross-window timing. Four clocks are involved and every stage boundary comes
// from one of them:
//
//   - the harness clock, Date.now() in this process, which is where the actions
//     it issues are timestamped (the click, the first PIN keystroke);
//   - CDP request timings (`request.timing().startTime`), which are wall-clock
//     readings from the browser process and therefore the same clock;
//   - the RP tab's, the popup's and the TCA frame's `performance` timelines,
//     three separate ones, each with its own time origin.
//
// A mark from the third group is made epoch-comparable to the first two by
// adding `performance.timeOrigin`. That is not exact: a document's timeOrigin is
// a single wall-clock reading taken at navigation start while `startTime`
// advances on the monotonic clock, so each document carries its own
// wall-vs-monotonic bias. This harness used to estimate that bias per document
// (NTP-style probing) and subtract it. The estimates came out at ~1 ms per
// document on this host, and since each stage carries the *difference* of its
// two endpoints' biases, the correction moved every Table 4 row by under 0.3%
// (click_login +1.1 of 783 ms, consent_check -0.3 of 100 ms, total +1.0 of
// 1507 ms; consent_page_load and code_exchange not at all, their endpoints
// sharing a clock). That is smaller than the probe's own noise — Date.now()
// truncates to whole milliseconds and the estimate keeps half a CDP round trip
// — so the correction was removed rather than reported as if it were signal.
// Re-measure before trusting this on a host with a visibly slewing clock or
// with documents that live far longer than the ~1 s they do here.
//
// Intervals with both endpoints inside one document are computed on that
// document's own timeline, where the question does not arise at all.
//
// What is deliberately avoided everywhere is timing an
// `expect(...).toBeEnabled()`, whose 100 ms poll is coarser than several of the
// quantities being reported.

export const CREDS = { username: 'Alice', password: 'Alice-pass', pin: '135790' };

/** Per-iteration stage timings, in ms. Keys are the reported columns. */
export interface LoginStages extends Record<string, number> {
    /** The click, until the consent page's navigation starts. */
    click_login_ms: number;
    /** The same with the simulated credential-entry delay taken out. */
    click_login_machine_ms: number;
    /** Fetching and parsing the consent document. No Table 4 row. */
    consent_page_load_ms: number;
    /** Consent page rendered, until AC.VerifyCred finishes. Machine-only. */
    consent_check_ms: number;
    /** Verification done, until the user starts typing. No Table 4 row. */
    pin_entry_ms: number;
    /** The same with the simulated delay taken out. */
    pin_entry_machine_ms: number;
    /** First keystroke of the PIN, until the RP has decrypted the tokens. */
    code_exchange_ms: number;
    /** The same with the simulated submit delay taken out. */
    code_exchange_machine_ms: number;
    /** The same, but ending at the greeting instead. */
    code_exchange_to_home_ms: number;
    /** Decryption done, until the greeting is on screen. */
    render_home_ms: number;
    total_ms: number;
    /** Simulated interaction delay falling inside `total_ms` (see ../human.ts). */
    human_ms: number;
    /** total_ms minus human_ms: the system's share, comparable to the paper. */
    machine_ms: number;
}

export interface LoginResult {
    stages: LoginStages;
    /** The TCA's own orion.* measures, read out of its frame. */
    tcaMeasures: Record<string, number>;
    /** The stage boundaries themselves, epoch ms, for locating other events. */
    marks: Record<string, number>;
    page: Page;
    popup: Page;
}

interface Measure {
    name: string;
    duration: number;
}

/** Reads a window's own orion.* measures. */
async function readMeasures(ctx: Page | Frame): Promise<Measure[]> {
    return ctx.evaluate(() =>
        performance
            .getEntriesByType('measure')
            .filter((e) => e.name.startsWith('orion.'))
            .map((e) => ({ name: e.name, duration: e.duration })),
    );
}

/**
 * Interval between two marks in the same window, in ms.
 *
 * Both endpoints come from one high-resolution timeline, so this needs no epoch
 * conversion and is the most precise measurement the harness can make.
 */
async function markDelta(ctx: Page | Frame, from: string, to: string): Promise<number> {
    return ctx.evaluate(([a, b]) => {
        const ea = performance.getEntriesByName(a, 'mark')[0];
        const eb = performance.getEntriesByName(b, 'mark')[0];
        if (!ea) throw new Error(`mark ${a} not found in this window`);
        if (!eb) throw new Error(`mark ${b} not found in this window`);
        return eb.startTime - ea.startTime;
    }, [from, to]);
}

/**
 * A document's epoch reading of a named mark.
 *
 * Carries that document's wall-vs-monotonic bias — see the header on why it is
 * left in rather than estimated away.
 */
async function markEpoch(ctx: Page | Frame, mark: string): Promise<number> {
    return ctx.evaluate((name) => {
        const e = performance.getEntriesByName(name, 'mark')[0];
        if (!e) throw new Error(`mark ${name} not found in this window`);
        return performance.timeOrigin + e.startTime;
    }, mark);
}

/**
 * The consent document's navigation timing: the two stage boundaries it carries,
 * plus what is needed to check that they mean what they are taken to mean.
 *
 * Read in one evaluate so both boundaries and the assertion come from the same
 * navigation entry.
 *
 * `fetchStart`, not `timeOrigin`, is where stage 1 ends. The consent document is
 * reached by a redirect — `POST /ssso/login` answers 302 to the authorize URL
 * (IdP/handler.go handleDoLogin) — and a document's timeOrigin is the start of
 * the *whole* navigation, so it lands at form-submit time, before the POST is
 * even on the wire. Ending stage 1 there would drop the POST round trip and the
 * IdP's own password check out of the row that is named for reaching the consent
 * page, and bury them in consent_page_load_ms instead. Measured on this host:
 * timeOrigin 0, redirectStart 6.7 (the POST goes out), redirectEnd/fetchStart
 * 12.3 (the 302 is in), domContentLoadedEventEnd 102.6. Locally that is 12 ms in
 * the wrong row; under the paper's RTT profiles it is a whole RTT.
 */
interface ConsentNavTiming {
    /** Stage 1's end: the 302 is in and the consent document starts loading. */
    fetchStart: number;
    /** Stage 2's start. */
    domReady: number;
    redirectCount: number;
    /** fetchStart on the document's own timeline, for the assertion only. */
    fetchStartRel: number;
}

async function consentNavTiming(ctx: Page): Promise<ConsentNavTiming> {
    return ctx.evaluate(() => {
        const nav = performance.getEntriesByType('navigation')[0] as
            | PerformanceNavigationTiming
            | undefined;
        if (!nav) throw new Error('consent document has no navigation timing entry');
        return {
            fetchStart: performance.timeOrigin + nav.fetchStart,
            domReady: performance.timeOrigin + nav.domContentLoadedEventEnd,
            redirectCount: nav.redirectCount,
            fetchStartRel: nav.fetchStart,
        };
    });
}

/** The TCA frame inside an IdP popup, located by URL rather than by selector. */
export function tcaFrame(popup: Page, htmlFile: string): Frame {
    const f = popup.frames().find((fr) => fr.url().includes(htmlFile));
    if (!f) throw new Error(`TCA frame ${htmlFile} not found — cannot read its timeline`);
    return f;
}

/** Same, but waits for the frame to have navigated to its real URL. */
async function waitForTcaFrame(popup: Page, htmlFile: string, timeout = 20_000): Promise<Frame> {
    const deadline = Date.now() + timeout;
    for (;;) {
        const f = popup.frames().find((fr) => fr.url().includes(htmlFile));
        if (f) return f;
        if (Date.now() > deadline) throw new Error(`TCA frame ${htmlFile} never appeared`);
        await popup.waitForTimeout(25);
    }
}

/**
 * Waits for the TCA's PIN button to become enabled, polling on animation frames
 * inside the frame itself.
 *
 * `expect(locator).toBeEnabled()` would be the idiomatic form, but it polls on a
 * 100 ms timer and this wait sits *inside* the consent interval: the button
 * enables the moment AC.VerifyCred finishes, so up to 100 ms of pure polling
 * latency would be attributed to consent. Measured against a ~45 ms
 * verification, that is not a rounding error, it is the larger half of the
 * number.
 */
async function waitForPinButton(frame: Frame, timeout = 20_000): Promise<void> {
    await frame.waitForFunction(
        () => {
            const b = document.getElementById('submit_pin_btn') as HTMLButtonElement | null;
            return !!b && !b.disabled;
        },
        undefined,
        { timeout, polling: 'raf' },
    );
}

/**
 * Drives one complete login and returns the Table 4 SSO-Flow stage timings.
 *
 * The caller owns the context: a fresh one per iteration is required, because a
 * warm session skips the consent step and would silently measure a shorter flow.
 */
export async function runLogin(
    context: BrowserContext,
    human: Human,
): Promise<LoginResult> {
    const page = await context.newPage();
    human.reset();

    // Stage 3's end point. Registered before any navigation, and read from the
    // browser's own Resource Timing rather than from Date.now() at event
    // dispatch, so it sits on the same epoch clock as the marks. `startTime` is
    // epoch ms; `responseStart` is relative to it.
    let tRpDecrypted = NaN;
    page.on('response', (resp) => {
        if (Number.isFinite(tRpDecrypted)) return; // the first callback only
        let pathname: string;
        try {
            pathname = new URL(resp.url()).pathname;
        } catch {
            return;
        }
        if (!pathname.endsWith('/ssso/callback')) return;
        const t = resp.request().timing();
        if (t.startTime > 0 && t.responseStart >= 0) tRpDecrypted = t.startTime + t.responseStart;
    });

    await page.goto('/ssso/login');
    const loginBtn = page.locator('#loginBtn');
    await expect(loginBtn).toBeEnabled({ timeout: 15_000 });

    // --- Stage 1: click "Login" through to the IdP consent page -------------
    const popupPromise = context.waitForEvent('page', { timeout: 15_000 });
    const tClick = await human.click(loginBtn);
    // The delay in front of that click falls before the measured window, so the
    // human accounting below is relative to here rather than to zero.
    const humanAtClick = human.total;
    const popup = await popupPromise;
    const idpLoginURL = new URL('/ssso/login', ORION.idp);
    await popup.waitForURL(
        (url) => url.origin === idpLoginURL.origin && url.pathname === idpLoginURL.pathname,
        { waitUntil: 'domcontentloaded', timeout: 15_000 },
    );

    await popup.waitForSelector('input[name="username"]', { timeout: 15_000 });
    await human.type(popup.locator('input[name="username"]'), CREDS.username);
    await human.type(popup.locator('input[name="password"]'), CREDS.password);
    await Promise.all([
        popup.waitForLoadState('domcontentloaded'),
        human.click(popup.locator('button[type="submit"]')),
    ]);

    // The consent page is the document that embeds the cross-origin TCA iframe.
    // Its navigation timing has by now replaced the login page's, so this reads
    // the consent document — which is the one stage 1 ends on.
    await popup.waitForSelector('#iframe_container iframe', { timeout: 15_000 });
    // Stage 1 ends when the browser starts fetching this document; stage 2 opens
    // when it is ready. Both read from the popup's current (consent) document.
    const nav = await consentNavTiming(popup);
    // The boundary is only "the browser starts navigating to the consent page"
    // while the redirect chain stays same-origin and one hop long: a cross-origin
    // hop zeroes the redirect timings, and an extra hop would put the second
    // round trip on the wrong side of the boundary. Either way the figure would
    // slide silently, so it fails loudly here instead.
    if (nav.redirectCount !== 1 || !(nav.fetchStartRel > 0)) {
        throw new Error(
            `consent page reached by an unexpected navigation (redirectCount=` +
                `${nav.redirectCount}, fetchStart=${nav.fetchStartRel}) — the stage 1 ` +
                `boundary assumes exactly one same-origin redirect (POST /ssso/login -> 302)`,
        );
    }
    const tConsentNavStart = nav.fetchStart;
    const tConsentReady = nav.domReady;
    const humanInClickLogin = human.total - humanAtClick;

    // --- Stage 2: the TCA verifies, the user enters the PIN -----------------
    // The TCA verifies the RP credential while the user is still on this frame,
    // which is why the enable-wait comes before the interaction delay.
    const dvf = await waitForTcaFrame(popup, '/dvf.html');
    await waitForPinButton(dvf);

    const tca = popup.frameLocator('#iframe_container iframe');
    const pinBtn = tca.locator('#submit_pin_btn');

    // Stage 3 opens the moment the user starts entering their PIN, so its
    // start comes from the type() call rather than from the submit that
    // follows. Everything before it — verification, and the delay in front of
    // the first keystroke — stays in pin_entry.
    const humanBeforePin = human.total;
    const tPinTypeStart = await human.type(tca.locator('#pin_input'), CREDS.pin);
    const humanAtTypeStart = human.total;
    await human.click(pinBtn);
    // 100 ms each: the delay before the first keystroke lands in pin_entry, the
    // one before the submit click lands in code_exchange.
    const humanInPinEntry = humanAtTypeStart - humanBeforePin;
    const humanInStage3 = human.total - humanAtTypeStart;

    // --- Stage 3: the RP redeems the code and decrypts the tokens -----------
    await page.waitForURL(/\/ssso\/home/, { timeout: 30_000 });
    if (!Number.isFinite(tRpDecrypted)) {
        throw new Error('no /ssso/callback response was observed — cannot time the code exchange');
    }

    // The login is over when the user sees they are signed in. Timestamped
    // inside the page, on animation frames, so neither Playwright's polling nor
    // the round trip back out of the browser lands in the figure. The greeting
    // only appears if the RP decrypted id_token.name under K_S, so this doubles
    // as the assertion that the whole chain worked.
    const tLoggedIn: number = await page
        .waitForFunction(
            (name) => {
                if (!document.body.textContent?.includes(`Signed in as ${name}`)) return null;
                return performance.timeOrigin + performance.now();
            },
            CREDS.username,
            { timeout: 15_000, polling: 'raf' },
        )
        .then((h) => h.jsonValue());

    // Read the TCA's timeline before the caller tears the context down.
    const frame = dvf;
    const tcaMeasures: Record<string, number> = {};
    for (const m of await readMeasures(frame)) tcaMeasures[m.name] = m.duration;

    // Read after the measured window has closed, so these round trips cannot
    // land inside a reported interval.
    const tPinSubmit = await markEpoch(frame, 'orion:pin_submit');
    const tVerifyEnd = await markEpoch(frame, 'orion:verifycred_end');

    const total = tLoggedIn - tClick;
    const humanInTotal = human.total - humanAtClick;
    const clickLogin = tConsentNavStart - tClick;
    const pinEntry = tPinTypeStart - tVerifyEnd;
    const codeExchange = tRpDecrypted - tPinTypeStart;
    const stages: LoginStages = {
        click_login_ms: clickLogin,
        click_login_machine_ms: clickLogin - humanInClickLogin,
        // Fetching and parsing the consent document. Between the stages: the
        // redirect has been followed, so it is no longer "redirecting to", and
        // the TCA has not started, so it is not yet the consent check.
        consent_page_load_ms: tConsentReady - tConsentNavStart,
        // Machine-only: the user does nothing while the TCA loads and verifies.
        consent_check_ms: tVerifyEnd - tConsentReady,
        // Between the stages, attributed to no Table 4 row.
        pin_entry_ms: pinEntry,
        pin_entry_machine_ms: pinEntry - humanInPinEntry,
        code_exchange_ms: codeExchange,
        // The delay in front of the submit click is the only interaction left
        // inside stage 3; typing itself is atomic (see ../human.ts).
        code_exchange_machine_ms: codeExchange - humanInStage3,
        // The same span carried on to the rendered home page, kept as its own
        // column because that is when the user actually sees the login finish.
        // The difference is the RP rendering /ssso/home plus the browser
        // parsing it, both of which happen after decryption.
        code_exchange_to_home_ms: tLoggedIn - tPinTypeStart,
        // The tail after decryption: the RP rendering /ssso/home and the
        // browser parsing it. Present so the identity below closes.
        render_home_ms: tLoggedIn - tRpDecrypted,
        total_ms: total,
        human_ms: humanInTotal,
        machine_ms: total - humanInTotal,
    };

    // The decomposition must actually decompose. A drift beyond a millisecond
    // of clock granularity means a boundary was read off the wrong document —
    // the failure mode that silently produced plausible-looking numbers twice
    // while this harness was being written.
    const sum =
        stages.click_login_ms +
        stages.consent_page_load_ms +
        stages.consent_check_ms +
        stages.pin_entry_ms +
        stages.code_exchange_ms +
        stages.render_home_ms;
    if (Math.abs(sum - total) > 2) {
        throw new Error(
            `stage decomposition does not close: parts sum to ${sum.toFixed(2)} ms ` +
                `but total is ${total.toFixed(2)} ms`,
        );
    }

    const marks = {
        click: tClick,
        consentReady: tConsentReady,
        consentNavStart: tConsentNavStart,
        verifyEnd: tVerifyEnd,
        pinSubmit: tPinSubmit,
        rpDecrypted: tRpDecrypted,
        loggedIn: tLoggedIn,
    };
    return { stages, tcaMeasures, marks, page, popup };
}
