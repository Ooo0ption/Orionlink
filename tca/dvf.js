// TCA-side script for dvf.html: verifies the RP credential shown to the user,
// runs the PIN-OPRF, and seals the authorization record D_enc that leaves the
// iframe.

import { PSVerify, PSPublicKey, CreateRegistrationRequest, GenerateEncKey, GenerateDEnc } from './cryptolib.js';

// Origins of the pages this frame may exchange messages with, taken from the
// deployment configuration rather than compiled in.
const ORION = window.ORION || {};
if (!ORION.idpOrigin || !ORION.brokerOrigin) {
    throw new Error('TCA: /orion-config.js did not load — service origins unknown');
}
const ALLOWED_PARENT_ORIGINS = new Set(ORION.allowedParentOrigins || []);

// Reports whether an inbound message's origin is one this frame accepts.
function isAllowedOrigin(o) { return ALLOWED_PARENT_ORIGINS.has(o); }

const IDP_PARENT_ORIGIN = ORION.idpOrigin;
const BROKER_ORIGIN = ORION.brokerOrigin;

// Marks a point in the protocol timeline, read back by the measurement harness.
function omark(name) { try { performance.mark(name); } catch (e) { /* timing is best-effort */ } }
// Records the interval between two marks. The measured intervals cover
// cryptographic and network work only, never a DOM write.
function omeasure(name, start, end) {
    try { performance.measure(name, start, end); } catch (e) { /* timing is best-effort */ }
}

// Appends a line to the on-page log.
function log(msg) { const el = document.getElementById('log'); if (el) el.textContent += "\n" + msg; }
// Shows a protocol value in the TCA panel.
function setv(id, val, cls) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = String(val);
    el.className = 'vv' + (cls ? ' ' + cls : '');
}
// Truncates a value for display.
function trunc(s, n) { s = String(s); return s.length > n ? s.slice(0, n) + '…' : s; }

const submit_pin_btn = document.getElementById('submit_pin_btn');
submit_pin_btn.disabled = true;

let resolveInitPromise;
const initReadyPromise = new Promise(resolve => {
    resolveInitPromise = resolve;
});
let brokerWindow = null;
let brokerDoc = null;
let acid = null, cvk = null, r = null, rp_domain = null, uid = null;
let pin_startTime = null;

// On PIN submit, blinds the PIN into alpha and sends it to the IdP page.
submit_pin_btn.addEventListener('click', async () => {
    if (submit_pin_btn.disabled) {
        return;
    }
    const pin = document.getElementById('pin_input').value;
    if (!pin) {
        log('PIN empty.');
        document.getElementById('notice_message').textContent = 'Please enter a PIN.';
        return;
    }
    log('PIN entered.');
    pin_startTime = Date.now();
    omark('orion:pin_submit');

    omark('orion:blind_start');
    const { alpha, rBig } = await CreateRegistrationRequest(pin, uid);
    omark('orion:blind_end');
    omeasure('orion.tca.oprf_blind', 'orion:blind_start', 'orion:blind_end');

    r = rBig;
    window.parent.postMessage({ type: 'alpha', alpha: alpha }, IDP_PARENT_ORIGIN);
    log('alpha=' + alpha);
    setv('v_alpha', trunc(alpha, 26));

    document.getElementById('notice_message').textContent = 'Waiting...';
    submit_pin_btn.disabled = true;
});

// Drives the consent flow from the messages the IdP and broker pages send:
// init and start_resp carry the credential to verify, uid unlocks the PIN entry,
// beta completes the OPRF, and code ends the exchange.
window.addEventListener('message', async function (event) {
    if (!event.data || !event.data.type) {
        return;
    }
    if (!isAllowedOrigin(event.origin)) {
        log('Rejected message from disallowed origin: ' + event.origin);
        return;
    }

    log('Received message of type: ' + event.data.type + ' from ' + event.origin);
    switch (event.data.type) {
        case 'init':
            acid = event.data.acid;
            log('Received init message with acid: ' + acid);
            setv('v_acid', trunc(acid, 30));
            if (event.data.cvk) {
                const cvkJSON = event.data.cvk;
                log('cvk=' + cvkJSON);
                cvk = PSPublicKey.fromJSON(cvkJSON);
            }
            resolveInitPromise({ acid, cvk });
            break;

        case 'start_resp':
            log('Received start_resp message: ' + JSON.stringify(event.data));
            brokerDoc = event.source;
            let t;
            if (event.data.t) {
                t = event.data.t;
                log('t=' + t);
            }
            if (event.data.rp_domain) {
                rp_domain = event.data.rp_domain;
                log('rp_domain=' + rp_domain);
                let dShown = event.data.rp_domain;
                try { dShown = atob(event.data.rp_domain); } catch (e) { }
                setv('v_D', dShown);
            }

            log('Waiting for init data to be ready...');
            const initData = await initReadyPromise;
            log('Init data is ready, proceeding with verification.');

            omark('orion:verifycred_start');
            const verifyOk = PSVerify(initData.acid, rp_domain, t, initData.cvk);
            omark('orion:verifycred_end');
            omeasure('orion.tca.verify_cred', 'orion:verifycred_start', 'orion:verifycred_end');

            if (verifyOk) {
                setv('PSVerifyResult', '✓ verified — acid commits to D', 'ok');
                log('PSVerify success');
                window.parent.postMessage({ type: 'verify', value: 'ok' }, IDP_PARENT_ORIGIN);
            } else {
                setv('PSVerifyResult', '✗ failed');
                log('PSVerify failed');
                window.parent.postMessage({ type: 'verify', value: 'failed' }, IDP_PARENT_ORIGIN);
            }
            break;

        case 'uid':
            uid = event.data.uid;
            log('Received uid: ' + uid);
            submit_pin_btn.disabled = false;
            document.getElementById('notice_message').textContent = 'Now you can enter your PIN.';
            break;

        case 'beta':
            const beta = event.data.beta;

            omark('orion:km_start');
            const enc_key = await GenerateEncKey(beta, r);
            omark('orion:km_end');
            omeasure('orion.tca.oprf_unblind_kdf', 'orion:km_start', 'orion:km_end');

            omark('orion:denc_start');
            const { combined, nonce } = await GenerateDEnc(enc_key, rp_domain, acid);
            omark('orion:denc_end');
            omeasure('orion.tca.d_enc', 'orion:denc_start', 'orion:denc_end');

            window.parent.postMessage({ type: 'key', D_enc: combined }, IDP_PARENT_ORIGIN);

            log('Received beta: ' + beta);
            setv('v_beta', trunc(beta, 26));
            setv('v_km', '🔒 derived — never leaves the TCA', 'ok');
            setv('v_denc', trunc(combined, 26));
            break;

        case 'code':
            const code = event.data.code;
            omark('orion:code_received');
            omeasure('orion.tca.pin_to_code', 'orion:pin_submit', 'orion:code_received');

            const pin_endTime = Date.now();
            const pin_duration = pin_endTime - pin_startTime;
            console.log(`Time taken from user entering PIN to receiving code: ${pin_duration} ms`);
            log('Received code: ' + code);
            if (brokerDoc) {
                brokerDoc.postMessage({ type: 'code', code: code }, BROKER_ORIGIN);
            } else {
                log('Error: brokerDoc is not available to send the code.');
            }
            window.parent.postMessage({
                type: 'authorization_completed',
                message: 'Authorization completed. Now you can close this window.',
            }, IDP_PARENT_ORIGIN);
            document.getElementById('notice_message').textContent = 'Authorization completed. Now you can close this window.';
            break;
    }
}, false);

log('postMessage to get RP Message.');
if (window.parent && window.parent.opener) {
    brokerWindow = window.parent.opener;
    brokerWindow.postMessage({ type: 'start' }, BROKER_ORIGIN);
} else {
    log('Error: Cannot find window.parent.opener');
}
