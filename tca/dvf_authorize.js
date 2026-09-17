// TCA-side script for dvf_authorize.html: re-derives K_m from the user's PIN and
// decrypts a stored authorization record for review, inside the TCA origin.

import { CreateRegistrationRequest, GenerateEncKey, DecryptDEnc, base64ToString } from './cryptolib.js';

// Origins of the pages this frame may exchange messages with, taken from the
// deployment configuration rather than compiled in.
const ORION = window.ORION || {};
if (!ORION.idpOrigin) {
    throw new Error('TCA: /orion-config.js did not load — service origins unknown');
}
const ALLOWED_PARENT_ORIGINS = new Set(ORION.allowedParentOrigins || []);

// Reports whether an inbound message's origin is one this frame accepts.
function isAllowedOrigin(o) { return ALLOWED_PARENT_ORIGINS.has(o); }

const IDP_PARENT_ORIGIN = ORION.idpOrigin;

// Marks a point in the protocol timeline, read back by the measurement harness.
function omark(name) { try { performance.mark(name); } catch (e) { /* timing is best-effort */ } }
// Records the interval between two marks. The measured intervals cover
// cryptographic and network work only, never a DOM write.
function omeasure(name, start, end) {
    try { performance.measure(name, start, end); } catch (e) { /* timing is best-effort */ }
}

const submit_pin_btn = document.getElementById('submit_pin_btn');
submit_pin_btn.disabled = true;

let r = null, uid = null, denc = null;

// On PIN submit, blinds the PIN into alpha and sends it to the IdP revoke page.
submit_pin_btn.addEventListener('click', async () => {
    if (submit_pin_btn.disabled) {
        return;
    }
    const pin = document.querySelector('input[name=pin]').value;
    if (!pin) {
        document.getElementById('notice_message').textContent = 'Please enter a PIN.';
        return;
    }

    omark('orion:authz_pin_submit');

    try {
        omark('orion:authz_blind_start');
        const { alpha, rBig } = await CreateRegistrationRequest(pin, uid);
        omark('orion:authz_blind_end');
        omeasure('orion.tca.authz_blind', 'orion:authz_blind_start', 'orion:authz_blind_end');
        r = rBig;
        omark('orion:authz_alpha_sent');
        window.parent.postMessage({ type: 'alpha', alpha: alpha }, IDP_PARENT_ORIGIN);
    } catch (error) {
        document.getElementById('notice_message').textContent = 'Error: ' + error.message;
    }

    document.getElementById('notice_message').textContent = 'Waiting...';
    submit_pin_btn.disabled = true;
});

// Handles the two messages the IdP revoke page sends: decrypt hands over the
// stored record and unlocks PIN entry, beta completes the OPRF and yields the
// plaintext, which is rendered only inside this frame.
window.addEventListener('message', async function (event) {
    if (!event.data || !event.data.type) {
        return;
    }
    if (!isAllowedOrigin(event.origin)) {
        return;
    }

    switch (event.data.type) {
        case 'decrypt':
            denc = event.data.denc;
            uid = event.data.uid;
            submit_pin_btn.disabled = false;
            document.getElementById('notice_message').textContent = 'Please enter your PIN and click Decrypt.';
            document.getElementById('pin_input_div').style.display = 'block';
            break;
        case 'beta':
            const beta = event.data.beta;
            omark('orion:authz_beta_recv');
            omeasure('orion.tca.authz_oprf_rtt', 'orion:authz_alpha_sent', 'orion:authz_beta_recv');
            try {
                omark('orion:authz_unblind_start');
                const enc_key = await GenerateEncKey(beta, r);
                const { D, Sigma1, Sigma2, Nonce } = await DecryptDEnc(enc_key, denc);
                omark('orion:authz_decrypt_done');
                omeasure('orion.tca.authz_unblind_decrypt', 'orion:authz_unblind_start', 'orion:authz_decrypt_done');
                omeasure('orion.tca.authz_pin_to_plaintext', 'orion:authz_pin_submit', 'orion:authz_decrypt_done');
                document.getElementById('pin_input_div').style.display = 'none';
                document.getElementById('rp_domain_div').style.display = 'block';
                const Dstr = base64ToString(D);
                document.getElementById('Domain').textContent = Dstr;
                document.getElementById('ACID').textContent = `{"Sigma1":"${Sigma1}","Sigma2":"${Sigma2}"}`;
                document.getElementById('Nonce').textContent = Nonce;
                document.getElementById('notice_message').textContent = "Decryption successful.";
                window.parent.postMessage({ type: 'decryption_done' }, IDP_PARENT_ORIGIN);
            } catch (error) {
                document.getElementById('notice_message').textContent =
                    'Decryption failed — check your PIN and try again.';
                submit_pin_btn.disabled = false;
            }
            break;
    }
}, false);

// Signals the parent page that this frame is ready to receive the record.
window.addEventListener('DOMContentLoaded', () => {
    window.parent.postMessage({ type: 'dvf_ready' }, IDP_PARENT_ORIGIN);
});
