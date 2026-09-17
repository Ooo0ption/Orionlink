import { Locator } from '@playwright/test';

// Simulated human interaction cost for the end-to-end latency figures.
//
// Why the harness cannot just click as fast as Playwright allows: the number
// the paper reports as "end-to-end login latency" is what a user waits, and a
// user does not submit a PIN 3 ms after the field becomes enabled. Driving the
// flow at machine speed measures the system's throughput, not the login's
// duration, and it also hides an effect that matters here — OrionLink's TCA
// does its heavy cryptography while the user is still reading and typing, so
// part of the protocol cost is absorbed by that time rather than added to it.
//
// The charge is a flat 100 ms per interaction. It is deliberately a single
// crude constant: the quantities the paper reports are the protocol measures
// and the machine time, and this exists only to keep the flow from being
// unrealistically instantaneous.
//
// Environment:
//   ORION_HUMAN=0   disable entirely (every interaction becomes 0 ms)

/** Simulated cost of one interaction: a click, or filling one field. */
export const ACTION_MS = 100;

/** Sign in, username, password, submit, PIN, submit PIN. */
export const ACTIONS_PER_LOGIN = 6;

const ENABLED = process.env.ORION_HUMAN !== '0';

/**
 * Charges a fixed delay per interaction and keeps a running total, so a harness
 * can report the machine-only latency alongside the user-perceived one without
 * a second run.
 */
export class Human {
    /** Total simulated human time consumed, in milliseconds. */
    total = 0;

    /** Resets the accumulator between iterations. */
    reset() {
        this.total = 0;
    }

    /** Sleeps for one interaction's worth of time and books it. */
    private async pause(): Promise<void> {
        if (!ENABLED) return;
        this.total += ACTION_MS;
        await new Promise((r) => setTimeout(r, ACTION_MS));
    }

    /**
     * Clicks the target, after one interaction's delay.
     *
     * Returns the epoch ms at which the click was actually issued, so a latency
     * harness can start a stage interval at the action rather than at the start
     * of the simulated delay in front of it.
     */
    async click(target: Locator): Promise<number> {
        await this.pause();
        const at = Date.now();
        await target.click();
        return at;
    }

    /**
     * Fills a field, after one interaction's delay.
     *
     * Set atomically rather than key by key. Typing through
     * `pressSequentially` costs one CDP round trip per character — some 100 ms
     * for a 6-digit PIN — and that lands inside the measured consent interval,
     * where it would be reported as protocol cost. Nothing on either form
     * observes the difference: neither the IdP credential page nor the TCA
     * registers an input handler, and the PIN is read once, from the click
     * handler (tca/dvf.js). Restore per-key delivery here if a field ever does
     * grow one, and move the wait out of the measured span.
     */
    async type(target: Locator, text: string): Promise<number> {
        await this.pause();
        const at = Date.now();
        await target.fill(text);
        return at;
    }

    /** Simulated cost of one full login, for sizing test timeouts. */
    static estimatePerLoginMs(): number {
        return ENABLED ? ACTIONS_PER_LOGIN * ACTION_MS : 0;
    }
}

/** Describes the active configuration, for the report header. */
export function humanConfig() {
    return {
        enabled: ENABLED,
        per_action_ms: ENABLED ? ACTION_MS : 0,
        actions_per_login: ACTIONS_PER_LOGIN,
    };
}
