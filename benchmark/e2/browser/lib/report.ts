import * as fs from 'fs';
import * as path from 'path';
import { humanConfig } from '../human';

// Shared summarisation and report writing for the three perf harnesses under
// perf/. Each of them measures a different row group of paper Table 4
// (tab:latency-breakdown) and writes one JSON file into benchmark/results/.

export const ITERATIONS = Number(process.env.ORION_PERF_ITERATIONS || 10);
export const OUT_DIR =
    // benchmark/e2/browser/lib -> benchmark/results, shared with the Go harness
    // under benchmark/e2/tokenrefresh. Each report is named after the spec that
    // produced it, prefixed with its experiment: e2-<spec>-<profile>.json.
    process.env.ORION_PERF_OUT || path.resolve(__dirname, '../../../results');
export const PROFILE = process.env.ORION_PROFILE || 'demo';

export interface Summary {
    n: number;
    mean_ms: number;
    stddev_ms: number;
    min_ms: number;
    p50_ms: number;
    p95_ms: number;
    max_ms: number;
}

export function summarize(samples: number[]): Summary {
    const sorted = [...samples].sort((a, b) => a - b);
    const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
    const variance =
        samples.reduce((acc, v) => acc + (v - mean) ** 2, 0) / Math.max(1, samples.length - 1);
    const at = (q: number) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
    return {
        n: samples.length,
        mean_ms: mean,
        stddev_ms: Math.sqrt(variance),
        min_ms: sorted[0],
        p50_ms: at(0.5),
        p95_ms: at(0.95),
        max_ms: sorted[sorted.length - 1],
    };
}

/** Column-wise summary of a list of per-iteration records. */
export function summarizeAll<T extends Record<string, number>>(
    rows: T[],
): Record<string, Summary> {
    const out: Record<string, Summary> = {};
    if (rows.length === 0) return out;
    for (const key of Object.keys(rows[0])) {
        out[key] = summarize(rows.map((r) => r[key]));
    }
    return out;
}

export interface Report {
    /** Which rows of paper Table 4 this file backs. */
    table4_rows: string[];
    profile: string;
    iterations: number;
    generated_at: string;
    human: ReturnType<typeof humanConfig>;
    /** The concrete measured path, when transport semantics matter. */
    transport?: string;
    stages: Record<string, Summary>;
    /** Sub-measures self-reported by the TCA, where the harness collects them. */
    measures?: Record<string, Summary>;
}

/** Writes `results/<name>-<profile>.json` and prints the same figures. */
export function writeReport(name: string, report: Report): string {
    fs.mkdirSync(OUT_DIR, { recursive: true });
    const outFile = path.join(OUT_DIR, `${name}-${report.profile}.json`);
    fs.writeFileSync(outFile, JSON.stringify(report, null, 2));

    console.log(`\n${name}  profile=${report.profile}  iterations=${report.iterations}`);
    console.log(`  Table 4 rows: ${report.table4_rows.join(', ')}`);
    printBlock('stages', report.stages);
    if (report.measures) printBlock('TCA sub-measures', report.measures);
    console.log(`\nwrote ${outFile}`);
    return outFile;
}

function printBlock(title: string, block: Record<string, Summary>) {
    console.log(`  --- ${title} ---`);
    for (const [key, s] of Object.entries(block)) {
        console.log(
            `  ${key.padEnd(28)} mean ${s.mean_ms.toFixed(2).padStart(9)} ms  ` +
                `p50 ${s.p50_ms.toFixed(2).padStart(9)}  p95 ${s.p95_ms.toFixed(2).padStart(9)}  ` +
                `sd ${s.stddev_ms.toFixed(2)}`,
        );
    }
}
