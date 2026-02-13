import { analyze } from "./lib/bininspect_wasm.js";
import type { AnalysisReport } from "./lib/bininspect_wasm.d.ts";

const report: AnalysisReport = analyze(
  await Deno.readFile(
    "./target/release/bininspect",
  ),
);

if (report) {
  await Deno.writeTextFile(
    "bininspect-output.json",
    JSON.stringify(report, null, 2),
  );
}
