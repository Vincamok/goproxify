import { sleep } from "k6";
import { get, summary } from "./common.js";

// PAUSE (secondes) entre deux itérations : sans pause, 2 VUs envoient ~900 req/s ; run-load.sh --target la fixe à 0,1 s.
const PAUSE = Number(__ENV.PAUSE || 0);

export const options = {
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
  vus: 2,
  duration: "15s",
  thresholds: { http_req_failed: ["rate<0.01"], http_req_duration: ["p(95)<200"] },
};

export default function () {
  get("/");
  get("/echo");
  if (PAUSE > 0) sleep(PAUSE);
}

export const handleSummary = summary("smoke");
