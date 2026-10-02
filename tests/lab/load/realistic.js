// Trafic réaliste sur la boutique simulée (route lab-realistic : 3 instances, health check, retry, rate-limit, réécriture du corps) :
// clients web (pages + assets + panier), clients API, lecteurs de flux SSE, échanges WebSocket, téléchargements
// et envois de fichiers. Débit imposé (modèle ouvert) avec une courbe de journée ; SHOP_RATE = pic d'itérations/s
// des visiteurs (≈ 8 requêtes chacune). Par défaut ~150 req/s au pic pendant 3 min : faible impact sur la production.
import http from "k6/http";
import ws from "k6/ws";
import { check, sleep, group } from "k6";
import { summary } from "./common.js";

const HOST = __ENV.HOST || "lab-realistic.lab.test";
const BASE = `http://${HOST}`;
const PEAK = Number(__ENV.SHOP_RATE || 20);
const D = __ENV.DURATION || "3m";

// 404 attendus (liens morts) : ne comptent pas comme échecs.
http.setResponseCallback(http.expectedStatuses({ min: 200, max: 399 }, 404));

export const options = {
  summaryTrendStats: ["avg", "med", "p(90)", "p(95)", "p(99)", "max"],
  scenarios: {
    visiteurs: {
      executor: "ramping-arrival-rate",
      exec: "visiteur",
      startRate: 1,
      timeUnit: "1s",
      preAllocatedVUs: 50,
      maxVUs: 300,
      stages: [
        { duration: "20s", target: Math.max(2, Math.round(PEAK / 4)) },
        { duration: "1m", target: PEAK },
        { duration: "1m", target: Math.round(PEAK / 2) },
        { duration: "40s", target: 1 },
      ],
    },
    api: { executor: "constant-arrival-rate", exec: "clientApi", rate: Math.max(1, Math.round(PEAK / 2)), timeUnit: "1s", duration: D, preAllocatedVUs: 20, maxVUs: 100 },
    flux: { executor: "constant-vus", exec: "fluxSSE", vus: 3, duration: D },
    chat: { executor: "constant-vus", exec: "chatWS", vus: 3, duration: D },
    fichiers: { executor: "constant-arrival-rate", exec: "fichiers", rate: 1, timeUnit: "2s", duration: D, preAllocatedVUs: 5, maxVUs: 10 },
  },
  thresholds: {
    "http_req_failed{kind:page}": ["rate<0.01"],
    "http_req_failed{kind:api}": ["rate<0.01"],
    "http_req_duration{kind:page}": ["p(95)<300"],
    "http_req_duration{kind:api}": ["p(95)<300"],
    "checks": ["rate>0.99"],
    "dropped_iterations": ["count==0"],
  },
};

const assets = ["/static/app.js", "/static/vendor.js", "/static/style.css", "/static/logo.svg", "/static/fonts.woff2"];
const pause = (min, max) => sleep(min + Math.random() * (max - min));

export function visiteur() {
  group("visite", () => {
    let r = http.get(`${BASE}/`, { tags: { kind: "page" } });
    check(r, { "accueil 200": (x) => x.status === 200, "accueil sans URL interne": (x) => !x.body.includes("lab-sim:") });
    for (const a of assets.slice(0, 3 + Math.floor(Math.random() * 3))) {
      http.get(`${BASE}${a}`, { tags: { kind: "asset" } });
    }
    pause(0.5, 2);
    r = http.get(`${BASE}/api/products`, { tags: { kind: "page" } });
    check(r, { "catalogue JSON": (x) => x.status === 200 && x.json("items.0.name") === "stylo" });
    if (Math.random() < 0.3) {
      pause(0.5, 1.5);
      http.get(`${BASE}/login`, { tags: { kind: "page" } });
      r = http.post(`${BASE}/echo`, JSON.stringify({ cart: [1, 2, 3] }), { headers: { "Content-Type": "application/json" }, tags: { kind: "page" } });
      check(r, { "panier accepté": (x) => x.status === 200 });
    }
    if (Math.random() < 0.05) http.get(`${BASE}/ancienne-page`, { tags: { kind: "page" } }); // 404 légitime côté site
  });
}

export function clientApi() {
  const h = { headers: { Authorization: "Bearer lab-token", Accept: "application/json" }, tags: { kind: "api" } };
  const r = http.get(`${BASE}/api/v1/orders?page=${1 + Math.floor(Math.random() * 5)}`, h);
  check(r, { "api 200": (x) => x.status === 200 });
  if (Math.random() < 0.1) http.options(`${BASE}/api/v1/orders`, { headers: { Origin: "https://app.lab.test", "Access-Control-Request-Method": "GET" }, tags: { kind: "api" } });
  if (Math.random() < 0.2) http.get(`${BASE}/slow?ms=${100 + Math.floor(Math.random() * 400)}`, { tags: { kind: "api" } });
}

export function fluxSSE() {
  const r = http.get(`${BASE}/sse?n=10&ms=300`, { tags: { kind: "sse" } });
  check(r, { "flux complet": (x) => x.status === 200 && (x.body.match(/data:/g) || []).length === 10 });
  pause(1, 3);
}

export function chatWS() {
  const res = ws.connect(`ws://${HOST}/ws`, {}, (s) => {
    let got = 0;
    s.on("open", () => s.send("bonjour"));
    s.on("message", (m) => {
      got++;
      check(m, { "écho WebSocket": (x) => x.endsWith(":bonjour") || x.endsWith(":msg") });
      if (got < 5) s.setTimeout(() => s.send("msg"), 400);
      else s.close();
    });
    s.setTimeout(() => s.close(), 10000);
  });
  check(res, { "upgrade 101": (r) => r && r.status === 101 });
  pause(1, 4);
}

export function fichiers() {
  if (Math.random() < 0.6) {
    const r = http.get(`${BASE}/bytes?n=2097152`, { tags: { kind: "download" } });
    check(r, { "téléchargement 2 Mo": (x) => x.status === 200 && x.body.length === 2097152 });
  } else {
    const r = http.post(`${BASE}/upload`, "z".repeat(512 * 1024), { tags: { kind: "upload" } });
    check(r, { "envoi 512 Ko": (x) => x.status === 200 && x.body === String(512 * 1024) });
  }
}

export const handleSummary = summary("realistic");
