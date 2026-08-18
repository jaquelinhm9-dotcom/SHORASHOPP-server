import express from "express";
import cors from "cors";
import crypto from "node:crypto";
import "dotenv/config";

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.disable("x-powered-by");
app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.get("/", (_req, res) => {
  res.json({
    name: "SHORASHOPP",
    service: "backend",
    status: "online"
  });
});

app.get("/api/health", (_req, res) => {
  res.status(200).json({
    ok: true,
    service: "shorashopp-server",
    time: new Date().toISOString()
  });
});

function parseSignature(value = "") {
  const result = {};
  for (const part of value.split(",")) {
    const [key, ...rest] = part.trim().split("=");
    if (key && rest.length) result[key] = rest.join("=");
  }
  return result;
}

function verifyMercadoPagoSignature(req) {
  const secret = process.env.MERCADOPAGO_WEBHOOK_SECRET;
  if (!secret) return { ok: false, status: 503, reason: "Webhook secret not configured" };

  const xSignature = req.get("x-signature");
  const xRequestId = req.get("x-request-id");
  if (!xSignature || !xRequestId) {
    return { ok: false, status: 401, reason: "Missing Mercado Pago signature headers" };
  }

  const { ts, v1 } = parseSignature(xSignature);
  const dataId = req.query["data.id"];

  // Mercado Pago's documented manifest for HMAC-SHA256.
  const manifestParts = [];
  if (dataId !== undefined && dataId !== "") manifestParts.push(`id:${String(dataId).toLowerCase()}`);
  if (xRequestId) manifestParts.push(`request-id:${xRequestId}`);
  if (ts) manifestParts.push(`ts:${ts}`);
  const manifest = manifestParts.join(";") + ";";

  if (!ts || !v1) {
    return { ok: false, status: 401, reason: "Invalid Mercado Pago signature format" };
  }

  const expected = crypto
    .createHmac("sha256", secret)
    .update(manifest)
    .digest("hex");

  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(v1, "utf8");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, status: 401, reason: "Invalid Mercado Pago signature" };
  }

  return { ok: true };
}

// Mercado Pago Webhook endpoint.
// Configure this URL in Mercado Pago as:
// https://TU-DOMINIO/api/webhooks/mercadopago
app.post("/api/webhooks/mercadopago", async (req, res) => {
  const verification = verifyMercadoPagoSignature(req);

  if (!verification.ok) {
    console.warn("[Mercado Pago webhook rejected]", verification.reason);
    return res.status(verification.status).json({ ok: false });
  }

  const event = req.body || {};
  console.log("[Mercado Pago webhook]", JSON.stringify({
    receivedAt: new Date().toISOString(),
    id: event.id ?? null,
    type: event.type ?? null,
    action: event.action ?? null,
    dataId: event.data?.id ?? req.query["data.id"] ?? null,
    liveMode: event.live_mode ?? null
  }));

  // IMPORTANT:
  // The production version should persist the event/order/payment in the
  // SHORASHOPP database and then reconcile the resource with Mercado Pago.
  // Keep this response fast: Mercado Pago expects HTTP 200/201.
  return res.sendStatus(200);
});

app.use((_req, res) => {
  res.status(404).json({ ok: false, error: "Not found" });
});

app.listen(PORT, () => {
  console.log(`SHORASHOPP server listening on port ${PORT}`);
});
