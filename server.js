import express from "express";
import cors from "cors";
import crypto from "node:crypto";
import Stripe from "stripe";
import "dotenv/config";

const app = express();
const PORT = Number(process.env.PORT || 3000);

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;

if (!STRIPE_SECRET_KEY) {
  console.warn(
    "[Stripe] STRIPE_SECRET_KEY is not configured. Stripe checkout will be unavailable."
  );
}

const stripe = STRIPE_SECRET_KEY
  ? new Stripe(STRIPE_SECRET_KEY)
  : null;

app.disable("x-powered-by");

app.use(
  cors({
    origin: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

app.use(express.json({ limit: "1mb" }));

app.get("/", (_req, res) => {
  res.json({
    name: "SHORASHOPP",
    service: "backend",
    status: "online",
    stripeConfigured: Boolean(stripe)
  });
});

app.get("/api/health", (_req, res) => {
  res.status(200).json({
    ok: true,
    service: "shorashopp-server",
    stripeConfigured: Boolean(stripe),
    time: new Date().toISOString()
  });
});

/* -------------------------------------------------------------------------- */
/*                                STRIPE                                      */
/* -------------------------------------------------------------------------- */

function sanitizeProduct(item) {
  if (!item || typeof item !== "object") return null;

  const name =
    typeof item.name === "string" && item.name.trim()
      ? item.name.trim().slice(0, 200)
      : null;

  const price = Number(item.price);
  const quantity = Number(item.quantity ?? 1);

  if (!name) return null;
  if (!Number.isFinite(price) || price <= 0) return null;
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
    return null;
  }

  return {
    name,
    price,
    quantity
  };
}

app.post("/api/stripe/create-checkout-session", async (req, res) => {
  try {
    if (!stripe) {
      return res.status(503).json({
        ok: false,
        error: "Stripe is not configured on the server."
      });
    }

    const items = Array.isArray(req.body?.items)
      ? req.body.items.map(sanitizeProduct).filter(Boolean)
      : [];

    if (!items.length) {
      return res.status(400).json({
        ok: false,
        error: "No valid products were provided."
      });
    }

    const successUrl =
      typeof req.body?.successUrl === "string" &&
      req.body.successUrl.startsWith("http")
        ? req.body.successUrl
        : null;

    const cancelUrl =
      typeof req.body?.cancelUrl === "string" &&
      req.body.cancelUrl.startsWith("http")
        ? req.body.cancelUrl
        : null;

    if (!successUrl || !cancelUrl) {
      return res.status(400).json({
        ok: false,
        error: "Valid successUrl and cancelUrl are required."
      });
    }

    const lineItems = items.map((item) => ({
      price_data: {
        currency: "mxn",
        product_data: {
          name: item.name
        },
        unit_amount: Math.round(item.price * 100)
      },
      quantity: item.quantity
    }));

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: lineItems,

      success_url: `${successUrl}${
        successUrl.includes("?") ? "&" : "?"
      }session_id={CHECKOUT_SESSION_ID}`,

      cancel_url: cancelUrl,

      metadata: {
        platform: "VaniDaxi"
      }
    });

    return res.status(200).json({
      ok: true,
      checkoutUrl: session.url,
      sessionId: session.id
    });
  } catch (error) {
    console.error("[Stripe checkout error]", error);

    return res.status(500).json({
      ok: false,
      error: "Unable to create Stripe checkout session."
    });
  }
});

/* -------------------------------------------------------------------------- */
/*                              MERCADO PAGO                                  */
/* -------------------------------------------------------------------------- */

function parseSignature(value = "") {
  const result = {};

  for (const part of value.split(",")) {
    const [key, ...rest] = part.trim().split("=");

    if (key && rest.length) {
      result[key] = rest.join("=");
    }
  }

  return result;
}

function verifyMercadoPagoSignature(req) {
  const secret = process.env.MERCADOPAGO_WEBHOOK_SECRET;

  if (!secret) {
    return {
      ok: false,
      status: 503,
      reason: "Webhook secret not configured"
    };
  }

  const xSignature = req.get("x-signature");
  const xRequestId = req.get("x-request-id");

  if (!xSignature || !xRequestId) {
    return {
      ok: false,
      status: 401,
      reason: "Missing Mercado Pago signature headers"
    };
  }

  const { ts, v1 } = parseSignature(xSignature);
  const dataId = req.query["data.id"];

  const manifestParts = [];

  if (dataId !== undefined && dataId !== "") {
    manifestParts.push(`id:${String(dataId).toLowerCase()}`);
  }

  if (xRequestId) {
    manifestParts.push(`request-id:${xRequestId}`);
  }

  if (ts) {
    manifestParts.push(`ts:${ts}`);
  }

  const manifest = `${manifestParts.join(";")};`;

  if (!ts || !v1) {
    return {
      ok: false,
      status: 401,
      reason: "Invalid Mercado Pago signature format"
    };
  }

  const expected = crypto
    .createHmac("sha256", secret)
    .update(manifest)
    .digest("hex");

  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(v1, "utf8");

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return {
      ok: false,
      status: 401,
      reason: "Invalid Mercado Pago signature"
    };
  }

  return { ok: true };
}

app.post("/api/webhooks/mercadopago", async (req, res) => {
  const verification = verifyMercadoPagoSignature(req);

  if (!verification.ok) {
    console.warn(
      "[Mercado Pago webhook rejected]",
      verification.reason
    );

    return res.status(verification.status).json({
      ok: false
    });
  }

  const event = req.body || {};

  console.log(
    "[Mercado Pago webhook]",
    JSON.stringify({
      receivedAt: new Date().toISOString(),
      id: event.id ?? null,
      type: event.type ?? null,
      action: event.action ?? null,
      dataId: event.data?.id ?? req.query["data.id"] ?? null,
      liveMode: event.live_mode ?? null
    })
  );

  return res.sendStatus(200);
});

/* -------------------------------------------------------------------------- */

app.use((_req, res) => {
  res.status(404).json({
    ok: false,
    error: "Not found"
  });
});

app.listen(PORT, () => {
  console.log(`SHORASHOPP server listening on port ${PORT}`);
});
