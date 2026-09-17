/**
 * StudyVerse AI - Production Cloud Functions Backend
 * Stack: Firebase Functions (v2), Express, Firestore Admin SDK, Razorpay Webhooks, Google GenAI
 * Security: HMAC SHA256 Signature Verification, Timing-Safe Comparison, Idempotency, Fail-Closed Auth & Subscription Gate
 */

const { onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { GoogleGenAI } = require("@google/genai");

// Initialize Firebase Admin SDK
if (!admin.apps.length) {
  admin.initializeApp();
}
const db = admin.firestore();

const app = express();

// Enable Cross-Origin Resource Sharing
app.use(cors({ origin: true }));

/**
 * CRITICAL SECURITY REQUIREMENT:
 * Preserve raw request buffer for HMAC SHA256 signature validation.
 * Never rely on JSON.stringify(req.body) as key order or formatting shifts invalidate signatures.
 */
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

// ---------------------------------------------------------------------------
// 1. Razorpay Webhook Endpoint (/api/razorpay-webhook)
// ---------------------------------------------------------------------------
app.post("/api/razorpay-webhook", async (req, res) => {
  const signature = req.headers["x-razorpay-signature"];
  const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

  if (!signature || !webhookSecret) {
    console.error("[Webhook Error] Missing signature or RAZORPAY_WEBHOOK_SECRET in environment.");
    return res.status(400).json({ error: "Missing signature or webhook secret configuration" });
  }

  // 1. HMAC SHA256 Signature Verification using raw payload
  try {
    const rawPayload = req.rawBody || Buffer.from(JSON.stringify(req.body));
    const expectedSignature = crypto
      .createHmac("sha256", webhookSecret)
      .update(rawPayload)
      .digest("hex");

    // Timing-safe comparison prevents timing attack vectors
    const isSignatureValid = crypto.timingSafeEqual(
      Buffer.from(expectedSignature, "utf8"),
      Buffer.from(signature, "utf8")
    );

    if (!isSignatureValid) {
      console.warn("[Webhook Security] Invalid signature detected. Rejected request.");
      return res.status(400).json({ error: "Invalid signature" });
    }
  } catch (err) {
    console.error("[Webhook Security] Signature validation failed:", err.message);
    return res.status(400).json({ error: "Signature verification failed" });
  }

  const event = req.body;
  // Extract unique Event ID for Idempotency
  const eventId =
    event.id ||
    req.headers["x-razorpay-event-id"] ||
    (event.payload && event.payload.payment && event.payload.payment.entity && event.payload.payment.entity.id);

  if (!eventId) {
    console.error("[Webhook Error] Could not determine unique event identifier.");
    return res.status(400).json({ error: "Missing event identifier" });
  }

  try {
    // 2. Atomic Idempotency Check & Subscription Activation
    const webhookDocRef = db.collection("processed_webhooks").doc(eventId);

    await db.runTransaction(async (transaction) => {
      const webhookDoc = await transaction.get(webhookDocRef);

      // If already processed, exit transaction immediately
      if (webhookDoc.exists) {
        return;
      }

      // Mark this webhook event as processed immediately in transaction
      transaction.set(webhookDocRef, {
        eventId,
        event: event.event,
        processedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      // Handle successful payment events
      if (event.event === "payment.captured" || event.event === "order.paid") {
        const paymentEntity =
          event.payload?.payment?.entity || event.payload?.order?.entity;

        if (!paymentEntity) {
          throw new Error("Missing payment entity inside webhook payload");
        }

        // Retrieve user metadata provided when creating the Razorpay Order
        const userId =
          paymentEntity.notes?.userId ||
          paymentEntity.notes?.uid ||
          paymentEntity.notes?.studentId;

        const planTier =
          paymentEntity.notes?.planTier ||
          paymentEntity.notes?.plan ||
          "MONTHLY_PASS";

        // Calculate subscription duration (default 30 days)
        const durationDays = parseInt(paymentEntity.notes?.durationDays || "30", 10);
        const validUntil = new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000);

        if (userId) {
          const userDocRef = db.collection("users").doc(userId);

          transaction.set(
            userDocRef,
            {
              subscriptionStatus: "ACTIVE",
              planTier: planTier,
              validUntil: admin.firestore.Timestamp.fromDate(validUntil),
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
              lastPayment: {
                paymentId: paymentEntity.id,
                orderId: paymentEntity.order_id || null,
                amount: paymentEntity.amount / 100, // paise to INR
                currency: paymentEntity.currency || "INR",
                method: paymentEntity.method || "unknown",
                capturedAt: admin.firestore.FieldValue.serverTimestamp(),
              },
            },
            { merge: true }
          );

          // Write audit log entry
          const paymentAuditRef = db.collection("payments").doc(paymentEntity.id);
          transaction.set(paymentAuditRef, {
            paymentId: paymentEntity.id,
            userId,
            planTier,
            amount: paymentEntity.amount / 100,
            validUntil: admin.firestore.Timestamp.fromDate(validUntil),
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
          });

          console.log(`[Subscription Activated] User ${userId} upgraded to ${planTier}.`);
        } else {
          console.warn(`[Webhook Warning] No userId found in notes for payment ${paymentEntity.id}`);
        }
      }
    });

    // Acknowledge receipt to Razorpay
    return res.status(200).json({ status: "success", eventId });
  } catch (error) {
    console.error("[Webhook Internal Error]:", error);
    // Returning 500 triggers Razorpay's automated exponential retry mechanism
    return res.status(500).json({ error: "Internal processing error. Retrying." });
  }
});

// ---------------------------------------------------------------------------
// 2. Secure Gemini AI Proxy API (/api/generate-ai-response)
// ---------------------------------------------------------------------------
app.post("/api/generate-ai-response", async (req, res) => {
  // 1. Authenticate Firebase Auth Bearer Token
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: Missing Bearer Token" });
  }

  const idToken = authHeader.split("Bearer ")[1].trim();
  let decodedToken;

  try {
    decodedToken = await admin.auth().verifyIdToken(idToken);
  } catch (authErr) {
    console.error("[Auth Error] Invalid Firebase ID Token:", authErr.message);
    return res.status(401).json({ error: "Unauthorized: Invalid or expired token" });
  }

  const uid = decodedToken.uid;
  const { prompt, subject, grade } = req.body;

  if (!prompt || typeof prompt !== "string" || prompt.trim().length === 0) {
    return res.status(400).json({ error: "Bad Request: prompt is required" });
  }

  // 2. Fail-Closed Subscription Gatekeeper
  try {
    const userDoc = await db.collection("users").doc(uid).get();

    if (!userDoc.exists) {
      return res.status(403).json({
        error: "Forbidden: User profile not found. Subscription required.",
      });
    }

    const userData = userDoc.data();
    const isStatusActive = userData.subscriptionStatus === "ACTIVE";

    let isNotExpired = true;
    if (userData.validUntil) {
      const validUntilDate = userData.validUntil.toDate
        ? userData.validUntil.toDate()
        : new Date(userData.validUntil);
      if (Date.now() > validUntilDate.getTime()) {
        isNotExpired = false;
      }
    }

    // Fail-Closed Policy
    if (!isStatusActive || !isNotExpired) {
      return res.status(403).json({
        error: "Forbidden: Active subscription required. Your plan is inactive or expired.",
        subscriptionStatus: userData.subscriptionStatus || "INACTIVE",
        isExpired: !isNotExpired,
      });
    }

    // 3. Authorized Call to Google Gemini API
    const geminiApiKey = process.env.GEMINI_API_KEY;
    if (!geminiApiKey) {
      console.error("[Config Error] Missing GEMINI_API_KEY in environment variables.");
      return res.status(500).json({ error: "AI Service configuration error" });
    }

    const ai = new GoogleGenAI({ apiKey: geminiApiKey });

    // Pedagogical System Instruction with KaTeX Mathematical Enforcement
    const systemInstruction = `
You are StudyVerse AI, a premier Indian curriculum (CBSE/ICSE/State Board/JEE/NEET) educational tutor.
Student context: Grade ${grade || "10"}, Subject: ${subject || "General Study"}.

STRICT MATHEMATICAL & SCIENTIFIC FORMATTING RULES (KaTeX COMPLIANT):
1. Always format all mathematical formulas, algebraic equations, physical units, and chemical reactions using standard LaTeX / KaTeX.
2. Format inline math using single dollar signs: e.g. $x = \\frac{-b \\pm \\sqrt{b^2 - 4ac}}{2a}$ or $F = ma$.
3. Format multi-line, standalone equations using double dollar signs:
   $$E = mc^2$$
4. For chemistry reactions, use:
   $$2H_2 + O_2 \\rightarrow 2H_2O$$
5. Break answers down into step-by-step points with bold keywords, intuitive real-life examples, and an exam tip.
`;

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: prompt,
      config: {
        systemInstruction,
        temperature: 0.4,
      },
    });

    return res.status(200).json({
      success: true,
      response: response.text,
      model: "gemini-2.5-flash",
      timestamp: new Date().toISOString(),
    });
  } catch (apiErr) {
    console.error("[Gemini AI Error]:", apiErr);
    return res.status(500).json({
      error: "Failed to generate AI response. Please try again.",
    });
  }
});

// Export as Firebase 2nd Gen HTTP Cloud Function
exports.api = onRequest({ region: "asia-south1", cors: true }, app);
