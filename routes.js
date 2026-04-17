import express from "express";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { PDFDocument } from "pdf-lib";
import { generateToken } from "./auth.js";
import { protect } from "./middleware.js";
import { upload } from "./upload.js";
import { supabase } from "./supabase.js";

const router = express.Router();
const RAZORPAY_BASE_URL = "https://api.razorpay.com/v1";
const PAYMENT_AMOUNT_PAISE = 50000;
const PAYMENT_CURRENCY = "INR";

const imageExt = (path = "") => path.toLowerCase().split(".").pop() || "";

const toPdfCoords = (page, pos) => {
  const { width, height } = page.getSize();
  return {
    x: (Number(pos.x) / 100) * width,
    y: height - (Number(pos.y) / 100) * height,
    pageWidth: width,
    pageHeight: height,
  };
};

const toPdfSize = (coords, pos, defaults, embeddedImage = null) => {
  const widthPct =
    typeof pos?.widthPct === "number" ? Math.max(1, pos.widthPct) : defaults.w;
  const width = (widthPct / 100) * coords.pageWidth;

  if (
    embeddedImage &&
    typeof embeddedImage.width === "number" &&
    typeof embeddedImage.height === "number" &&
    embeddedImage.width > 0
  ) {
    return {
      width,
      height: (width * embeddedImage.height) / embeddedImage.width,
    };
  }

  const heightPct =
    typeof pos?.heightPct === "number" ? Math.max(1, pos.heightPct) : defaults.h;

  return {
    width,
    height: (heightPct / 100) * coords.pageHeight,
  };
};

const fetchBytesFromSignedPath = async (path) => {
  const { data: signedData, error: signedError } = await supabase.storage
    .from("documents")
    .createSignedUrl(path, 300);

  if (signedError) throw signedError;

  const resp = await fetch(signedData.signedUrl);

  if (!resp.ok) {
    throw new Error(`Failed to fetch file bytes: ${resp.status}`);
  }

  const arr = await resp.arrayBuffer();
  return new Uint8Array(arr);
};

const detectImageFormat = (bytes) => {
  if (!bytes || bytes.length < 4) return "unknown";

  // PNG: 89 50 4E 47
  if (
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47
  ) {
    return "png";
  }

  // JPEG: FF D8
  if (bytes[0] === 0xff && bytes[1] === 0xd8) {
    return "jpg";
  }

  return "unknown";
};

const embedImageSafe = async (pdfDoc, bytes, label) => {
  const fmt = detectImageFormat(bytes);

  try {
    if (fmt === "png") {
      return await pdfDoc.embedPng(bytes);
    }

    if (fmt === "jpg") {
      return await pdfDoc.embedJpg(bytes);
    }

    // Fallback if magic number not detected.
    try {
      return await pdfDoc.embedPng(bytes);
    } catch {
      return await pdfDoc.embedJpg(bytes);
    }
  } catch (err) {
    throw new Error(
      `Invalid ${label} image format. Please upload PNG or JPG image.`,
    );
  }
};

const ensureRazorpayConfig = () => {
  if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
    throw new Error("Razorpay keys are not configured");
  }
};

const razorpayAuthHeader = () => {
  const encoded = Buffer.from(
    `${process.env.RAZORPAY_KEY_ID}:${process.env.RAZORPAY_KEY_SECRET}`,
  ).toString("base64");

  return `Basic ${encoded}`;
};

const razorpayRequest = async (path, options = {}) => {
  ensureRazorpayConfig();

  const response = await fetch(`${RAZORPAY_BASE_URL}${path}`, {
    ...options,
    headers: {
      Authorization: razorpayAuthHeader(),
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  const json = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(json?.error?.description || "Razorpay API request failed");
  }

  return json;
};

const verifyRazorpaySignature = ({ orderId, paymentId, signature }) => {
  ensureRazorpayConfig();

  const payload = `${orderId}|${paymentId}`;
  const expected = crypto
    .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
    .update(payload)
    .digest("hex");

  return expected === signature;
};

const verifyRazorpayWebhookSignature = ({ rawBody, signature }) => {
  const webhookSecret =
    process.env.RAZORPAY_WEBHOOK_SECRET || process.env.RAZORPAY_KEY_SECRET;

  if (!webhookSecret) {
    throw new Error("Razorpay webhook secret is not configured");
  }

  const expected = crypto
    .createHmac("sha256", webhookSecret)
    .update(rawBody)
    .digest("hex");

  return expected === signature;
};

/* ================= AUTH ================= */

// Register
router.post("/auth/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const cleanName = String(name || "").trim();
    const cleanEmail = String(email || "").trim().toLowerCase();

    if (role === "admin") {
      return res.status(403).json({
        error: "Not a Admin",
      });
    }

    if (!cleanName || !cleanEmail || !password || !role) {
      return res.status(400).json({ error: "All fields required" });
    }

    // Check if email exists
    const { data: existing, error: existingError } = await supabase
      .from("users")
      .select("id")
      .eq("email", cleanEmail)
      .maybeSingle();

    if (existingError) throw existingError;

    if (existing) {
      return res.status(400).json({
        error: "Email already registered",
      });
    }

    // Hash password
    const hash = await bcrypt.hash(password, 10);

    // Insert user
    // Get max notary number
    let notaryNumber = null;

    if (role === "notary") {
      const { data } = await supabase
        .from("users")
        .select("notary_number")
        .eq("role", "notary")
        .order("notary_number", { ascending: false })
        .limit(1);

      notaryNumber = data?.[0]?.notary_number ? data[0].notary_number + 1 : 1;
    }

    // Insert user
    const { error } = await supabase.from("users").insert([
      {
        name: cleanName,
        email: cleanEmail,
        password: hash,
        role,
        notary_number: notaryNumber,
      },
    ]);

    if (error?.code === "23505") {
      return res.status(400).json({
        error: "Email already registered",
      });
    }
    if (error) throw error;

    res.json({ message: "Registered successfully" });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error:
        err instanceof Error ? `Registration failed: ${err.message}` : "Registration failed",
    });
  }
});

// Login
router.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = String(email || "").trim().toLowerCase();

    if (!cleanEmail || !password) {
      return res.status(400).json({
        error: "Email and password required",
      });
    }

    // Get user from DB
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", cleanEmail)
      .single();

    if (!user || error) {
      return res.status(400).json({
        error: "User not found",
      });
    }

    // Compare password
    const ok = await bcrypt.compare(password, user.password);

    if (!ok) {
      return res.status(400).json({
        error: "Wrong password",
      });
    }

    // Generate JWT
    const token = generateToken(user);

    res.json({
      token,
      role: user.role,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Login failed",
    });
  }
});

// Admin login
router.get("/admin/requests", async (req, res) => {
  console.log("ADMIN REQUEST HIT");

  try {
    const { data, error } = await supabase
      .from("notary_requests")
      .select(
        `
        *,
        users!notary_requests_user_id_fkey (
          name,
          email
        )
      `,
      )
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json(data);
  } catch (err) {
    console.error("ADMIN ERROR:", err);

    res.status(500).json({
      error: "Failed to fetch",
    });
  }
});

/* ================= FILE UPLOAD ================= */

/* ================= UPLOAD ================= */

router.post(
  "/upload",
  protect(["client"]),

  upload.single("document"),

  async (req, res) => {
    try {
      const file = req.file;

      if (!file) {
        return res.status(400).json({
          error: "No file uploaded",
        });
      }

      const name = `docs/${Date.now()}-${file.originalname}`;

      const { data, error } = await supabase.storage
        .from("documents")
        .upload(name, file.buffer, {
          contentType: file.mimetype,
        });

      if (error) throw error;

      res.json({ path: data.path });
    } catch (err) {
      console.error("UPLOAD ERROR:", err);

      res.status(500).json({
        error: "Upload failed",
      });
    }
  },
);

/* ================= ADMIN ================= */

router.post(
  "/admin/approve",
  protect(["admin"]),

  async (req, res) => {
    try {
      const { requestId, notaryId } = req.body;

      if (!requestId || !notaryId) {
        return res.status(400).json({
          error: "Missing fields",
        });
      }

      const { error } = await supabase
        .from("notary_requests")
        .update({
          status: "approved",
          notary_id: notaryId,
          admin_message: null,
        })
        .eq("id", requestId);

      if (error) throw error;

      res.json({ message: "Approved" });
    } catch (err) {
      console.error("APPROVE ERROR:", err);

      res.status(500).json({
        error: "Approve failed",
      });
    }
  },
);

router.post(
  "/admin/reject",
  protect(["admin"]),

  async (req, res) => {
    try {
      const { requestId, message } = req.body;

      if (!requestId || !message) {
        return res.status(400).json({
          error: "Missing fields",
        });
      }

      const { error } = await supabase
        .from("notary_requests")
        .update({
          status: "rejected",
          admin_message: message,
          notary_status: null,
          certificate_id: null,
          signature_url: null,
          stamp_url: null,
        })
        .eq("id", requestId);

      if (error) throw error;

      res.json({ message: "Rejected" });
    } catch (err) {
      console.error("REJECT ERROR:", err);

      res.status(500).json({
        error: "Reject failed",
      });
    }
  },
);

router.post(
  "/admin/update",
  protect(["admin"]),

  async (req, res) => {
    try {
      const { id, name, email, phone, document_type } = req.body;

      if (!id) {
        return res.status(400).json({
          error: "Missing ID",
        });
      }

      const { error } = await supabase
        .from("notary_requests")
        .update({
          name,
          email,
          phone,
          document_type,
        })
        .eq("id", id);

      if (error) throw error;

      res.json({ message: "Updated" });
    } catch (err) {
      console.error("UPDATE ERROR:", err);

      res.status(500).json({
        error: "Update failed",
      });
    }
  },
);

// ================= CLIENT REQUESTS =================

router.get(
  "/client/requests",
  protect(["client"]),

  async (req, res) => {
    try {
      const userId = req.user.id;

      const { data, error } = await supabase
        .from("notary_requests")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false });

      if (error) throw error;

      res.json(data);
    } catch (err) {
      console.error("CLIENT REQUEST ERROR:", err);

      res.status(500).json({
        error: "Failed to load requests",
      });
    }
  },
);

/* ================= DOWNLOAD ================= */

router.get(
  "/download",
  protect(["client", "admin", "notary"]),

  async (req, res) => {
    try {
      const { path } = req.query;

      if (!path) {
        return res.status(400).json({
          error: "Missing file path",
        });
      }

      const { data, error } = await supabase.storage
        .from("documents")
        .createSignedUrl(path, 300);

      if (error) throw error;

      res.json({ url: data.signedUrl });
    } catch (err) {
      console.error("DOWNLOAD ERROR:", err);

      res.status(500).json({
        error: "Download failed",
      });
    }
  },
);

/* ================= DASHBOARDS ================= */

// Admin
router.get(
  "/admin/dashboard",
  protect(["admin"]),

  (req, res) => {
    res.json({
      message: "Welcome Admin",
      user: req.user,
    });
  },
);

// Notary
router.get(
  "/notary/dashboard",
  protect(["notary"]),

  (req, res) => {
    res.json({
      message: "Welcome Notary",
      user: req.user,
    });
  },
);

// Client
router.get(
  "/client/dashboard",
  protect(["client"]),

  (req, res) => {
    res.json({
      message: "Welcome Client",
      user: req.user,
    });
  },
);
router.post(
  "/client/resubmit",
  protect(["client"]),

  async (req, res) => {
    try {
      const {
        id,
        name,
        email,
        phone,
        documentType,
        aadhaar_url,
        photo_url,
        document_url,
      } = req.body;

      const { error } = await supabase
        .from("notary_requests")
        .update({
          name,
          email,
          phone,
          document_type: documentType,
          aadhaar_url,
          photo_url,
          document_url,
          status: "pending",
          admin_message: null,
          notary_status: null,
          certificate_id: null,
          signature_url: null,
          stamp_url: null,
        })
        .eq("id", id);

      if (error) throw error;

      res.json({ message: "Resubmitted" });
    } catch (err) {
      res.status(500).json({
        error: "Resubmit failed",
      });
    }
  },
);

router.get(
  "/client/request/:id",
  protect(["client"]),

  async (req, res) => {
    try {
      const userId = req.user.id;
      const requestId = req.params.id;

      const { data, error } = await supabase
        .from("notary_requests")
        .select("*")
        .eq("id", requestId)
        .eq("user_id", userId) // security: only own request
        .single();

      if (error || !data) {
        return res.status(404).json({
          error: "Request not found",
        });
      }

      res.json(data);
    } catch (err) {
      console.error("LOAD SINGLE ERROR:", err);

      res.status(500).json({
        error: "Failed to load request",
      });
    }
  },
);

/* ================= CLIENT SUBMIT ================= */

router.post(
  "/payment/create-order",
  protect(["client"]),

  async (req, res) => {
    try {
      const order = await razorpayRequest("/orders", {
        method: "POST",
        body: JSON.stringify({
          amount: PAYMENT_AMOUNT_PAISE,
          currency: PAYMENT_CURRENCY,
          receipt: `n_${String(req.user.id).slice(0, 10)}_${Date.now()}`,
          notes: {
            user_id: String(req.user.id),
          },
        }),
      });

      res.json({
        orderId: order.id,
        amount: order.amount,
        currency: order.currency,
        keyId: process.env.RAZORPAY_KEY_ID,
      });
    } catch (err) {
      console.error("CREATE ORDER ERROR:", err);

      res.status(500).json({
        error:
          err instanceof Error
            ? `Unable to create payment order: ${err.message}`
            : "Unable to create payment order",
      });
    }
  },
);

router.post("/payment/webhook", async (req, res) => {
  try {
    const signature = req.headers["x-razorpay-signature"];
    const rawBody = req.rawBody;

    if (!signature || typeof signature !== "string" || !rawBody) {
      return res.status(400).json({
        error: "Invalid webhook signature headers/body",
      });
    }

    const isValid = verifyRazorpayWebhookSignature({
      rawBody,
      signature,
    });

    if (!isValid) {
      return res.status(400).json({
        error: "Invalid webhook signature",
      });
    }

    // Signature is verified. Add event-based persistence here when needed.
    const event = req.body?.event || "unknown";
    console.log("RAZORPAY WEBHOOK RECEIVED:", event);

    return res.json({ received: true });
  } catch (err) {
    console.error("RAZORPAY WEBHOOK ERROR:", err);
    return res.status(500).json({ error: "Webhook handling failed" });
  }
});

router.post(
  "/client/submit-test",
  protect(["client"]),

  async (req, res) => {
    try {
      if (process.env.ALLOW_TEST_SUBMIT !== "true") {
        return res.status(403).json({
          error: "Test submit is disabled",
        });
      }

      const {
        name,
        email,
        phone,
        documentType,
        aadhaar_url,
        photo_url,
        document_url,
      } = req.body;

      const user_id = req.user.id;

      const { error } = await supabase.from("notary_requests").insert([
        {
          user_id,
          name,
          email,
          phone,
          document_type: documentType,
          aadhaar_url,
          photo_url,
          document_url,
          status: "pending",
        },
      ]);

      if (error) throw error;

      res.json({ message: "Submitted (test mode)" });
    } catch (err) {
      console.error("TEST SUBMIT ERROR:", err);
      res.status(500).json({
        error: "Test submit failed",
      });
    }
  },
);

router.post(
  "/client/submit",
  protect(["client"]),

  async (req, res) => {
    try {
      const {
        name,
        email,
        phone,
        documentType,
        aadhaar_url,
        photo_url,
        document_url,
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature,
      } = req.body;

      const user_id = req.user.id;

      if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
        return res.status(400).json({
          error: "Payment details missing",
        });
      }

      const isValidSignature = verifyRazorpaySignature({
        orderId: razorpay_order_id,
        paymentId: razorpay_payment_id,
        signature: razorpay_signature,
      });

      if (!isValidSignature) {
        return res.status(400).json({
          error: "Payment signature verification failed",
        });
      }

      const payment = await razorpayRequest(`/payments/${razorpay_payment_id}`);
      if (
        payment.order_id !== razorpay_order_id ||
        payment.amount !== PAYMENT_AMOUNT_PAISE ||
        payment.currency !== PAYMENT_CURRENCY ||
        !["authorized", "captured"].includes(payment.status)
      ) {
        return res.status(400).json({
          error: "Payment verification failed",
        });
      }

      const { error } = await supabase.from("notary_requests").insert([
        {
          user_id,
          name,
          email,
          phone,
          document_type: documentType,
          aadhaar_url,
          photo_url,
          document_url,
          status: "pending",
        },
      ]);

      if (error) throw error;

      res.json({ message: "Submitted" });
    } catch (err) {
      console.error("SUBMIT ERROR:", err);

      res.status(500).json({
        error: "Submit failed",
      });
    }
  },
);

/* ================= Notary ================= */

// Notary - My Requests
router.get(
  "/notary/requests",
  protect(["notary"]),

  async (req, res) => {
    try {
      const notaryId = req.user.id;

      const { data, error } = await supabase
        .from("notary_requests")
        .select("*")
        .eq("notary_id", notaryId)
        .in("status", ["approved", "verified", "notary_rejected"])
        .order("created_at", { ascending: false });

      if (error) throw error;

      res.json(data);
    } catch (err) {
      res.status(500).json({ error: "Failed to load" });
    }
  },
);

router.get(
  "/notary/assets",
  protect(["notary"]),

  async (req, res) => {
    try {
      const notaryId = req.user.id;

      const { data: user, error: userError } = await supabase
        .from("users")
        .select("signature_url, stamp_url")
        .eq("id", notaryId)
        .single();

      if (userError) throw userError;

      let signatureSignedUrl = null;
      let stampSignedUrl = null;

      if (user?.signature_url) {
        const { data, error } = await supabase.storage
          .from("documents")
          .createSignedUrl(user.signature_url, 300);
        if (error) throw error;
        signatureSignedUrl = data.signedUrl;
      }

      if (user?.stamp_url) {
        const { data, error } = await supabase.storage
          .from("documents")
          .createSignedUrl(user.stamp_url, 300);
        if (error) throw error;
        stampSignedUrl = data.signedUrl;
      }

      res.json({
        signaturePath: user?.signature_url || null,
        stampPath: user?.stamp_url || null,
        signatureUrl: signatureSignedUrl,
        stampUrl: stampSignedUrl,
      });
    } catch (err) {
      console.error("NOTARY ASSETS ERROR:", err);

      res.status(500).json({
        error: "Failed to load assets",
      });
    }
  },
);

// Notary Verify
// ================= NOTARY VERIFY =================

router.post(
  "/notary/verify",
  protect(["notary"]),

  async (req, res) => {
    try {
      const { id, signaturePositions, stampPositions } = req.body;
      const notaryId = req.user.id;

      if (!id) {
        return res.status(400).json({
          error: "Missing request id",
        });
      }

      if (
        !Array.isArray(signaturePositions) ||
        !Array.isArray(stampPositions) ||
        signaturePositions.length === 0 ||
        stampPositions.length === 0
      ) {
        return res.status(400).json({
          error: "Missing signature/stamp placements",
        });
      }

      const { data: notary, error: notaryErr } = await supabase
        .from("users")
        .select("signature_url, stamp_url")
        .eq("id", notaryId)
        .single();

      if (notaryErr || !notary) {
        return res.status(400).json({
          error: "Notary profile incomplete",
        });
      }

      if (!notary.signature_url || !notary.stamp_url) {
        return res.status(400).json({
          error: "Upload signature and stamp first",
        });
      }

      const { data: requestData, error: requestErr } = await supabase
        .from("notary_requests")
        .select("id, document_url")
        .eq("id", id)
        .eq("notary_id", notaryId)
        .single();

      if (requestErr || !requestData) {
        return res.status(404).json({
          error: "Request not found",
        });
      }

      if (!requestData.document_url) {
        return res.status(400).json({
          error: "Document missing for request",
        });
      }

      const documentExt = imageExt(requestData.document_url);
      if (documentExt !== "pdf") {
        return res.status(400).json({
          error: "Only PDF documents can be stamped right now",
        });
      }

      const documentBytes = await fetchBytesFromSignedPath(requestData.document_url);
      const signatureBytes = await fetchBytesFromSignedPath(notary.signature_url);
      const stampBytes = await fetchBytesFromSignedPath(notary.stamp_url);

      const pdfDoc = await PDFDocument.load(documentBytes);
      const pages = pdfDoc.getPages();

      const signatureImage = await embedImageSafe(
        pdfDoc,
        signatureBytes,
        "signature",
      );
      const stampImage = await embedImageSafe(pdfDoc, stampBytes, "stamp");

      for (const pos of signaturePositions) {
          if (
            typeof pos?.x !== "number" ||
            typeof pos?.y !== "number" ||
            typeof pos?.page !== "number"
          ) {
          return res.status(400).json({
            error: "Invalid signature placement format",
          });
        }

        const pageIndex = Math.max(1, Math.floor(pos.page)) - 1;
        const page = pages[pageIndex];

        if (!page) {
          return res.status(400).json({
            error: `Invalid signature page: ${pos.page}`,
          });
        }

        const coords = toPdfCoords(page, pos);
          const drawSize = toPdfSize(coords, pos, { w: 24, h: 10 }, signatureImage);

        page.drawImage(signatureImage, {
          x: coords.x - drawSize.width / 2,
          y: coords.y - drawSize.height / 2,
          width: drawSize.width,
          height: drawSize.height,
        });
        }

      for (const pos of stampPositions) {
          if (
            typeof pos?.x !== "number" ||
            typeof pos?.y !== "number" ||
            typeof pos?.page !== "number"
          ) {
          return res.status(400).json({
            error: "Invalid stamp placement format",
          });
        }

        const pageIndex = Math.max(1, Math.floor(pos.page)) - 1;
        const page = pages[pageIndex];

        if (!page) {
          return res.status(400).json({
            error: `Invalid stamp page: ${pos.page}`,
          });
        }

        const coords = toPdfCoords(page, pos);
          const drawSize = toPdfSize(coords, pos, { w: 18, h: 18 }, stampImage);

        page.drawImage(stampImage, {
          x: coords.x - drawSize.width / 2,
          y: coords.y - drawSize.height / 2,
          width: drawSize.width,
          height: drawSize.height,
        });
        }

      const stampedPdfBytes = await pdfDoc.save();
      const stampedPath = `verified/${Date.now()}-request-${id}.pdf`;

      const { error: uploadErr } = await supabase.storage
        .from("documents")
        .upload(stampedPath, stampedPdfBytes, {
          contentType: "application/pdf",
        });

      if (uploadErr) throw uploadErr;

      const certificateId = "CERT-" + Date.now();

      const { error } = await supabase
        .from("notary_requests")
        .update({
          status: "verified",
          notary_status: "verified",
          certificate_id: certificateId,
          document_url: stampedPath,
          signature_url: notary.signature_url,
          stamp_url: notary.stamp_url,
          verified_at: new Date(),
        })
        .eq("id", id)
        .eq("notary_id", notaryId);

      if (error) throw error;

      res.json({
        message: "Verified successfully",
        certificateId,
      });
    } catch (err) {
      console.error("VERIFY ERROR:", err);

      res.status(500).json({
        error: "Verify failed",
      });
    }
  },
);
// Admin: Get all notaries
router.get(
  "/admin/notaries",
  protect(["admin"]),

  async (req, res) => {
    const { data, error } = await supabase
      .from("users")
      .select("id, name, email, notary_number")
      .eq("role", "notary")
      .order("notary_number");

    if (error) {
      return res.status(500).json({ error: "Failed" });
    }

    res.json(data);
  },
);
// ================= NOTARY REJECT =================

router.post(
  "/notary/reject",
  protect(["notary"]),

  async (req, res) => {
    try {
      const { requestId, message } = req.body;
      const notaryId = req.user.id;

      if (!requestId || !message) {
        return res.status(400).json({
          error: "Missing fields",
        });
      }

      // Only allow rejecting own assigned requests
      const { error } = await supabase
        .from("notary_requests")
        .update({
          status: "notary_rejected",
          admin_message: message,
          notary_id: null,
          notary_status: null,
          certificate_id: null,
          signature_url: null,
          stamp_url: null,
        })
        .eq("id", requestId)
        .eq("notary_id", notaryId);

      if (error) throw error;

      res.json({ message: "Rejected by notary" });
    } catch (err) {
      console.error("NOTARY REJECT ERROR:", err);

      res.status(500).json({
        error: "Reject failed",
      });
    }
  },
);

// Upload notary signature & stamp
router.post(
  "/notary/upload-assets",
  protect(["notary"]),
  upload.fields([
    { name: "signature", maxCount: 1 },
    { name: "stamp", maxCount: 1 },
  ]),

  async (req, res) => {
    try {
      const notaryId = req.user.id;
      const files = req.files || {};

      const hasSignature = Boolean(files.signature?.[0]);
      const hasStamp = Boolean(files.stamp?.[0]);

      if (!hasSignature && !hasStamp) {
        return res.status(400).json({
          error: "Select signature or stamp to upload",
        });
      }

      const { data: currentUser, error: currentUserErr } = await supabase
        .from("users")
        .select("signature_url, stamp_url")
        .eq("id", notaryId)
        .single();

      if (currentUserErr) throw currentUserErr;

      let signaturePath = currentUser?.signature_url || null;
      let stampPath = currentUser?.stamp_url || null;

      // Upload signature
      if (hasSignature) {
        const file = files.signature[0];

        const name = `signatures/${Date.now()}-${file.originalname}`;

        const { data, error } = await supabase.storage
          .from("documents")
          .upload(name, file.buffer, {
            contentType: file.mimetype,
          });

        if (error) throw error;

        signaturePath = data.path;
      }

      // Upload stamp
      if (hasStamp) {
        const file = files.stamp[0];

        const name = `stamps/${Date.now()}-${file.originalname}`;

        const { data, error } = await supabase.storage
          .from("documents")
          .upload(name, file.buffer, {
            contentType: file.mimetype,
          });

        if (error) throw error;

        stampPath = data.path;
      }

      // Save to user
      const { error: updateErr } = await supabase
        .from("users")
        .update({
          signature_url: signaturePath,
          stamp_url: stampPath,
        })
        .eq("id", notaryId);

      if (updateErr) throw updateErr;

      res.json({
        message: "Assets uploaded",
        signature: signaturePath,
        stamp: stampPath,
      });
    } catch (err) {
      console.error("UPLOAD ASSET ERROR:", err);

      res.status(500).json({
        error: "Upload failed",
      });
    }
  },
);


export default router;

