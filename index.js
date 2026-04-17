import dotenv from "dotenv";

dotenv.config();
console.log("DEBUG URL:", process.env.SUPABASE_URL);

import express from "express";
import cors from "cors";
import multer from "multer";
import routes from "./routes.js";



const app = express();

const allowedOrigins = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow server-to-server and tools without Origin header.
      if (!origin) return callback(null, true);
      if (!allowedOrigins.length || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  }),
);

app.use(
  express.json({
    verify: (req, _res, buf) => {
      if (req.originalUrl === "/api/payment/webhook") {
        req.rawBody = buf.toString();
      }
    },
  }),
);

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

console.log("SUPABASE:", process.env.SUPABASE_URL);
app.use("/api", routes);

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        error: "File too large. Maximum allowed size is 25MB.",
      });
    }

    return res.status(400).json({
      error: err.message || "Upload error",
    });
  }

  if (err) {
    console.error("UNHANDLED ERROR:", err);
    return res.status(500).json({
      error: "Internal server error",
    });
  }

  next();
});

const port = Number(process.env.PORT || 5000);
app.listen(port, () => {
  console.log(`Backend running on ${port}`);
});
