
const express = require("express");
const session = require("express-session");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const app = express();
const otpStore = new Map();

const mailTransporter = nodemailer.createTransport({
  
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 465),
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});
// Test Gmail SMTP Connection
mailTransporter.verify()
  .then(() => console.log("GMAIL SMTP CONNECTED SUCCESSFULLY"))
  .catch(error => console.error("GMAIL SMTP ERROR:", error.message));
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    const allowed = [
      "video/mp4",
      "video/webm",
      "video/quicktime"
    ];

    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Only MP4, WebM and MOV videos are allowed"));
    }
  }
});
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 24 * 60 * 60 * 1000
  }
}));

const requireAdmin = (req, res, next) => {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  res.status(401).json({ error: "Please login first" });
};
const requireSuperAdmin = (req, res, next) => {
  if (
    req.session &&
    req.session.isAdmin &&
    req.session.isSuperAdmin === true
  ) {
    return next();
  }

  return res.status(403).json({
    error: "Super Admin access required"
  });
};
const supabaseRequest = async (path, options = {}) => {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    throw new Error("Supabase environment variables are missing");
  }

  return fetch(`${url}/rest/v1/${path}`, {
    ...options,
    headers: {
      "apikey": key,
      "Authorization": `Bearer ${key}`,
      "Content-Type": "application/json",
      ...options.headers
    }
  });
};
// Admin Login
app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: "Username and password required"
      });
    }

    // Super Admin Login
    if (
      username === process.env.ADMIN_USERNAME &&
      password === process.env.ADMIN_PASSWORD
    ) {
      req.session.isAdmin = true;
      req.session.isSuperAdmin = true;
      req.session.adminUsername = username;

      return res.json({
        success: true,
        message: "Super Admin login successful"
      });
    }

    // Other Admin Login
    const response = await supabaseRequest(
      `admin_accounts?username=eq.${encodeURIComponent(username)}&select=username,password_hash,is_active`
    );

    if (!response.ok) {
      throw new Error(await response.text());
    }

    const accounts = await response.json();
    const admin = accounts[0];

    if (
      !admin ||
      !admin.is_active ||
      !(await bcrypt.compare(password, admin.password_hash))
    ) {
      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    req.session.isAdmin = true;
    req.session.isSuperAdmin = false;
    req.session.adminUsername = admin.username;

    res.json({
      success: true,
      message: "Admin login successful"
    });

  } catch (error) {
    console.error("Admin login error:", error.message);
    res.status(500).json({ error: "Login failed" });
  }
});
// Check Admin Login
app.get("/api/admin/check", requireAdmin, (req, res) => {
  res.json({
    loggedIn: true,
    isSuperAdmin: req.session.isSuperAdmin === true,
    username: req.session.adminUsername
  });
});
// Logout
app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});
// Forgot Password: Send OTP
app.post("/api/admin/forgot-password", async (req, res) => {
  const genericMessage = {
    success: true,
    message: "If an Admin account exists, an OTP has been sent."
  };

  try {
    const email = String(req.body.email || "").trim().toLowerCase();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.json(genericMessage);
    }

    const response = await supabaseRequest(
      `admin_accounts?email=eq.${encodeURIComponent(email)}&select=id,email,is_active`
    );

    if (!response.ok) throw new Error(await response.text());

    const accounts = await response.json();
    const admin = accounts.find(a => a.is_active);

    if (!admin) return res.json(genericMessage);

    const previous = otpStore.get(email);

    if (previous && Date.now() - previous.lastSentAt < 60000) {
      return res.json(genericMessage);
    }

    const otp = crypto.randomInt(100000, 1000000).toString();
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

    otpStore.set(email, {
      adminId: admin.id,
      otpHash,
      expiresAt: Date.now() + 5 * 60 * 1000,
      attempts: 0,
      lastSentAt: Date.now()
    });

    try {
      await mailTransporter.sendMail({
        from: process.env.SMTP_USER,
        to: admin.email,
        subject: "Astrociuos Admin Password Reset OTP",
        text: `Your password reset OTP is ${otp}. It expires in 5 minutes. Do not share this code.`
      });
    } catch (mailError) {
      otpStore.delete(email);
      throw mailError;
    }

    return res.json(genericMessage);

  } catch (error) {
    console.error("Forgot Password error:", error.message);
    return res.status(500).json({
      error: "Could not process password reset"
    });
  }
});
// Reset Admin Password: Verify OTP
app.post("/api/admin/reset-password", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const otp = String(req.body.otp || "");
    const newPassword = String(req.body.newPassword || "");

    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      !/^\d{6}$/.test(otp) ||
      newPassword.length < 8 ||
      newPassword.length > 100
    ) {
      return res.status(400).json({
        error: "Invalid email, OTP or password"
      });
    }

    const record = otpStore.get(email);

    if (!record || Date.now() > record.expiresAt) {
      otpStore.delete(email);
      return res.status(400).json({ error: "OTP expired or invalid" });
    }

    if (record.attempts >= 5) {
      otpStore.delete(email);
      return res.status(429).json({ error: "Too many attempts" });
    }

    const submittedHash = crypto.createHash("sha256").update(otp).digest("hex");

    const valid = crypto.timingSafeEqual(
      Buffer.from(record.otpHash, "hex"),
      Buffer.from(submittedHash, "hex")
    );

    if (!valid) {
      record.attempts++;

      if (record.attempts >= 5) {
        otpStore.delete(email);
      }

      return res.status(400).json({ error: "Invalid OTP" });
    }

    const password_hash = await bcrypt.hash(newPassword, 12);

    const response = await supabaseRequest(
      `admin_accounts?id=eq.${encodeURIComponent(record.adminId)}`,
      {
        method: "PATCH",
        headers: { "Prefer": "return=minimal" },
        body: JSON.stringify({ password_hash })
      }
    );

    if (!response.ok) throw new Error(await response.text());

    otpStore.delete(email);

    return res.json({
      success: true,
      message: "Password reset successful. Please login again."
    });

  } catch (error) {
    console.error("Reset Password error:", error.message);
    return res.status(500).json({ error: "Password reset failed" });
  }
});
// Super Admin: Create New Admin
app.post("/api/admin/accounts", requireSuperAdmin, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (
      !username ||
      !/^[A-Za-z0-9_-]{3,30}$/.test(username) ||
      !email ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      !password ||
      password.length < 8 ||
      password.length > 100
    ) {
      return res.status(400).json({
        error: "Invalid username, email or password"
      });
    }

    const check = await supabaseRequest(
      `admin_accounts?username=eq.${encodeURIComponent(username)}&select=id`
    );

    if (!check.ok) throw new Error(await check.text());

    if ((await check.json()).length > 0) {
      return res.status(409).json({
        error: "Username already exists"
      });
    }

    const emailCheck = await supabaseRequest(
      `admin_accounts?email=ilike.${encodeURIComponent(email)}&select=id`
    );

    if (!emailCheck.ok) throw new Error(await emailCheck.text());

    if ((await emailCheck.json()).length > 0) {
      return res.status(409).json({
        error: "Email already exists"
      });
    }

    const password_hash = await bcrypt.hash(password, 12);

    const response = await supabaseRequest("admin_accounts", {
      method: "POST",
      headers: {
        "Prefer": "return=minimal"
      },
      body: JSON.stringify({
        username,
        email: email.toLowerCase(),
        password_hash,
        is_active: true
      })
    });

    if (!response.ok) throw new Error(await response.text());

    res.json({
      success: true,
      message: "New Admin created successfully"
    });

  } catch (error) {
    console.error("Create Admin error:", error.message);
    res.status(500).json({
      error: "Could not create Admin"
    });
  }
});
// Super Admin: List Admin Accounts
app.get("/api/admin/accounts", requireSuperAdmin, async (req, res) => {
  try {
    const response = await supabaseRequest(
      "admin_accounts?select=id,username,email,created_at,is_active&order=id.asc"
    );

    if (!response.ok) throw new Error(await response.text());

    res.json(await response.json());
  } catch (error) {
    console.error("List Admins error:", error.message);
    res.status(500).json({ error: "Could not load Admin accounts" });
  }
});
// Super Admin: Delete Admin Account
app.delete("/api/admin/accounts/:id", requireSuperAdmin, async (req, res) => {
  try {
    const id = req.params.id;

    if (!/^\d+$/.test(id)) {
      return res.status(400).json({ error: "Invalid Admin ID" });
    }

    const check = await supabaseRequest(
      `admin_accounts?id=eq.${id}&select=username`
    );

    if (!check.ok) throw new Error(await check.text());

    const accounts = await check.json();
    const admin = accounts[0];

    if (!admin) {
      return res.status(404).json({ error: "Admin not found" });
    }

    if (
      admin.username.toLowerCase() === "tohanadmin" ||
      admin.username === process.env.ADMIN_USERNAME
    ) {
      return res.status(403).json({
        error: "Super Admin cannot be deleted"
      });
    }

    const response = await supabaseRequest(
      `admin_accounts?id=eq.${id}`,
      { method: "DELETE" }
    );

    if (!response.ok) throw new Error(await response.text());

    res.json({
      success: true,
      message: "Admin deleted successfully"
    });

  } catch (error) {
    console.error("Delete Admin error:", error.message);
    res.status(500).json({
      error: "Could not delete Admin"
    });
  }
});

// Get all Premium Plans
app.get("/api/plans", async (req, res) => {
  try {
    const response = await supabaseRequest(
      "plan_prices?select=id,plan_type,months,price_bdt&order=months.asc"
    );

    if (!response.ok) throw new Error(await response.text());

    res.json(await response.json());
  } catch (error) {
    console.error("Plans error:", error.message);
    res.status(500).json({ error: "Could not load plans" });
  }
});

// Admin: Add New Plan
app.post("/api/admin/plans", requireAdmin, async (req, res) => {
  try {
    const { plan_type, months, price_bdt } = req.body;

    if (
      !["Server Premium", "No Prefix User"].includes(plan_type) ||
      !Number.isInteger(months) || months < 1 || months > 120 ||
      !Number.isInteger(price_bdt) || price_bdt < 0
    ) {
      return res.status(400).json({ error: "Invalid plan information" });
    }

    const prefix = plan_type === "Server Premium" ? "server" : "user";
    const id = `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    const response = await supabaseRequest("plan_prices", {
      method: "POST",
      headers: { "Prefer": "return=representation" },
      body: JSON.stringify({ id, plan_type, months, price_bdt })
    });

    if (!response.ok) throw new Error(await response.text());

    res.json({ success: true, plan: (await response.json())[0] });
  } catch (error) {
    console.error("Add plan error:", error.message);
    res.status(500).json({ error: "Could not add plan" });
  }
});

// Admin: Update Plan
app.put("/api/admin/plans/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { plan_type, months, price_bdt } = req.body;

    if (
      !/^(server|user)_[A-Za-z0-9_-]{1,100}$/.test(id) ||
      !["Server Premium", "No Prefix User"].includes(plan_type) ||
      !Number.isInteger(months) || months < 1 || months > 120 ||
      !Number.isInteger(price_bdt) || price_bdt < 0
    ) {
      return res.status(400).json({ error: "Invalid plan information" });
    }

    const response = await supabaseRequest(
      `plan_prices?id=eq.${encodeURIComponent(id)}`,
      {
        method: "PATCH",
        headers: { "Prefer": "return=representation" },
        body: JSON.stringify({ plan_type, months, price_bdt })
      }
    );

    if (!response.ok) throw new Error(await response.text());

    const updated = await response.json();

    if (!updated.length) {
      return res.status(404).json({ error: "Plan not found" });
    }

    res.json({ success: true, plan: updated[0] });
  } catch (error) {
    console.error("Update plan error:", error.message);
    res.status(500).json({ error: "Could not update plan" });
  }
});

// Admin: Delete Plan
app.delete("/api/admin/plans/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;

    if (!/^(server|user)_[A-Za-z0-9_-]{1,100}$/.test(id)) {
      return res.status(400).json({ error: "Invalid plan ID" });
    }

    const response = await supabaseRequest(
      `plan_prices?id=eq.${encodeURIComponent(id)}`,
      {
        method: "DELETE",
        headers: { "Prefer": "return=representation" }
      }
    );

    if (!response.ok) throw new Error(await response.text());

    const deleted = await response.json();

    if (!deleted.length) {
      return res.status(404).json({ error: "Plan not found" });
    }

    res.json({ success: true });
  } catch (error) {
    console.error("Delete plan error:", error.message);
    res.status(500).json({ error: "Could not delete plan" });
  }
});

// Customer Submit Order
app.post("/api/orders", async (req, res) => {
  try {
    const {
      plan_id,
      discord_user_id,
      payment_method,
      transaction_id
    } = req.body;

    if (
      !/^(server|user)_[A-Za-z0-9_-]{1,100}$/.test(plan_id || "") ||
      !/^\d{17,20}$/.test(discord_user_id || "") ||
      !["bKash", "Nagad", "LTC", "Bybit", "Binance"].includes(payment_method) ||
      !transaction_id ||
      transaction_id.length > 100
    ) {
      return res.status(400).json({ error: "Invalid order information" });
    }

    const planResponse = await supabaseRequest(
      `plan_prices?id=eq.${encodeURIComponent(plan_id)}&select=id,plan_type,months,price_bdt`
    );

    if (!planResponse.ok) throw new Error(await planResponse.text());

    const plans = await planResponse.json();

    if (!plans.length) {
      return res.status(404).json({ error: "Plan not found" });
    }

    const plan = plans[0];

    const response = await supabaseRequest("orders", {
      method: "POST",
      headers: { "Prefer": "return=representation" },
      body: JSON.stringify({
        plan_id: plan.id,
        plan_type: plan.plan_type,
        months: plan.months,
        price_bdt: plan.price_bdt,
        discord_user_id,
        payment_method,
        transaction_id,
        status: "pending"
      })
    });

    if (!response.ok) throw new Error(await response.text());

    const order = await response.json();
    res.json({ success: true, order: order[0] });

  } catch (error) {
    console.error("Order error:", error.message);
    res.status(500).json({ error: "Could not submit order" });
  }
});

// Admin View Orders
app.get("/api/admin/orders", requireAdmin, async (req, res) => {
  try {
    const response = await supabaseRequest(
      "orders?select=*&order=created_at.desc"
    );

    if (!response.ok) throw new Error(await response.text());

    res.json(await response.json());

  } catch (error) {
    console.error("Orders error:", error.message);
    res.status(500).json({ error: "Could not load orders" });
  }
});

// Admin Approve or Reject Order
app.patch("/api/admin/orders/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { status } = req.body;

    if (!Number.isInteger(id) || id < 1 ||
        !["approved", "rejected"].includes(status)) {
      return res.status(400).json({ error: "Invalid order update" });
    }

    const response = await supabaseRequest(
      `orders?id=eq.${id}`,
      {
        method: "PATCH",
        headers: { "Prefer": "return=representation" },
        body: JSON.stringify({ status })
      }
    );

    if (!response.ok) throw new Error(await response.text());

    const updated = await response.json();

    if (!updated.length) {
      return res.status(404).json({ error: "Order not found" });
    }

    res.json({ success: true, order: updated[0] });

  } catch (error) {
    console.error("Order update error:", error.message);
    res.status(500).json({ error: "Could not update order" });
  }
});

 // Public: Get Enabled Payment Methods
app.get("/api/payment-methods", async (req, res) => {
  try {
    const response = await supabaseRequest(
      "payment_methods?select=id,name,details,enabled&enabled=eq.true&order=name.asc"
    );
    if (!response.ok) throw new Error(await response.text());
    res.json(await response.json());
  } catch (error) {
    console.error("Payment methods error:", error.message);
    res.status(500).json({ error: "Could not load payment methods" });
  }
});

// Admin: Get All Payment Methods
app.get("/api/admin/payment-methods", requireAdmin, async (req, res) => {
  try {
    const response = await supabaseRequest(
      "payment_methods?select=*&order=name.asc"
    );
    if (!response.ok) throw new Error(await response.text());
    res.json(await response.json());
  } catch (error) {
    console.error("Admin payment methods error:", error.message);
    res.status(500).json({ error: "Could not load payment settings" });
  }
});

// Admin: Update Payment Settings
app.patch("/api/admin/payment-methods/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { details, enabled } = req.body;

    if (
      typeof details !== "string" ||
      details.length > 500 ||
      typeof enabled !== "boolean"
    ) {
      return res.status(400).json({ error: "Invalid payment settings" });
    }

    const response = await supabaseRequest(
      `payment_methods?id=eq.${encodeURIComponent(id)}`,
      {
        method: "PATCH",
        headers: { "Prefer": "return=representation" },
        body: JSON.stringify({
          details,
          enabled,
          updated_at: new Date().toISOString()
        })
      }
    );

    if (!response.ok) throw new Error(await response.text());

    const updated = await response.json();

    if (!updated.length) {
      return res.status(404).json({ error: "Payment method not found" });
    }

    res.json({ success: true, payment_method: updated[0] });
  } catch (error) {
    console.error("Payment update error:", error.message);
    res.status(500).json({ error: "Could not update payment settings" });
  }
});
// Trusted Servers API

async function getTrustedServerInfo(server) {
  const response = await fetch(
    `https://discord.com/api/v10/invites/${encodeURIComponent(server.invite_code)}?with_counts=true`
  );

  if (!response.ok) {
    return null;
  }

  const data = await response.json();
  const guild = data.guild;
if (!guild) return null;
  return {
    id: server.id,
    name: guild.name,
    invite_url: server.invite_url,
    icon: guild.icon
  ? `https://cdn.discordapp.com/icons/${guild.id}/${guild.icon}.${guild.icon.startsWith("a_") ? "gif" : "png"}`
  : null,
    banner: guild.banner
  ? `https://cdn.discordapp.com/banners/${guild.id}/${guild.banner}.${guild.banner.startsWith("a_") ? "gif" : "png"}`
  : null,
    members: data.approximate_member_count ?? null,
    online: data.approximate_presence_count ?? null
  };
}

app.get("/api/trusted-servers", async (req, res) => {
  try {
    const response = await supabaseRequest(
      "trusted_servers?select=*&order=id.desc"
    );

    if (!response.ok) throw new Error(await response.text());

    const servers = await response.json();
    const results = await Promise.all(
      servers.map(getTrustedServerInfo)
    );

    res.json(results.filter(Boolean));
  } catch (error) {
    console.error("Trusted servers error:", error.message);
    res.status(500).json({ error: "Could not load servers" });
  }
});

app.post("/api/admin/trusted-servers", requireAdmin, async (req, res) => {
  try {
    const inviteUrl = (req.body.invite_url || "").trim();
    const match = inviteUrl.match(
      /^(?:https?:\/\/)?(?:www\.)?(?:discord\.gg\/|discord\.com\/invite\/)([a-zA-Z0-9-]+)\/?$/i
    );

    if (!match) {
      return res.status(400).json({ error: "Invalid Discord invite link" });
    }

    const inviteCode = match[1];

    const check = await fetch(
      `https://discord.com/api/v10/invites/${encodeURIComponent(inviteCode)}?with_counts=true`
    );

    if (!check.ok) {
      return res.status(400).json({ error: "Discord invite is invalid or unavailable" });
    }

    const response = await supabaseRequest("trusted_servers", {
      method: "POST",
      headers: { "Prefer": "return=representation" },
      body: JSON.stringify({
        invite_url: `https://discord.gg/${inviteCode}`,
        invite_code: inviteCode
      })
    });

    if (!response.ok) throw new Error(await response.text());

    res.json({ success: true, server: (await response.json())[0] });
  } catch (error) {
    console.error("Add trusted server error:", error.message);
    res.status(500).json({ error: "Could not add server" });
  }
});

app.delete("/api/admin/trusted-servers/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ error: "Invalid server ID" });
    }

    const response = await supabaseRequest(
      `trusted_servers?id=eq.${id}`,
      { method: "DELETE" }
    );

    if (!response.ok) throw new Error(await response.text());

    res.json({ success: true });
  } catch (error) {
    console.error("Delete trusted server error:", error.message);
    res.status(500).json({ error: "Could not delete server" });
  }
});

// Get Current Background Video
app.get("/api/background-video", (req, res) => {
  const url = `${process.env.SUPABASE_URL}/storage/v1/object/public/site-background/background/current`;
  res.json({ videoUrl: url });
});

// Admin Upload Background Video
app.post(
  "/api/admin/background-video",
  requireAdmin,
  (req, res, next) => {
    upload.single("video")(req, res, (error) => {
      if (error) {
        return res.status(400).json({ error: error.message });
      }
      next();
    });
  },
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "Please select a video" });
      }

      const url = `${process.env.SUPABASE_URL}/storage/v1/object/site-background/background/current`;

      const response = await fetch(url, {
        method: "POST",
        headers: {
          apikey: process.env.SUPABASE_SECRET_KEY,
          Authorization: `Bearer ${process.env.SUPABASE_SECRET_KEY}`,
          "Content-Type": req.file.mimetype,
          "x-upsert": "true"
        },
        body: req.file.buffer
      });

      if (!response.ok) {
        throw new Error(await response.text());
      }

      res.json({ success: true, message: "Background video uploaded" });
    } catch (error) {
      console.error("Background video error:", error.message);
      res.status(500).json({ error: "Video upload failed" });
    }
  }
);

app.get("/api/health", (req, res) => {
  res.json({ status: "online" });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Astrociuos running on port ${PORT}`);
});
