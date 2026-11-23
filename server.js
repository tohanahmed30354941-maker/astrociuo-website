
const express = require("express");
const session = require("express-session");

const app = express();

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
app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;

  if (
    !process.env.ADMIN_USERNAME ||
    !process.env.ADMIN_PASSWORD
  ) {
    return res.status(500).json({ error: "Admin login is not configured" });
  }

  if (
    username !== process.env.ADMIN_USERNAME ||
    password !== process.env.ADMIN_PASSWORD
  ) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  req.session.isAdmin = true;
  res.json({ success: true, message: "Login successful" });
});

// Check Admin Login
app.get("/api/admin/check", requireAdmin, (req, res) => {
  res.json({ loggedIn: true });
});

// Logout
app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// Get all Premium Plans
app.get("/api/plans", async (req, res) => {
  try {
    const response = await supabaseRequest(
      "plan_prices?select=id,plan_type,months,price_bdt&order=months.asc"
    );

    if (!response.ok) {
      throw new Error(await response.text());
    }

    const plans = await response.json();
    res.json(plans);
  } catch (error) {
    console.error("Plans error:", error.message);
    res.status(500).json({ error: "Could not load plans" });
  }
});

// Update a Premium Plan price (Admin only)
app.put("/api/admin/plans/:id", requireAdmin, async (req, res) => {
  try {
    const { price_bdt } = req.body;
    const id = req.params.id;

    if (
      !/^(server|user)_[1-8]$/.test(id) ||
      !Number.isInteger(price_bdt) ||
      price_bdt < 0
    ) {
      return res.status(400).json({ error: "Invalid plan or price" });
    }

    const response = await supabaseRequest(
      `plan_prices?id=eq.${encodeURIComponent(id)}`,
      {
        method: "PATCH",
        headers: {
          "Prefer": "return=representation"
        },
        body: JSON.stringify({ price_bdt })
      }
    );

    if (!response.ok) {
      throw new Error(await response.text());
    }

    const updated = await response.json();

    if (!updated.length) {
      return res.status(404).json({ error: "Plan not found" });
    }

    res.json({ success: true, plan: updated[0] });
  } catch (error) {
    console.error("Update error:", error.message);
    res.status(500).json({ error: "Could not update plan price" });
  }
});

// Health Check
app.get("/api/health", (req, res) => {
  res.json({ status: "online" });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Astrociuos running on port ${PORT}`);
});
