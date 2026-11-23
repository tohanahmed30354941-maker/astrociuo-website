
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
      !/^((server|user)_[1-8])$/.test(plan_id || "") ||
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
// Health Check
app.get("/api/health", (req, res) => {
  res.json({ status: "online" });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Astrociuos running on port ${PORT}`);
});
