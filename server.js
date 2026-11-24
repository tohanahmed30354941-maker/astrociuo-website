
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
      ? `https://cdn.discordapp.com/icons/${guild.id}/${guild.icon}.png`
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
// Health Check
app.get("/api/health", (req, res) => {
  res.json({ status: "online" });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Astrociuos running on port ${PORT}`);
});
