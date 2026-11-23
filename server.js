
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const app = express();

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

app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body;

  const correctUsername = process.env.ADMIN_USERNAME;
  const correctPassword = process.env.ADMIN_PASSWORD;

  if (!correctUsername || !correctPassword) {
    return res.status(500).json({ error: "Admin login is not configured" });
  }

  if (
    username !== correctUsername ||
    password !== correctPassword
  ) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  req.session.isAdmin = true;
  res.json({ success: true, message: "Login successful" });
});

app.get("/api/admin/check", requireAdmin, (req, res) => {
  res.json({ loggedIn: true });
});

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "online" });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Astrociuos running on port ${PORT}`);
});
