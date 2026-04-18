const { onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const express = require("express");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const bodyParser = require("body-parser");

admin.initializeApp();
const db = admin.firestore();

const app = express();
app.use(cors({ origin: true }));
app.use(bodyParser.json());

// Register
app.post("/register", async (req, res) => {
  const { email, password, defaultData } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Missing email or password" });

  const userId = uuidv4();
  const sessionToken = uuidv4();
  const lowerEmail = email.toLowerCase();

  try {
    const userRef = db.collection("users").doc(userId);
    const emailCheck = await db.collection("users").where("email", "==", lowerEmail).get();
    
    if (!emailCheck.empty) {
      return res.status(400).json({ error: "Email already exists" });
    }

    await userRef.set({
      id: userId,
      email: lowerEmail,
      password: password, // Note: In a production app, you should hash passwords
      data: defaultData || {}
    });

    await db.collection("sessions").doc(sessionToken).set({
      session_id: sessionToken,
      user_id: userId
    });

    res.json({ token: sessionToken, data: defaultData });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Missing email or password" });

  try {
    const userSnapshot = await db.collection("users")
      .where("email", "==", email.toLowerCase())
      .where("password", "==", password)
      .limit(1)
      .get();

    if (userSnapshot.empty) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = userSnapshot.docs[0].data();
    const sessionToken = uuidv4();

    await db.collection("sessions").doc(sessionToken).set({
      session_id: sessionToken,
      user_id: user.id
    });

    res.json({ token: sessionToken, data: user.data });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Auth Middleware
async function auth(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const sessionDoc = await db.collection("sessions").doc(token).get();
    if (!sessionDoc.exists) {
      return res.status(401).json({ error: "Invalid token" });
    }
    req.userId = sessionDoc.data().user_id;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
}

// Me
app.get("/me", auth, async (req, res) => {
  try {
    const userDoc = await db.collection("users").doc(req.userId).get();
    if (!userDoc.exists) return res.status(404).json({ error: "User not found" });
    res.json({ data: userDoc.data().data });
  } catch (err) {
    res.status(500).json({ error: "Database error" });
  }
});

// Sync
app.post("/sync", auth, async (req, res) => {
  const { data } = req.body;
  try {
    await db.collection("users").doc(req.userId).update({ data });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Save failed" });
  }
});

exports.api = onRequest({ region: "us-central1" }, app);
