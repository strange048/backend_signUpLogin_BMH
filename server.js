const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const cors = require("cors");

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Database
let db = null;
const dbPath = path.join(__dirname, "bookhall.db");

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    const PORT = process.env.PORT || 5000;

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });

  } catch (error) {
    console.log(`Database Error: ${error.message}`);
    process.exit(1);
  }
};

initializeDbAndServer();


// 🔐 JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({ message: "Invalid JWT Token" });
  }

  const jwtToken = authHeader.split(" ")[1];

  jwt.verify(jwtToken, "MY_SECRET_KEY", (error, payload) => {
    if (error) {
      return res.status(401).json({ message: "Invalid JWT Token" });
    }
    req.username = payload.username;
    next();
  });
};


// 📝 Register API
app.post("/user", async (req, res) => {
  const { username, password } = req.body;

  try {
    const userQuery = `SELECT * FROM user WHERE username = ?`;
    const dbUser = await db.get(userQuery, [username]);

    if (dbUser) {
      return res.status(400).json({ message: "User Already Exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const insertQuery = `
      INSERT INTO user (username, password)
      VALUES (?, ?)
    `;

    await db.run(insertQuery, [username, hashedPassword]);

    res.status(201).json({ message: "User Registered Successfully" });

  } catch (error) {
    res.status(500).json({ message: "Error in Register API" });
  }
});


// 🔑 Login API
app.post("/log", async (req, res) => {
  const { username, password } = req.body;

  try {
    const userQuery = `SELECT * FROM user WHERE username = ?`;
    const dbUser = await db.get(userQuery, [username]);

    if (!dbUser) {
      return res.status(400).json({ message: "Invalid User" });
    }

    const isPasswordMatched = await bcrypt.compare(
      password,
      dbUser.password
    );

    if (!isPasswordMatched) {
      return res.status(400).json({ message: "Invalid Password" });
    }

    const payload = { username: username };
    const jwtToken = jwt.sign(payload, "MY_SECRET_KEY");

    res.json({ jwt_token: jwtToken });

  } catch (error) {
    res.status(500).json({ message: "Error in Login API" });
  }
});


// 🏠 Test Route
app.get("/", (req, res) => {
  res.send("Backend is running successfully 🚀");
});
