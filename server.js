const express = require("express");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const dbPath = path.join(__dirname, "database.db");

let db = null;

const initializeDbServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
      )
    `);
    await db.exec(`
      CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    const PORT = process.env.PORT || 3005;
    app.listen(PORT, () => {
      console.log(`Server starts at http://localhost:${PORT}`);
    });
  } catch (e) {
    console.error('Error initializing database server:', e.message);
  }
};
initializeDbServer();

const SECRET_KEY = process.env.JWT_SECRET || "your_jwt_secret";

// User Registration
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    await db.run(
      `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
      [username, email, hashedPassword]
    );
    res.status(201).send('User registered successfully');
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// User Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await db.get(`SELECT * FROM users WHERE email = ?`, [email]);
    if (!user) {
      return res.status(404).send('User not found');
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send('Invalid credentials');
    }
    const token = jwt.sign({ userId: user.id }, SECRET_KEY);
    res.send({ token });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Middleware to authenticate the token
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(401).send('Access denied');
  }
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid token');
    }
    req.user = user;
    next();
  });
};

// Create Task
app.post("/tasks", authenticateToken, async (req, res) => {
  const { title, description } = req.body;
  try {
    await db.run(
      `INSERT INTO tasks (title, description) VALUES (?, ?)`,
      [title, description]
    );
    res.status(201).send('Task created successfully');
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Get All Tasks
app.get("/tasks", authenticateToken, async (req, res) => {
  try {
    const tasks = await db.all(`SELECT * FROM tasks`);
    res.send(tasks);
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Update Task
app.put("/tasks/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { title, description } = req.body;
  try {
    await db.run(
      `UPDATE tasks SET title = ?, description = ? WHERE id = ?`,
      [title, description, id]
    );
    res.send('Task updated successfully');
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Delete Task
app.delete("/tasks/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    await db.run(`DELETE FROM tasks WHERE id = ?`, [id]);
    res.send('Task deleted successfully');
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});
