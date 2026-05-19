import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { z } from "zod";
import { pool } from "./db.js";
import { v4 as uuidv4 } from "uuid";

function generateTokens(user) {
  const accessToken = jwt.sign(user, process.env.SECRET_KEY, {
    expiresIn: "1h",
  });
  const refreshToken = jwt.sign(user, process.env.REFRESH_SECRET_KEY, {
    expiresIn: "15d",
  });
  return { accessToken, refreshToken };
}

export async function createUser(req, res) {
  const userSchema = z.object({
    username: z.string().min(3).max(20),
    email: z.string().email({ message: "Please enter a valid email address" }),
    password: z.string().min(6),
  });
  const validation = userSchema.safeParse(req.body);
  if (!validation.success)
    return res.json({
      message: "Invalid input",
      errors: validation.error.issues,
    });
  const { username, email, password } = validation.data;
  const hashedPassword = await bcrypt.hash(password, 12);
  const uid = uuidv4();
  try {
    const [result] = await pool.query(
      "INSERT INTO users (uid, username, email, password) VALUES (?, ?, ?, ?)",
      [uid, username, email, hashedPassword],
    );
    const user = { id: result.insertId, uid: uid, username, email };
    const { accessToken, refreshToken } = generateTokens(user);
    res.status(201).json({ accessToken, refreshToken });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function getUser(req, res) {
  if (req.params.id !== req.user.uid)
    return res.status(403).json({ error: "Forbidden" });
  try {
    const [result] = await pool.query(
      "SELECT id, username, email FROM users WHERE uid = ?",
      [req.params.id],
    );
    if (result.length === 0)
      return res.status(404).json({ message: "User not found" });
    res.json(result[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function updateUser(req, res) {
  if (req.params.id !== req.user.uid)
    return res.status(403).json({ error: "Forbidden" });
  const { username, email, password } = req.body;
  const id = req.params.id;
  try {
    let hashed = null;
    if (password) hashed = await bcrypt.hash(password, 12);
    const [result] = await pool.query(
      "UPDATE users SET username = COALESCE(?, username), email = COALESCE(?, email), password = COALESCE(?, password) WHERE uid = ?",
      [username ?? null, email ?? null, hashed ?? null, id],
    );
    if (result.affectedRows == 0)
      return res.status(404).json({ message: "User with given Id not found" });
    res.json({ message: "User updated" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function deleteUser(req, res) {
  if (req.params.id !== req.user.uid)
    return res.status(403).json({ error: "Forbidden" });
  const id = req.params.id;
  try {
    const [result] = await pool.query("DELETE FROM users WHERE uid = ?", [id]);
    if (result.affectedRows == 0)
      return res.status(404).json({ message: "User with given Id not found" });
    res.json({ message: "User deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function login(req, res) {
  const loginSchema = z.object({
    identifier: z.string().min(3), // username or email
    password: z.string().min(6),
  });
  const validation = loginSchema.safeParse(req.body);
  if (!validation.success)
    return res
      .status(400)
      .json({ message: "Invalid input", errors: validation.error.issues });
  const { identifier, password } = validation.data;
  try {
    const [rows] = await pool.query(
      "SELECT id, username, email, password FROM users WHERE username = ? OR email = ? LIMIT 1",
      [identifier, identifier],
    );
    if (rows.length === 0)
      return res.status(401).json({ message: "Invalid credentials" });
    const userRow = rows[0];
    const match = await bcrypt.compare(password, userRow.password);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });
    const user = {
      id: userRow.id,
      username: userRow.username,
      email: userRow.email,
    };
    const { accessToken, refreshToken } = generateTokens(user);
    res.json({ accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function refreshTokenHandler(req, res) {
  const { refreshToken: token } = req.body;
  if (!token) return res.status(400).json({ message: "Refresh token required" });
  try {
    const user = jwt.verify(token, process.env.REFRESH_SECRET_KEY);
    const { accessToken, refreshToken } = generateTokens(user);
    res.json({ accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(401).json({ message: "Invalid or expired refresh token" });
  }
}
