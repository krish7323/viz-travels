import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ObjectId } from "mongodb";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 5002;   // Fixed: 5001 is reserved for the packages server (server/index.js)

const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret_key";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(
  process.env.ADMIN_PASSWORD || "Admin@1234",
  10
);

app.use(cors({
  origin: [
    "http://localhost:5173",  // Main frontend
    "http://localhost:5174",  // Vendor panel (Home)
    "http://localhost:5175",  // Admin panel client
    "http://localhost:3000",
    "http://localhost:5002",
  ],
  credentials: true,
}));

app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));

let client;

async function connectDB() {
  try {
    client = new MongoClient(MONGODB_URI);
    await client.connect();
    console.log("✅ Connected to MongoDB");
  } catch (err) {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  }
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// AUTH
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Username and password required" });
  if (username !== ADMIN_USERNAME)
    return res.status(401).json({ error: "Invalid credentials" });
  const valid = bcrypt.compareSync(password, ADMIN_PASSWORD_HASH);
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign({ username, role: "admin" }, JWT_SECRET, { expiresIn: "8h" });
  res.json({ token, username, message: "Login successful" });
});

app.get("/api/auth/verify", authMiddleware, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// DATABASES
app.get("/api/databases", authMiddleware, async (req, res) => {
  try {
    const adminDb = client.db("admin");
    const result = await adminDb.command({ listDatabases: 1 });
    res.json({ databases: result.databases.map(d => ({ name: d.name, sizeOnDisk: d.sizeOnDisk })) });
  } catch {
    const dbName = new URL(MONGODB_URI).pathname.replace("/", "") || "TourTravels1";
    res.json({ databases: [{ name: dbName, sizeOnDisk: 0 }] });
  }
});

// COLLECTIONS
app.get("/api/collections/:dbName", authMiddleware, async (req, res) => {
  try {
    const targetDb = client.db(req.params.dbName);
    const collections = await targetDb.listCollections().toArray();
    const withCounts = await Promise.all(
      collections.map(async col => ({
        name: col.name,
        count: await targetDb.collection(col.name).countDocuments(),
      }))
    );
    res.json({ collections: withCounts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET DOCUMENTS
app.get("/api/data/:dbName/:collectionName", authMiddleware, async (req, res) => {
  try {
    const { dbName, collectionName } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const search = req.query.search || "";
    const skip = (page - 1) * limit;
    const collection = client.db(dbName).collection(collectionName);

    let query = {};
    if (search) {
      const sample = await collection.findOne();
      if (sample) {
        const stringKeys = Object.keys(sample).filter(k => typeof sample[k] === "string" && k !== "_id");
        if (stringKeys.length > 0) {
          query = { $or: stringKeys.map(k => ({ [k]: { $regex: search, $options: "i" } })) };
        }
      }
    }

    const [documents, total] = await Promise.all([
      collection.find(query).skip(skip).limit(limit).toArray(),
      collection.countDocuments(query),
    ]);

    res.json({
      documents: documents.map(serializeDoc),
      total,
      page,
      totalPages: Math.ceil(total / limit),
      limit,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET SINGLE
app.get("/api/data/:dbName/:collectionName/:id", authMiddleware, async (req, res) => {
  try {
    const { dbName, collectionName, id } = req.params;
    const doc = await client.db(dbName).collection(collectionName).findOne({ _id: new ObjectId(id) });
    if (!doc) return res.status(404).json({ error: "Document not found" });
    res.json({ document: serializeDoc(doc) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// CREATE
app.post("/api/data/:dbName/:collectionName", authMiddleware, async (req, res) => {
  try {
    const { dbName, collectionName } = req.params;
    const docToInsert = { ...req.body };
    delete docToInsert._id;
    const result = await client.db(dbName).collection(collectionName).insertOne(docToInsert);
    res.status(201).json({ message: "Document created", insertedId: result.insertedId.toString() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE
app.put("/api/data/:dbName/:collectionName/:id", authMiddleware, async (req, res) => {
  try {
    const { dbName, collectionName, id } = req.params;
    const update = { ...req.body };
    delete update._id;
    const result = await client.db(dbName).collection(collectionName).updateOne(
      { _id: new ObjectId(id) },
      { $set: update }
    );
    if (result.matchedCount === 0) return res.status(404).json({ error: "Document not found" });
    res.json({ message: "Document updated", modifiedCount: result.modifiedCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE ONE
app.delete("/api/data/:dbName/:collectionName/:id", authMiddleware, async (req, res) => {
  try {
    const { dbName, collectionName, id } = req.params;
    const result = await client.db(dbName).collection(collectionName).deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) return res.status(404).json({ error: "Document not found" });
    res.json({ message: "Document deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// BULK DELETE
app.delete("/api/data/:dbName/:collectionName", authMiddleware, async (req, res) => {
  try {
    const { dbName, collectionName } = req.params;
    const { ids } = req.body;
    if (!ids || !Array.isArray(ids)) return res.status(400).json({ error: "ids array required" });
    const result = await client.db(dbName).collection(collectionName).deleteMany({
      _id: { $in: ids.map(id => new ObjectId(id)) },
    });
    res.json({ message: `Deleted ${result.deletedCount} documents` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// STATS
app.get("/api/stats/:dbName/:collectionName", authMiddleware, async (req, res) => {
  try {
    const { dbName, collectionName } = req.params;
    const stats = await client.db(dbName).command({ collStats: collectionName });
    res.json({ count: stats.count, size: stats.size, avgObjSize: stats.avgObjSize, storageSize: stats.storageSize, nindexes: stats.nindexes });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serve frontend for all other routes
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

function serializeDoc(doc) {
  if (!doc) return doc;
  const result = {};
  for (const [key, value] of Object.entries(doc)) {
    if (value instanceof ObjectId) result[key] = value.toString();
    else if (Array.isArray(value)) result[key] = value.map(v => v instanceof ObjectId ? v.toString() : v);
    else if (value && typeof value === "object" && !(value instanceof Date) && value.constructor === Object) result[key] = serializeDoc(value);
    else result[key] = value;
  }
  return result;
}

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Admin Panel running at http://localhost:${PORT}`);
    console.log(`👤 Login: ${ADMIN_USERNAME} / ${process.env.ADMIN_PASSWORD || "Admin@1234"}`);
  });
});
