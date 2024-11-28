const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();

// Middleware
app.use(express.json()); // For parsing JSON requests
app.use(cors()); // Allow cross-origin requests
app.use(express.static("public")); // Serve static files (e.g., login.html)

// Connect to MySQL
const db = mysql.createConnection({
    host: "localhost",
    user: "root", 
    password: "Ragini@2910", // MySQL password
    database: "rbac_system", // Database name
});

db.connect((err) => {
    if (err) {
        console.error("Database connection failed:", err.stack);
        return;
    }
    console.log("Connected to the database.");
});

// Serve login page by default
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/login.html");  // Serve the login page
});

// Register Route (POST)
app.post("/register", async (req, res) => {
    const { username, password, roleName } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.query("SELECT id FROM roles WHERE roleName = ?", [roleName], (err, result) => {
            if (err) return res.status(500).send("Database error");
            if (result.length === 0) return res.status(400).send("Role not found");

            const roleId = result[0].id;
            db.query("INSERT INTO users (username, password, role_id) VALUES (?, ?, ?)", 
                [username, hashedPassword, roleId], 
                (err) => {
                    if (err) return res.status(500).send("Error registering user");
                    res.status(201).send("User registered successfully");
                }
            );
        });
    } catch (error) {
        console.error("Error during registration:", error);
        res.status(500).send("An error occurred during registration.");
    }
});

// Login Route (POST)
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.query("SELECT * FROM users WHERE username = ?", [username], async (err, result) => {
        if (err) return res.status(500).send("Database error");
        if (result.length === 0) return res.status(400).send({ message: "Invalid username or password" });

        const user = result[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) return res.status(400).send({ message: "Invalid username or password" });

        db.query("SELECT roleName FROM roles WHERE id = ?", [user.role_id], (err, roleResult) => {
            if (err) return res.status(500).send("Error fetching role");

            const roleName = roleResult[0].roleName;

            res.status(200).json({
                message: "Login successful",
                role: roleName,
            });
        });
    });
});

// Middleware to verify JWT token (optional if you're using JWT for secure APIs)
const authenticateToken = (req, res, next) => {
    const token = req.headers["authorization"];
    if (!token) return res.status(403).send("Token required");

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send("Invalid token");
        req.user = user;
        next();
    });
};

// Start server
const port = 5000;
app.listen(port, () => {
    console.log(`Server running on http://localhost:5000`);
});
