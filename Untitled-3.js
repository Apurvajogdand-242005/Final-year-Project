const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const bodyParser=require("body-parser");

const app = express();
const PORT = 5000;

// Middleware
app.use(bodyParser.urlencoded({extended:true}));
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  session({
    secret: "secretKey",
    resave: false,
    saveUninitialized: true,
  })
);

// Static files
app.use("/static", express.static(path.join(__dirname, "static")));

// Set EJS view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "templates"));

// Database setup
const db = new sqlite3.Database(path.join(__dirname, "civic_connect.db"), (err) => {
  if (err) console.error("DB Connection Error:", err.message);
  else console.log("✅ Connected to SQLite DB");
});

// Create tables if not exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS complaints (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category TEXT NOT NULL,
      description TEXT NOT NULL,
      votes INTEGER DEFAULT 0
  )`);
});

// ----------------- ROUTES ------------------

// Home Page
app.use("/static",express.static(path.join(__dirname,"static")));//static linkage
app.get("/", (req, res) => res.render("index"));

// Submit Complaint (GET)
app.get("/submit", (req, res) => res.render("submit"));

// Submit Complaint (POST)
app.post("/submit", (req, res) => {
  const { category, description } = req.body;       
  db.run(
    "INSERT INTO complaints (category, description) VALUES (?, ?)",
    [category, description],
    (err) => {
      if (err) {
        console.error("DB Insert Error:", err.message);
        return res.status(500).send("Database Error");
      }
      console.log("✅ Complaint inserted successfully");
      res.redirect("/status");
    }
  );
});

// Show existing complaints
app.get("/existing", (req, res) => {
  db.all("SELECT * FROM complaints", [], (err, rows) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Database Error");
    }
    res.render("existing", { complaints: rows });
  });
});

// Vote for a complaint
app.post("/vote/:id", (req, res) => {
  const complaintId = req.params.id;
  db.run("UPDATE complaints SET votes = votes + 1 WHERE id = ?", [complaintId], (err) => {
    if (err) {
      console.error("Vote Error:", err.message);
      return res.status(500).send("Database Error");
    }
    res.redirect("/existing");
  });
});

// Complaint status
app.get("/status", (req, res) => {
  db.all("SELECT * FROM complaints", [], (err, rows) => {
    if (err) {
      console.error(err.message);
      return res.status(500).send("Database Error");
    }
    res.render("status", { complaints: rows });
  });
});

// User Register
app.get("/register", (req, res) => res.render("user_register"));

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);

  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
    if (err) {
      console.error("Register Error:", err.message);
      return res.status(500).send("Registration failed");
    }
    res.redirect("/login");
  });
});

// User Login
app.get("/login", (req, res) => res.render("user_login"));

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err || !user) {
      console.error("Login Error:", err ? err.message : "User not found");
      return res.status(401).send("Invalid credentials");
    }
    if (bcrypt.compareSync(password, user.password)) {
      req.session.user = user;
      res.redirect("/");
    } else {
      res.status(401).send("Invalid credentials");
    }
  });
});

// Admin Login
app.get("/admin/login", (req, res) => res.render("admin_login"));

app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM admins WHERE username = ?", [username], (err, admin) => {
    if (err || !admin) {
      console.error("Admin Login Error:", err ? err.message : "Admin not found");
      return res.status(401).send("Invalid credentials");
    }
    if (bcrypt.compareSync(password, admin.password)) {
      req.session.admin = admin;
      res.redirect("/admin/dashboard");
    } else {
      res.status(401).send("Invalid credentials");
    }
  });
});

// Admin Dashboard
app.get("/admin/dashboard", (req, res) => {
  if (!req.session.admin) return res.redirect("/admin/login");

  db.all("SELECT * FROM complaints", [], (err, rows) => {
    if (err) {
      console.error("Dashboard Error:", err.message);
      return res.status(500).send("Database Error");
    }
    res.render("admin_dashboard", { complaints: rows });
  });
});

// ----------------- SERVER START ------------------
app.listen(PORT, () => {
console.log(`🚀 Server running at http://localhost:${PORT}`);
});