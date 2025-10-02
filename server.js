const express = require("express"),
  session = require("express-session"),
  bcrypt = require("bcryptjs"),
  sqlite3 = require("sqlite3").verbose(),
  path = require("path"),
  nodemailer = require("nodemailer"),
  multer = require("multer"),
  puppeteer = require("puppeteer");

const app = express(), PORT = 5000, dbPath = path.join(__dirname, "civic_connect.db");

// --- Configuration & Middleware ---
app.use(express.urlencoded({ extended: true }), express.json(), session({ secret: "secretKey", resave: false, saveUninitialized: true }));
app.use("/static", express.static(path.join(__dirname, "static")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "templates"));

const storage = multer.diskStorage({
  destination: (r, f, cb) => cb(null, path.join(__dirname, 'static', 'uploads')),
  filename: (r, f, cb) => cb(null, f.fieldname + '-' + Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(f.originalname))
}), upload = multer({ storage });

// --- Database Promisification ---
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error("❌ DB Connection Error:", err.message);
    else console.log("✅ Connected to SQLite DB");
});
const dbRun = (query, params = []) => new Promise((resolve, reject) => db.run(query, params, function(err) { err ? reject(err) : resolve(this); }));
const dbGet = (query, params = []) => new Promise((resolve, reject) => db.get(query, params, (err, row) => { err ? reject(err) : resolve(row); }));
const dbAll = (query, params = []) => new Promise((resolve, reject) => db.all(query, params, (err, rows) => { err ? reject(err) : resolve(rows); }));
const alterTable = (col, def) => db.run(`ALTER TABLE complaints ADD COLUMN ${col} ${def}`, (err) => err && !err.message.includes("duplicate column name") ? console.error(`❌ Error adding ${col} column:`, err.message) : undefined);

// --- DB Schema & Migrations ---
db.serialize(() => {
    ['user_id INTEGER', 'status TEXT DEFAULT \'Pending\'', 'submitted_date DATETIME DEFAULT CURRENT_TIMESTAMP', 'resolved_date DATETIME', 'title TEXT', 'location TEXT', 'image_path TEXT'].forEach(colDef => alterTable(...colDef.split(' ', 2)));
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT, password TEXT NOT NULL)`);
    db.run(`CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT NOT NULL, password TEXT NOT NULL)`, (err) => err ? console.error("❌ Error creating admins table:", err.message) : undefined);
    db.run(`CREATE TABLE IF NOT EXISTS complaints (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT NOT NULL, location TEXT NOT NULL, category TEXT NOT NULL, user_id INTEGER, status TEXT DEFAULT 'Pending', submitted_date DATETIME DEFAULT CURRENT_TIMESTAMP, resolved_date DATETIME, votes INTEGER DEFAULT 0)`);
    db.run(`CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, rating INTEGER NOT NULL CHECK (rating >=1 AND rating <=5), experience TEXT, date_submitted DATETIME DEFAULT CURRENT_TIMESTAMP, complaint_id INTEGER, FOREIGN KEY (user_id) REFERENCES users (id), FOREIGN KEY (complaint_id) REFERENCES complaints (id))`, (err) => err ? console.error("❌ Error creating feedback table:", err.message) : undefined);
});

// --- Email Functions ---
const emailConfig = {
    host: 'smtp.gmail.com', port: 587, secure: false,
    auth: { user: process.env.EMAIL_USER || 'apurvajogdand2005@gmail.com', pass: process.env.EMAIL_PASS || 'jaxd brqh wbet kbdd' }
}, transporter = nodemailer.createTransport(emailConfig);

const statusColors = { 'Resolved': '#28a745', 'In Progress': '#ffc107', 'Pending': '#6c757d', 'Rejected': '#dc3545' };

const getEmailHtml = (title, status, color, body) => `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #333;">Complaint Status Update</h2><p>Dear User,</p><p>${body}</p>
        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <h3 style="margin-top: 0; color: #333;">Complaint Details:</h3>
            <p><strong>Title:</strong> ${title}</p><p><strong>Status:</strong> <span style="color: ${color}; font-weight: bold;">${status}</span></p>
        </div>
        <p>You can track the status of your complaint by logging into your account.</p>
        <p>Thank regards,<br>Civic Connect Team</p>
    </div>`;

const sendMail = async (to, subject, html) => {
    try {
        await transporter.sendMail({ from: emailConfig.auth.user, to, subject, html });
        console.log(`✅ Email sent for: ${subject.slice(0, 30)}...`);
    } catch (error) { console.error('❌ Error sending email:', error); }
};
const sendSubmittedEmail = (e, t) => sendMail(e, 'Complaint Submitted Successfully - Civic Connect', getEmailHtml(t, 'Submitted', statusColors.Resolved, 'Your complaint has been submitted.'));
const sendStatusEmail = (e, t, s) => sendMail(e, `Complaint Status Updated - ${s} - Civic Connect`, getEmailHtml(t, s, statusColors[s], 'We have an update on your complaint in our Civic Connect system.'));

// --- Route Helpers ---
const userAuth = (req, res, next) => req.session.userId ? next() : res.redirect("/login");
const adminAuth = (req, res, next) => req.session.admin ? next() : res.redirect("/admin/login");

const getUserData = async (req) => {
    let userData = { userId: req.session.userId || null, username: null };
    if (!req.session.userId) return userData;
    try {
        const user = await dbGet("SELECT username FROM users WHERE id = ?", [req.session.userId]);
        if (user) userData.username = user.username;
    } catch (err) { console.error("Error fetching user data:", err.message); }
    return userData;
};

// --- Routes ---
const renderRoute = (view, dataFn) => async (req, res) => {
    try {
        const userData = await getUserData(req);
        const viewData = dataFn ? await dataFn(req, userData) : {};
        res.render(view, { ...viewData, ...userData });
    } catch (err) {
        console.error(`Route error in /${view}:`, err.message);
        res.status(500).send("Database Error");
    }
};

app.get("/", renderRoute("index"));
app.get("/about", renderRoute("about"));
app.get("/register", (req, res) => res.render("user_register"));
app.get("/login", (req, res) => res.render("user_login"));
app.get("/logout", (req, res) => req.session.destroy(err => res.redirect("/")));
app.get("/submit", userAuth, renderRoute("submit"));

app.get("/existing", renderRoute("existing", async (req, userData) => {
    const { message, location, category, existingId, existingTitle } = req.query;
    const msgData = message ? { message, messageLocation: location, messageCategory: category, existingId, existingTitle } : {};
    const baseQuery = req.session.userId ? "SELECT c.*, u.username FROM complaints c LEFT JOIN users u ON c.user_id = u.id" : "SELECT * FROM complaints";
    const complaints = await dbAll(`${baseQuery} ORDER BY votes DESC, id DESC`);
    return { complaints, ...msgData };
}));

app.get("/status", renderRoute("status", async () => ({ complaints: await dbAll("SELECT * FROM complaints") })));

app.get("/dashboard", userAuth, renderRoute("user_dashboard", async (req) => {
    const complaints = await dbAll("SELECT * FROM complaints WHERE user_id = ?", [req.session.userId]);
    const feedback = await dbAll("SELECT * FROM feedback WHERE user_id = ? ORDER BY date_submitted DESC LIMIT 5", [req.session.userId]).catch(e => { console.error("Feedback error:", e.message); return []; });
    return { complaints, feedback };
}));

app.post("/register", async (req, res) => {
    try {
        const { username, email, password } = req.body;
        await dbRun("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", [username, email, bcrypt.hashSync(password, 10)]);
        res.redirect("/login");
    } catch (err) { res.status(500).send(err.message.includes("UNIQUE constraint failed") ? "⚠ Username already exists." : "Registration failed"); }
});

app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await dbGet("SELECT * FROM users WHERE username = ?", [username]);
        if (!user || !bcrypt.compareSync(password, user.password)) return res.status(400).send("Invalid credentials");
        req.session.userId = user.id;
        res.redirect("/submit");
    } catch (err) { res.status(500).send("Database error"); }
});

app.post("/submit", userAuth, upload.single('image'), async (req, res) => {
    const { title, description, location, category } = req.body;
    try {
        const existing = await dbGet("SELECT id, title FROM complaints WHERE location = ? AND category = ?", [location, category]);
        if (existing) {
            return res.redirect(`/existing?message=complaint_exists&location=${encodeURIComponent(location)}&category=${encodeURIComponent(category)}&existing_id=${existing.id}&existing_title=${encodeURIComponent(existing.title)}`);
        }
        await dbRun("INSERT INTO complaints (title, description, location, category, user_id, image_path) VALUES (?, ?, ?, ?, ?, ?)",
            [title, description, location, category, req.session.userId, req.file?.filename || null]);
        const user = await dbGet("SELECT email FROM users WHERE id = ?", [req.session.userId]);
        if (user?.email) await sendSubmittedEmail(user.email, title);
        res.redirect("/existing");
    } catch (err) { res.status(500).send("Database Error: " + err.message); }
});

app.get("/api/search-complaints", async (req, res) => {
    const { q: searchTerm = '', category = '', location = '' } = req.query;
    let query = "SELECT * FROM complaints WHERE 1=1", params = [];
    if (searchTerm) { query += " AND (title LIKE ? OR description LIKE ?)"; params.push(`%${searchTerm}%`, `%${searchTerm}%`); }
    if (category) { query += " AND category = ?"; params.push(category); }
    if (location) { query += " AND location LIKE ?"; params.push(`%${location}%`); }
    query += " ORDER BY votes DESC, id DESC";
    try { res.json(await dbAll(query, params)); } catch (err) { res.status(500).json({ error: "Database Error" }); }
});

app.post("/vote/:id", async (req, res) => {
    try {
        await dbRun("UPDATE complaints SET votes = votes + 1 WHERE id = ?", [req.params.id]);
        res.send(`<script>alert("vote for this complaint successfully added!"); window.location.href='/existing';</script>`);
    } catch (err) { res.status(500).send("Database Error"); }
});

app.post("/feedback", userAuth, async (req, res) => {
    const { rating, experience, complaint_id } = req.body;
    if (!rating || rating < 1 || rating > 5) return res.status(400).json({ success: false, message: "Invalid rating" });
    try {
        const result = await dbRun("INSERT INTO feedback (user_id, rating, experience, complaint_id) VALUES (?, ?, ?, ?)", [req.session.userId, parseInt(rating), experience || '', complaint_id ? parseInt(complaint_id) : null]);
        res.json({ success: true, message: "Feedback submitted successfully!", id: result.lastID });
    } catch (err) { res.status(500).json({ success: false, message: "Database error" }); }
});

app.get("/api/feedback", userAuth, async (req, res) => {
    try { res.json(await dbAll("SELECT * FROM feedback WHERE user_id = ? ORDER BY date_submitted DESC", [req.session.userId])); }
    catch (err) { res.status(500).json({ error: "Database error" }); }
});

const handleUpdateStatus = (redirectPath) => async (req, res) => {
    const { id: complaintId } = req.params;
    const newStatus = req.body.status || req.body.newstatus;
    try {
        const complaint = await dbGet("SELECT * FROM complaints WHERE id = ?", [complaintId]);
        if (!complaint) return res.status(404).send("Complaint not found");
        if (complaint.status === newStatus) return res.redirect(redirectPath);

        let updateQuery = "UPDATE complaints SET status = ?", updateParams = [newStatus];
        if (newStatus === 'Resolved') updateQuery += ", resolved_date = CURRENT_TIMESTAMP";
        updateQuery += " WHERE id = ?";
        updateParams.push(complaintId);
        await dbRun(updateQuery, updateParams);

        if (complaint.user_id) {
            const user = await dbGet("SELECT email FROM users WHERE id = ?", [complaint.user_id]);
            if (user?.email) await sendStatusEmail(user.email, complaint.title, newStatus);
        }
        res.redirect(redirectPath);
    } catch (err) { res.status(500).send("Database Error: " + err.message); }
};
app.post('/update-status/:id', handleUpdateStatus('/existing'));

// --- Admin Routes ---
app.get("/admin/register", (req, res) => res.render("admin_register"));
app.get("/admin/login", (req, res) => res.render("admin_login"));
app.get("/admin/logout", (req, res) => req.session.destroy(err => res.redirect("/")));

app.post("/admin/register", async (req, res) => {
    const { username, email, password, confirmPassword, adminCode } = req.body;
    const renderErr = (e) => res.render("admin_register", { error: e });
    if (!username || !email || !password || !confirmPassword || !adminCode) return renderErr("All fields are required");
    if (password !== confirmPassword) return renderErr("Passwords do not match");
    if (password.length < 6) return renderErr("Password must be at least 6 characters long");
    if (adminCode !== "ADMIN2025") return renderErr("Invalid admin registration code");

    try {
        if ((await dbGet("SELECT COUNT(*) as count FROM admins")).count >= 3) return renderErr("Maximum limit of 3 administrators reached.");
        if (await dbGet("SELECT id FROM admins WHERE username = ?", [username])) return renderErr("Username already exists");
        await dbRun("INSERT INTO admins (username, email, password) VALUES (?, ?, ?)", [username, email, bcrypt.hashSync(password, 10)]);
        res.redirect("/admin/login?message=Registration successful! Please login.");
    } catch (err) { renderErr(`Registration failed: ${err.message}`); }
});

app.post("/admin/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const admin = await dbGet("SELECT * FROM admins WHERE username = ?", [username]);
        if (!admin || !bcrypt.compareSync(password, admin.password)) return res.status(401).send("Invalid credentials");
        req.session.admin = admin;
        res.redirect("/admin/dashboard");
    } catch (err) { res.status(401).send("Invalid credentials"); }
});

app.get("/admin/dashboard", adminAuth, renderRoute("admin_dashboard", async () => ({ complaints: await dbAll("SELECT c.*, u.username FROM complaints c LEFT JOIN users u ON c.user_id = u.id") })));
app.post("/admin/update_status/:id", adminAuth, handleUpdateStatus('/admin/dashboard'));

app.get("/admin/delete_complaint/:id", adminAuth, async (req, res) => {
    try { await dbRun("DELETE FROM complaints WHERE id = ?", [req.params.id]); res.redirect("/admin/dashboard"); }
    catch (err) { res.status(500).send("Database Error"); }
});

app.get("/admin/export", adminAuth, async (req, res) => {
    try {
        const rows = await dbAll("SELECT * FROM complaints", []);
        const csvHeaders = "ID,Title,Category,Description,Location,Status,Votes,User ID\n";
        const csvContent = rows.map(row => `${row.id},"${row.title}","${row.category}","${row.description}","${row.location}","${row.status || 'Pending'}",${row.votes},${row.user_id}`).join("\n");
        res.header('Content-Type', 'text/csv').attachment('complaints_export.csv').send(csvHeaders + csvContent);
    } catch (err) { res.status(500).send("Database Error"); }
});

const getReportData = (rows) => {
    // Analytics calculation logic (condensed)
    const stats = { location: {}, category: {}, user: {}, monthly: {}, status: {} }, metrics = { votes: 0, high: 0, medium: 0, low: 0, resolved: 0, resolutionTime: 0 };
    rows.forEach(c => {
        const d = new Date(c.submitted_date), m = d.toISOString().slice(0, 7);
        c.priority = (c.votes >= 10) ? 'High' : (c.votes >= 5) ? 'Medium' : 'Low';
        metrics[c.priority.toLowerCase()]++;
        metrics.votes += c.votes || 0;
        stats.monthly[m] = (stats.monthly[m] || 0) + 1;
        stats.user[c.user_id] = (stats.user[c.user_id] || 0) + 1;
        stats.category[c.category] = (stats.category[c.category] || 0) + 1;
        stats.status[c.status || 'Pending'] = (stats.status[c.status || 'Pending'] || 0) + 1;
        if (!stats.location[c.location]) stats.location[c.location] = { count: 0, categories: {}, totalVotes: 0 };
        stats.location[c.location].count++; stats.location[c.location].totalVotes += c.votes || 0;
        if (!stats.location[c.location].categories[c.category]) stats.location[c.location].categories[c.category] = { count: 0, complaints: [] };
        stats.location[c.location].categories[c.category].count++; stats.location[c.location].categories[c.category].complaints.push(c);
        if (c.resolved_date) { metrics.resolutionTime += (new Date(c.resolved_date) - d) / 86400000; metrics.resolved++; }
    });
    const total = rows.length, totalP = metrics.high + metrics.medium + metrics.low;
    Object.keys(stats.location).forEach(l => stats.location[l].avgVotes = (stats.location[l].totalVotes / stats.location[l].count).toFixed(1));
    return {
        totalComplaints: total, totalVotes: metrics.votes, locationStats: stats.location, categoryStats: stats.category, statusStats: stats.status,
        avgPriority: totalP > 0 ? ((metrics.high * 3 + metrics.medium * 2 + metrics.low) / totalP).toFixed(1) : 0,
        priorityStats: { high: metrics.high, medium: metrics.medium, low: metrics.low },
        resolutionRate: total > 0 ? ((metrics.resolved / total) * 100).toFixed(1) : 0,
        avgResolutionTime: metrics.resolved > 0 ? (metrics.resolutionTime / metrics.resolved).toFixed(1) : 0,
        topUsers: Object.entries(stats.user).sort((a, b) => b[1] - a[1]).slice(0, 5),
        monthlyData: Object.entries(stats.monthly).sort((a, b) => a[0].localeCompare(b[0])).map(([m, c]) => ({ month: m, count: c })),
        generatedDate: new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    };
};

app.get("/admin/analytics", adminAuth, async (req, res) => {
    try {
        const complaints = await dbAll("SELECT * FROM complaints");
        const totalComplaints = complaints.length;
        const resolvedComplaints = complaints.filter(c => c.status === 'Resolved').length;
        const pendingComplaints = complaints.filter(c => !c.status || c.status === 'Pending').length;
        const inProgressComplaints = complaints.filter(c => c.status === 'In Progress').length;
        const totalVotes = complaints.reduce((sum, c) => sum + (c.votes || 0), 0);

        // Calculate category stats
        const categoryStats = {};
        complaints.forEach(c => {
            if (categoryStats[c.category]) categoryStats[c.category]++;
            else categoryStats[c.category] = 1;
        });

        res.render("admin_analytics", {
            totalComplaints,
            resolvedComplaints,
            pendingComplaints,
            inProgressComplaints,
            totalVotes,
            categoryStats
        });
    } catch (err) {
        console.error("Error loading analytics:", err);
        res.status(500).send("Error loading analytics");
    }
});

app.get("/admin/government-report", adminAuth, renderRoute("government_report", async () => {
    const rows = await dbAll("SELECT c.*, u.username as user_name, u.id as user_id FROM complaints c LEFT JOIN users u ON c.user_id = u.id ORDER BY c.location, c.category, c.votes DESC", []);
    const reportData = getReportData(rows);
    console.log(`📊 Report Generated: - Total Complaints: ${reportData.totalComplaints}`);
    return { ...reportData, complaints: rows };
}));

app.get("/admin/visualization-report", adminAuth, renderRoute("visualization_report", async () => {
    const rows = await dbAll("SELECT c.*, u.username as user_name, u.id as user_id FROM complaints c LEFT JOIN users u ON c.user_id = u.id ORDER BY c.location, c.category, c.votes DESC", []);
    const reportData = getReportData(rows);

    // Transform data for visualization template
    const priorityData = [['high', reportData.priorityStats.high], ['medium', reportData.priorityStats.medium], ['low', reportData.priorityStats.low]];
    const locationData = Object.entries(reportData.locationStats).map(([loc, data]) => [loc, data.count]);
    const categoryData = Object.entries(reportData.categoryStats).map(([cat, count]) => [cat, count]);
    const statusData = Object.entries(reportData.statusStats).map(([status, count]) => [status, count]);
    const userData = reportData.topUsers.map(([id, count]) => [id, count]);

    // Generate daily data (last 30 days)
    const dailyData = [];
    const now = new Date();
    for (let i = 29; i >= 0; i--) {
        const date = new Date(now);
        date.setDate(date.getDate() - i);
        const dateStr = date.toISOString().split('T')[0];
        const count = rows.filter(r => r.submitted_date.startsWith(dateStr)).length;
        dailyData.push([dateStr, count]);
    }

    // Generate hourly data
    const hourlyData = [];
    for (let h = 0; h < 24; h++) {
        const count = rows.filter(r => new Date(r.submitted_date).getHours() === h).length;
        hourlyData.push({ hour: h, count });
    }

    return {
        ...reportData,
        priorityData,
        locationData,
        categoryData,
        statusData,
        userData,
        dailyData,
        hourlyData,
        complaints: rows
    };
}));

app.get("/admin/download-report-pdf", adminAuth, async (req, res) => {
    try {
        const browser = await puppeteer.launch();
        const page = await browser.newPage();
        // Set session cookie for authentication
        const sessionCookie = req.headers.cookie;
        if (sessionCookie) {
            const cookies = sessionCookie.split(';').map(c => {
                const [name, value] = c.trim().split('=');
                return { name, value, domain: 'localhost', path: '/' };
            });
            await page.setCookie(...cookies);
        }
        await page.goto(`http://localhost:${PORT}/admin/government-report`, { waitUntil: 'networkidle0' });
        const pdfBuffer = await page.pdf({ format: 'A4' });
        await browser.close();
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename="government_report.pdf"');
        res.send(pdfBuffer);
    } catch (err) {
        console.error('Error generating PDF:', err);
        res.status(500).send('Error generating PDF');
    }
});

app.get("/admin/download-visualization-pdf", adminAuth, async (req, res) => {
    try {
        const browser = await puppeteer.launch();
        const page = await browser.newPage();
        // Set session cookie for authentication
        const sessionCookie = req.headers.cookie;
        if (sessionCookie) {
            const cookies = sessionCookie.split(';').map(c => {
                const [name, value] = c.trim().split('=');
                return { name, value, domain: 'localhost', path: '/' };
            });
            await page.setCookie(...cookies);
        }
        await page.goto(`http://localhost:${PORT}/admin/visualization-report`, { waitUntil: 'networkidle0' });
        const pdfBuffer = await page.pdf({ format: 'A4' });
        await browser.close();
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename="visualization_report.pdf"');
        res.send(pdfBuffer);
    } catch (err) {
        console.error('Error generating visualization PDF:', err);
        res.status(500).send('Error generating visualization PDF');
    }
});


// --- Server Start ---
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));