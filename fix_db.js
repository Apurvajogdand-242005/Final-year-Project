const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const dbPath = path.join(__dirname, "civic_connect.db");
const db = new sqlite3.Database(dbPath);

console.log("Fixing database schema...");

// First, backup existing data
db.all("SELECT * FROM complaints", [], (err, rows) => {
  if (err) {
    console.error("Error backing up data:", err.message);
    return;
  }

  console.log(`Backing up ${rows.length} complaints...`);

  // Drop and recreate table with proper schema
  db.serialize(() => {
    // Drop existing table
    db.run("DROP TABLE IF EXISTS complaints", (err) => {
      if (err) {
        console.error("Error dropping table:", err.message);
        return;
      }
      console.log("Dropped old complaints table");

      // Create new table with proper schema
      db.run(`CREATE TABLE complaints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        location TEXT NOT NULL,
        category TEXT NOT NULL,
        user_id INTEGER,
        status TEXT DEFAULT 'Pending',
        submitted_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        resolved_date DATETIME,
        votes INTEGER DEFAULT 0
      )`, (err) => {
        if (err) {
          console.error("Error creating new table:", err.message);
          return;
        }
        console.log("Created new complaints table with proper schema");

        // Reinsert backed up data
        let inserted = 0;
        rows.forEach(row => {
          db.run(`INSERT INTO complaints (id, title, description, location, category, user_id, status, submitted_date, resolved_date, votes)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [row.id, row.title, row.description, row.location, row.category, row.user_id, row.status,
             row.submitted_date || new Date().toISOString(), row.resolved_date, row.votes],
            function(err) {
              if (err) {
                console.error("Error reinserting row:", err.message);
              } else {
                inserted++;
                if (inserted === rows.length) {
                  console.log(`✅ Successfully migrated ${inserted} complaints`);
                  console.log("Database schema fixed!");
                  db.close();
                }
              }
            });
        });

        if (rows.length === 0) {
          console.log("No data to migrate. Schema fixed!");
          db.close();
        }
      });
    });
  });
});
