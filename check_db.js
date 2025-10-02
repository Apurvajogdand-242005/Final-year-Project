const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const dbPath = path.join(__dirname, "civic_connect.db");
const db = new sqlite3.Database(dbPath);

console.log("Checking database schema...");

db.all("PRAGMA table_info(complaints)", [], (err, rows) => {
  if (err) {
    console.error("Error:", err.message);
  } else {
    console.log("\nComplaints table schema:");
    console.log("Column Name | Type | Not Null | Default Value | Primary Key");
    console.log("-".repeat(60));
    rows.forEach(row => {
      console.log(`${row.name.padEnd(12)} | ${row.type.padEnd(8)} | ${row.notnull ? 'YES' : 'NO'.padEnd(8)} | ${row.dflt_value || 'NULL'.padEnd(13)} | ${row.pk ? 'YES' : 'NO'}`);
    });
  }

  // Also check a sample row
  db.get("SELECT * FROM complaints LIMIT 1", [], (err, row) => {
    if (err) {
      console.error("Error getting sample row:", err.message);
    } else if (row) {
      console.log("\nSample complaint row:");
      console.log(JSON.stringify(row, null, 2));
    } else {
      console.log("\nNo complaints in database yet.");
    }
    db.close();
  });
});
