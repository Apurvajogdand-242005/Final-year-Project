const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'civic_connect.db');
console.log('Testing UPDATE query on:', dbPath);

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('❌ DB Connection Error:', err.message);
    return;
  }
  console.log('✅ Connected to SQLite DB');

  // Test the exact UPDATE query that's failing
  const updateQuery = "UPDATE complaints SET status = ?, resolved_date = CURRENT_TIMESTAMP WHERE id = ?";
  const updateParams = ['Resolved', 1]; // Test with complaint ID 1

  console.log('Test Query:', updateQuery);
  console.log('Test Params:', updateParams);

  db.run(updateQuery, updateParams, function (err) {
    if (err) {
      console.error("❌ DB Update Error:", err.message);
      console.error("Full error:", err);
    } else {
      console.log(`✅ Update successful, changes: ${this.changes}`);
    }
    db.close();
  });
});
