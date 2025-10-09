const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const ExcelJS = require('exceljs');

const app = express();

// ------------------ Middleware ------------------ //
app.use(cors({
  origin: 'https://luct-reporting-2-y8ix.vercel.app', // your frontend
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true
}));
app.use(bodyParser.json());

// ------------------ Database ------------------ //
const db = mysql.createPool({
  host: process.env.DB_HOST || 'sql12.freesqldatabase.com',
  user: process.env.DB_USER || 'sql12802067',
  password: process.env.DB_PASSWORD || '79DRrghTKQ',
  database: process.env.DB_NAME || 'sql12802067',
  port: 3306,
  connectionLimit: 10,
  waitForConnections: true,
  queueLimit: 0
});

// Test DB connection
db.getConnection((err, conn) => {
  if (err) {
    console.error('Database connection error:', err);
    process.exit(1);
  }
  console.log('✅ MySQL connected');
  conn.release();
});

// ------------------ JWT Auth ------------------ //
const SECRET = process.env.JWT_SECRET || 'your_secret_key';
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// ------------------ API Routes ------------------ //

// -- Auth -- //
app.post('/api/register', async (req, res) => {
  const { name, password, identifier, role } = req.body;
  if (!name || !password || !identifier || !role) return res.status(400).json({ message: 'Missing fields' });

  const validRoles = ['student', 'lecturer', 'pl', 'prl'];
  if (!validRoles.includes(role)) return res.status(400).json({ message: 'Invalid role' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    db.query(
      'INSERT INTO users (role, name, identifier, password) VALUES (?, ?, ?, ?)',
      [role, name, identifier, hashed],
      (err) => {
        if (err) {
          if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ message: 'Identifier exists' });
          return res.status(500).json({ message: 'Error registering', error: err.message });
        }
        res.json({ message: 'Registered successfully' });
      }
    );
  } catch (err) {
    res.status(500).json({ message: 'Password processing error', error: err.message });
  }
});

app.post('/api/login', (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) return res.status(400).json({ message: 'Missing identifier or password' });

  db.query('SELECT * FROM users WHERE identifier = ?', [identifier], async (err, results) => {
    if (err) return res.status(500).json({ message: 'DB query error', error: err.message });
    if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, role: user.role }, SECRET, { expiresIn: '1h' });
    res.json({ token, role: user.role });
  });
});

// -- Courses -- //
app.get('/api/courses', authenticate, (req, res) => {
  const search = req.query.search ? `%${req.query.search}%` : '%';
  db.query(
    'SELECT * FROM courses WHERE name LIKE ? OR code LIKE ? OR faculty_name LIKE ?',
    [search, search, search],
    (err, results) => {
      if (err) return res.status(500).json({ message: 'Error fetching courses', error: err.message });
      res.json(results);
    }
  );
});

app.post('/api/courses', authenticate, (req, res) => {
  if (req.user.role !== 'pl') return res.status(403).json({ message: 'Only Program Leaders can add courses' });
  const { name, code, facultyName } = req.body;
  if (!name || !code || !facultyName) return res.status(400).json({ message: 'Missing fields' });

  db.query('INSERT INTO courses (name, code, faculty_name) VALUES (?, ?, ?)', [name, code, facultyName], (err) => {
    if (err) return res.status(500).json({ message: 'Error adding course', error: err.message });
    res.json({ message: 'Course added successfully' });
  });
});

// -- Classes -- //
app.get('/api/classes', authenticate, (req, res) => {
  let sql = `SELECT cl.*, c.name as course_name, c.code as course_code, u.name as lecturer_name 
             FROM classes cl 
             JOIN courses c ON cl.course_id = c.id 
             LEFT JOIN users u ON cl.lecturer_id = u.id`;
  const params = [];
  if (req.user.role === 'lecturer') {
    sql += ' WHERE cl.lecturer_id = ?';
    params.push(req.user.id);
  }
  db.query(sql, params, (err, results) => {
    if (err) return res.status(500).json({ message: 'Error fetching classes', error: err.message });
    res.json(results);
  });
});

app.post('/api/classes', authenticate, (req, res) => {
  if (req.user.role !== 'pl') return res.status(403).json({ message: 'Only Program Leaders can add classes' });
  const { name, courseId, lecturerId } = req.body;
  if (!name || !courseId || !lecturerId) return res.status(400).json({ message: 'Missing fields' });

  db.query('INSERT INTO classes (name, course_id, lecturer_id) VALUES (?, ?, ?)', [name, courseId, lecturerId], (err) => {
    if (err) return res.status(500).json({ message: 'Error adding class', error: err.message });
    res.json({ message: 'Class added successfully' });
  });
});

// -- Reports -- //
app.get('/api/reports', authenticate, (req, res) => {
  let sql = `SELECT r.*, cl.name as class_name, u.name as lecturer_name 
             FROM reports r 
             JOIN classes cl ON r.class_id = cl.id 
             LEFT JOIN users u ON cl.lecturer_id = u.id`;
  db.query(sql, [], (err, results) => {
    if (err) return res.status(500).json({ message: 'Error fetching reports', error: err.message });
    res.json(results);
  });
});

// ------------------ Catch-All 404 ------------------ //
app.all('*', (req, res) => {
  res.status(404).json({ message: `Route ${req.method} ${req.path} not found` });
});

// ------------------ Start Server ------------------ //
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
