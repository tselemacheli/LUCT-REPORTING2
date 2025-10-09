const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const ExcelJS = require('exceljs');
const rateLimit = require('express-rate-limit');
const winston = require('winston');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Configure Winston logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

// Database configuration with environment variables
const db = mysql.createPool({
  host: process.env.DB_HOST || 'sql12.freesqldatabase.com',
  user: process.env.DB_USER || 'sql12802067',
  password: process.env.DB_PASSWORD || '79DRrghTKQ',
  database: process.env.DB_NAME || 'sql12802067',
  port: process.env.DB_PORT || 3306,
  connectionLimit: 10,
  connectTimeout: 60000,
  waitForConnections: true,
  queueLimit: 0,
});

db.getConnection((err, connection) => {
  if (err) {
    logger.error('Database connection error:', err);
    process.exit(1);
  }
  logger.info('MySQL Connected to FreeSQLDatabase');
  connection.release();
});

const SECRET = process.env.JWT_SECRET || 'your_secure_random_key_here';

// Rate limiting for login and register endpoints
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: 'Too many attempts, please try again later.',
});

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    logger.warn('No token provided', { path: req.path });
    return res.status(401).json({ message: 'No token provided' });
  }
  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      logger.warn('Invalid or expired token', { path: req.path });
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Register endpoint
app.post('/api/register', loginLimiter, async (req, res) => {
  const { name, password, identifier, role } = req.body;
  if (!name || !password || !identifier || !role) {
    logger.warn('Missing required fields in register', { body: req.body });
    return res.status(400).json({ message: 'Missing required fields' });
  }
  const validRoles = ['student', 'lecturer', 'pl', 'prl'];
  if (!validRoles.includes(role)) {
    logger.warn('Invalid role in register', { role });
    return res.status(400).json({ message: 'Invalid role' });
  }
  if (!/^[a-zA-Z ]+$/.test(name) || name.trim().split(/\s+/).length > 3) {
    logger.warn('Invalid name format', { name });
    return res.status(400).json({ message: 'Invalid name: max 3 words, letters only' });
  }
  if (password.length < 6) {
    logger.warn('Password too short', { identifier });
    return res.status(400).json({ message: 'Password must be at least 6 characters' });
  }
  if (!identifier || (role === 'student' && !/^\d+$/.test(identifier)) || (['lecturer', 'pl', 'prl'].includes(role) && !/^[A-Za-z0-9]+$/.test(identifier))) {
    logger.warn('Invalid identifier format', { identifier, role });
    return res.status(400).json({ message: 'Invalid identifier: must be numbers for students, alphanumeric for others' });
  }
  try {
    const hashed = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (role, name, identifier, password) VALUES (?, ?, ?, ?)',
      [role, name, identifier, hashed],
      (err) => {
        if (err) {
          logger.error('Registration error:', err);
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: 'Identifier already exists' });
          }
          return res.status(500).json({ message: 'Error registering user', error: err.message });
        }
        logger.info('User registered successfully', { identifier, role });
        res.json({ message: 'Registered successfully' });
      });
  } catch (hashError) {
    logger.error('Hashing error:', hashError);
    res.status(500).json({ message: 'Error processing password', error: hashError.message });
  }
});

// Login endpoint
app.post('/api/login', loginLimiter, (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) {
    logger.warn('Missing identifier or password in login', { body: req.body });
    return res.status(400).json({ message: 'Missing identifier or password' });
  }
  db.query('SELECT * FROM users WHERE identifier = ?', [identifier], async (err, results) => {
    if (err) {
      logger.error('Login query error:', err);
      return res.status(500).json({ message: 'Error querying database', error: err.message });
    }
    if (results.length === 0) {
      logger.warn('Invalid credentials: user not found', { identifier });
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      logger.warn('Invalid credentials: password mismatch', { identifier });
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, role: user.role }, SECRET, { expiresIn: '1h' });
    logger.info('User logged in successfully', { identifier, role: user.role });
    res.json({ token, role: user.role });
  });
});

// Get lecturers (for Program Leader)
app.get('/api/lecturers', authenticate, (req, res) => {
  if (req.user.role !== 'pl') {
    logger.warn('Unauthorized access to lecturers', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only Program Leaders can access this' });
  }
  db.query('SELECT id, name FROM users WHERE role = "lecturer"', (err, results) => {
    if (err) {
      logger.error('Fetch lecturers error:', err);
      return res.status(500).json({ message: 'Error fetching lecturers', error: err.message });
    }
    logger.info('Lecturers fetched', { userId: req.user.id });
    res.json(results);
  });
});

// Get lecturers for a student's enrolled classes
app.get('/api/my-lecturers', authenticate, (req, res) => {
  if (req.user.role !== 'student') {
    logger.warn('Unauthorized access to my-lecturers', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only students can access this' });
  }
  const sql = `
    SELECT DISTINCT u.id, u.name, u.identifier
    FROM users u
    JOIN classes c ON u.id = c.lecturer_id
    JOIN enrollments e ON c.id = e.class_id
    WHERE e.student_id = ? AND u.role = 'lecturer'
  `;
  db.query(sql, [req.user.id], (err, results) => {
    if (err) {
      logger.error('Fetch my-lecturers error:', err);
      return res.status(500).json({ message: 'Error fetching lecturers', error: err.message });
    }
    logger.info('My lecturers fetched', { userId: req.user.id, count: results.length });
    res.json(results);
  });
});

// Get available classes for a student to enroll in
app.get('/api/available-classes', authenticate, (req, res) => {
  if (req.user.role !== 'student') {
    logger.warn('Unauthorized access to available-classes', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only students can access this' });
  }
  const search = req.query.search ? `%${req.query.search}%` : '%';
  const sql = `
    SELECT c.id, c.name, co.name AS course_name
    FROM classes c
    JOIN courses co ON c.course_id = co.id
    WHERE c.id NOT IN (
      SELECT class_id FROM enrollments WHERE student_id = ?
    )
    AND (c.name LIKE ? OR co.name LIKE ?)
  `;
  db.query(sql, [req.user.id, search, search], (err, results) => {
    if (err) {
      logger.error('Fetch available-classes error:', err);
      return res.status(500).json({ message: 'Error fetching available classes', error: err.message });
    }
    logger.info('Available classes fetched', { userId: req.user.id, search: req.query.search, count: results.length });
    res.json(results);
  });
});

// Get student's enrolled classes
app.get('/api/my-enrollments', authenticate, (req, res) => {
  if (req.user.role !== 'student') {
    logger.warn('Unauthorized access to my-enrollments', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only students can access this' });
  }
  const search = req.query.search ? `%${req.query.search}%` : '%';
  const sql = `
    SELECT e.class_id AS id, c.name, co.name AS course_name
    FROM enrollments e
    JOIN classes c ON e.class_id = c.id
    JOIN courses co ON c.course_id = co.id
    WHERE e.student_id = ?
    AND (c.name LIKE ? OR co.name LIKE ?)
  `;
  db.query(sql, [req.user.id, search, search], (err, results) => {
    if (err) {
      logger.error('Fetch my-enrollments error:', err);
      return res.status(500).json({ message: 'Error fetching enrollments', error: err.message });
    }
    logger.info('Enrollments fetched', { userId: req.user.id, search: req.query.search, count: results.length });
    res.json(results);
  });
});

// Enroll in a class
app.post('/api/enroll', authenticate, (req, res) => {
  if (req.user.role !== 'student') {
    logger.warn('Unauthorized enrollment attempt', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only students can enroll' });
  }
  const { classId } = req.body;
  if (!classId) {
    logger.warn('Missing classId in enroll', { userId: req.user.id });
    return res.status(400).json({ message: 'Class ID is required' });
  }
  db.query(
    'INSERT INTO enrollments (student_id, class_id) VALUES (?, ?)',
    [req.user.id, classId],
    (err) => {
      if (err) {
        logger.error('Enrollment error:', err);
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: 'You are already enrolled in this class' });
        }
        return res.status(500).json({ message: 'Error enrolling in class', error: err.message });
      }
      logger.info('Enrolled successfully', { userId: req.user.id, classId });
      res.json({ message: 'Enrolled successfully' });
    }
  );
});

// Submit a report
app.post('/api/reports', authenticate, (req, res) => {
  if (req.user.role !== 'lecturer') {
    logger.warn('Unauthorized report submission attempt', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only lecturers can submit reports' });
  }
  const {
    classId,
    week,
    dateLecture,
    venue,
    scheduledTime,
    topic,
    learningOutcomes,
    recommendations,
    actualPresent,
    totalRegistered,
  } = req.body;

  if (!classId || !week || !dateLecture || !venue || !scheduledTime || !topic || !learningOutcomes || !recommendations || actualPresent === undefined || totalRegistered === undefined) {
    logger.warn('Missing required fields in report submission', { userId: req.user.id });
    return res.status(400).json({ message: 'Missing required fields' });
  }

  const sql = `
    INSERT INTO reports (class_id, week, date_lecture, venue, scheduled_time, topic, learning_outcomes, recommendations, actual_present, total_registered)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  db.query(
    sql,
    [classId, week, dateLecture, venue, scheduledTime, topic, learningOutcomes, recommendations, actualPresent, totalRegistered],
    (err, result) => {
      if (err) {
        logger.error('Report submission error:', err);
        return res.status(500).json({ message: 'Error submitting report', error: err.message });
      }
      logger.info('Report submitted successfully', { userId: req.user.id, reportId: result.insertId });
      res.json({ message: 'Report submitted successfully', reportId: result.insertId });
    }
  );
});

// Get reports
app.get('/api/reports', authenticate, (req, res) => {
  const search = req.query.search ? `%${req.query.search}%` : '%';
  let sql;
  let params;

  if (req.user.role === 'lecturer') {
    sql = `
      SELECT r.*, c.name AS class_name, co.name AS course_name
      FROM reports r
      JOIN classes c ON r.class_id = c.id
      JOIN courses co ON c.course_id = co.id
      WHERE c.lecturer_id = ? AND (r.topic LIKE ? OR c.name LIKE ? OR co.name LIKE ?)
    `;
    params = [req.user.id, search, search, search];
  } else if (req.user.role === 'prl') {
    sql = `
      SELECT r.*, c.name AS class_name, co.name AS course_name
      FROM reports r
      JOIN classes c ON r.class_id = c.id
      JOIN courses co ON c.course_id = co.id
      WHERE r.prl_feedback IS NULL AND (r.topic LIKE ? OR c.name LIKE ? OR co.name LIKE ?)
    `;
    params = [search, search, search];
  } else {
    logger.warn('Unauthorized access to reports', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only lecturers and PRLs can access reports' });
  }

  db.query(sql, params, (err, results) => {
    if (err) {
      logger.error('Fetch reports error:', err);
      return res.status(500).json({ message: 'Error fetching reports', error: err.message });
    }
    logger.info('Reports fetched', { userId: req.user.id, count: results.length });
    res.json(results);
  });
});

// Add feedback to a report
app.put('/api/reports/:id/feedback', authenticate, (req, res) => {
  if (req.user.role !== 'prl') {
    logger.warn('Unauthorized feedback submission attempt', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only PRLs can add feedback' });
  }
  const { feedback } = req.body;
  const reportId = req.params.id;

  if (!feedback) {
    logger.warn('Missing feedback in report feedback', { userId: req.user.id, reportId });
    return res.status(400).json({ message: 'Feedback is required' });
  }

  const sql = 'UPDATE reports SET prl_feedback = ? WHERE id = ?';
  db.query(sql, [feedback, reportId], (err, result) => {
    if (err) {
      logger.error('Report feedback error:', err);
      return res.status(500).json({ message: 'Error adding feedback', error: err.message });
    }
    if (result.affectedRows === 0) {
      logger.warn('Report not found for feedback', { userId: req.user.id, reportId });
      return res.status(404).json({ message: 'Report not found' });
    }
    logger.info('Feedback added to report', { userId: req.user.id, reportId });
    res.json({ message: 'Feedback added successfully' });
  });
});

// Get report attendance
app.get('/api/reports/:id/attendance', authenticate, (req, res) => {
  if (!['lecturer', 'prl'].includes(req.user.role)) {
    logger.warn('Unauthorized access to report attendance', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only lecturers and PRLs can access attendance' });
  }
  const reportId = req.params.id;
  const sql = `
    SELECT a.*, u.name AS student_name
    FROM attendance a
    JOIN users u ON a.student_id = u.id
    WHERE a.report_id = ?
  `;
  db.query(sql, [reportId], (err, results) => {
    if (err) {
      logger.error('Fetch report attendance error:', err);
      return res.status(500).json({ message: 'Error fetching attendance', error: err.message });
    }
    logger.info('Report attendance fetched', { userId: req.user.id, reportId, count: results.length });
    res.json(results);
  });
});

// Mark attendance
app.post('/api/attendance', authenticate, (req, res) => {
  if (req.user.role !== 'lecturer') {
    logger.warn('Unauthorized attendance marking attempt', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only lecturers can mark attendance' });
  }
  const { reportId, studentId, present } = req.body;

  if (!reportId || !studentId || present === undefined) {
    logger.warn('Missing required fields in attendance', { userId: req.user.id });
    return res.status(400).json({ message: 'Missing required fields' });
  }

  const sql = 'INSERT INTO attendance (report_id, student_id, present) VALUES (?, ?, ?)';
  db.query(sql, [reportId, studentId, present], (err, result) => {
    if (err) {
      logger.error('Attendance marking error:', err);
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(400).json({ message: 'Attendance already marked for this student and report' });
      }
      return res.status(500).json({ message: 'Error marking attendance', error: err.message });
    }
    logger.info('Attendance marked successfully', { userId: req.user.id, reportId, studentId });
    res.json({ message: 'Attendance marked successfully' });
  });
});

// Get student's attendance
app.get('/api/my-attendance', authenticate, (req, res) => {
  if (req.user.role !== 'student') {
    logger.warn('Unauthorized access to my-attendance', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only students can access their attendance' });
  }
  const search = req.query.search ? `%${req.query.search}%` : '%';
  const sql = `
    SELECT a.*, r.topic, c.name AS class_name, co.name AS course_name
    FROM attendance a
    JOIN reports r ON a.report_id = r.id
    JOIN classes c ON r.class_id = c.id
    JOIN courses co ON c.course_id = co.id
    WHERE a.student_id = ? AND (r.topic LIKE ? OR c.name LIKE ? OR co.name LIKE ?)
  `;
  db.query(sql, [req.user.id, search, search, search], (err, results) => {
    if (err) {
      logger.error('Fetch my-attendance error:', err);
      return res.status(500).json({ message: 'Error fetching attendance', error: err.message });
    }
    logger.info('My attendance fetched', { userId: req.user.id, count: results.length });
    res.json(results);
  });
});

// Rate a lecturer
app.post('/api/lecturer-ratings', authenticate, (req, res) => {
  if (req.user.role !== 'student') {
    logger.warn('Unauthorized lecturer rating attempt', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only students can rate lecturers' });
  }
  const { lecturerId, rating, comment } = req.body;

  if (!lecturerId || !rating || rating < 1 || rating > 5) {
    logger.warn('Invalid lecturer rating data', { userId: req.user.id, lecturerId, rating });
    return res.status(400).json({ message: 'Lecturer ID and rating (1-5) are required' });
  }

  const sql = 'INSERT INTO lecturer_ratings (student_id, lecturer_id, rating, comment) VALUES (?, ?, ?, ?)';
  db.query(sql, [req.user.id, lecturerId, rating, comment || ''], (err, result) => {
    if (err) {
      logger.error('Lecturer rating error:', err);
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(400).json({ message: 'You have already rated this lecturer' });
      }
      return res.status(500).json({ message: 'Error submitting rating', error: err.message });
    }
    logger.info('Lecturer rating submitted', { userId: req.user.id, lecturerId });
    res.json({ message: 'Rating submitted successfully' });
  });
});

// Get lecturer ratings
app.get('/api/lecturer-ratings/:lecturerId', authenticate, (req, res) => {
  if (!['pl', 'prl'].includes(req.user.role)) {
    logger.warn('Unauthorized access to lecturer ratings', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only PLs and PRLs can access lecturer ratings' });
  }
  const lecturerId = req.params.lecturerId;
  const sql = `
    SELECT lr.*, u.name AS student_name
    FROM lecturer_ratings lr
    JOIN users u ON lr.student_id = u.id
    WHERE lr.lecturer_id = ?
  `;
  db.query(sql, [lecturerId], (err, results) => {
    if (err) {
      logger.error('Fetch lecturer ratings error:', err);
      return res.status(500).json({ message: 'Error fetching ratings', error: err.message });
    }
    logger.info('Lecturer ratings fetched', { userId: req.user.id, lecturerId, count: results.length });
    res.json(results);
  });
});

// Get all lecturer ratings
app.get('/api/lecturer-ratings', authenticate, (req, res) => {
  if (!['pl', 'prl'].includes(req.user.role)) {
    logger.warn('Unauthorized access to all lecturer ratings', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only PLs and PRLs can access lecturer ratings' });
  }
  const search = req.query.search ? `%${req.query.search}%` : '%';
  const sql = `
    SELECT lr.*, u1.name AS student_name, u2.name AS lecturer_name
    FROM lecturer_ratings lr
    JOIN users u1 ON lr.student_id = u1.id
    JOIN users u2 ON lr.lecturer_id = u2.id
    WHERE u1.name LIKE ? OR u2.name LIKE ?
  `;
  db.query(sql, [search, search], (err, results) => {
    if (err) {
      logger.error('Fetch all lecturer ratings error:', err);
      return res.status(500).json({ message: 'Error fetching ratings', error: err.message });
    }
    logger.info('All lecturer ratings fetched', { userId: req.user.id, count: results.length });
    res.json(results);
  });
});

// Get courses
app.get('/api/courses', authenticate, (req, res) => {
  if (!['pl', 'lecturer'].includes(req.user.role)) {
    logger.warn('Unauthorized access to courses', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only PLs and lecturers can access courses' });
  }
  const search = req.query.search ? `%${req.query.search}%` : '%';
  const sql = 'SELECT * FROM courses WHERE name LIKE ? OR code LIKE ?';
  db.query(sql, [search, search], (err, results) => {
    if (err) {
      logger.error('Fetch courses error:', err);
      return res.status(500).json({ message: 'Error fetching courses', error: err.message });
    }
    logger.info('Courses fetched', { userId: req.user.id, count: results.length });
    res.json(results);
  });
});

// Add a course
app.post('/api/courses', authenticate, (req, res) => {
  if (req.user.role !== 'pl') {
    logger.warn('Unauthorized course creation attempt', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only PLs can add courses' });
  }
  const { name, code, facultyName } = req.body;

  if (!name || !code || !facultyName) {
    logger.warn('Missing required fields in course creation', { userId: req.user.id });
    return res.status(400).json({ message: 'Missing required fields' });
  }

  const sql = 'INSERT INTO courses (name, code, faculty_name) VALUES (?, ?, ?)';
  db.query(sql, [name, code, facultyName], (err, result) => {
    if (err) {
      logger.error('Course creation error:', err);
      return res.status(500).json({ message: 'Error adding course', error: err.message });
    }
    logger.info('Course added successfully', { userId: req.user.id, courseId: result.insertId });
    res.json({ message: 'Course added successfully' });
  });
});

// Get classes
app.get('/api/classes', authenticate, (req, res) => {
  if (!['pl', 'lecturer'].includes(req.user.role)) {
    logger.warn('Unauthorized access to classes', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only PLs and lecturers can access classes' });
  }
  const search = req.query.search ? `%${req.query.search}%` : '%';
  const sql = `
    SELECT c.*, co.name AS course_name, u.name AS lecturer_name
    FROM classes c
    JOIN courses co ON c.course_id = co.id
    LEFT JOIN users u ON c.lecturer_id = u.id
    WHERE c.name LIKE ? OR co.name LIKE ?
  `;
  db.query(sql, [search, search], (err, results) => {
    if (err) {
      logger.error('Fetch classes error:', err);
      return res.status(500).json({ message: 'Error fetching classes', error: err.message });
    }
    logger.info('Classes fetched', { userId: req.user.id, count: results.length });
    res.json(results);
  });
});

// Add a class
app.post('/api/classes', authenticate, (req, res) => {
  if (req.user.role !== 'pl') {
    logger.warn('Unauthorized class creation attempt', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only PLs can add classes' });
  }
  const { name, courseId, lecturerId } = req.body;

  if (!name || !courseId) {
    logger.warn('Missing required fields in class creation', { userId: req.user.id });
    return res.status(400).json({ message: 'Name and course ID are required' });
  }

  const sql = 'INSERT INTO classes (name, course_id, lecturer_id) VALUES (?, ?, ?)';
  db.query(sql, [name, courseId, lecturerId || null], (err, result) => {
    if (err) {
      logger.error('Class creation error:', err);
      return res.status(500).json({ message: 'Error adding class', error: err.message });
    }
    logger.info('Class added successfully', { userId: req.user.id, classId: result.insertId });
    res.json({ message: 'Class added successfully' });
  });
});

// Get class details
app.get('/api/class/:id', authenticate, (req, res) => {
  if (!['pl', 'lecturer'].includes(req.user.role)) {
    logger.warn('Unauthorized access to class details', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only PLs and lecturers can access class details' });
  }
  const classId = req.params.id;
  const sql = `
    SELECT c.*, co.name AS course_name, u.name AS lecturer_name
    FROM classes c
    JOIN courses co ON c.course_id = co.id
    LEFT JOIN users u ON c.lecturer_id = u.id
    WHERE c.id = ?
  `;
  db.query(sql, [classId], (err, results) => {
    if (err) {
      logger.error('Fetch class details error:', err);
      return res.status(500).json({ message: 'Error fetching class details', error: err.message });
    }
    if (results.length === 0) {
      logger.warn('Class not found', { userId: req.user.id, classId });
      return res.status(404).json({ message: 'Class not found' });
    }
    logger.info('Class details fetched', { userId: req.user.id, classId });
    res.json(results[0]);
  });
});

// Export reports
app.get('/api/reports/export', authenticate, async (req, res) => {
  if (req.user.role !== 'prl') {
    logger.warn('Unauthorized access to export reports', { userId: req.user.id, role: req.user.role });
    return res.status(403).json({ message: 'Forbidden: Only PRLs can export reports' });
  }

  const sql = `
    SELECT r.*, c.name AS class_name, co.name AS course_name
    FROM reports r
    JOIN classes c ON r.class_id = c.id
    JOIN courses co ON c.course_id = co.id
  `;
  db.query(sql, async (err, results) => {
    if (err) {
      logger.error('Export reports error:', err);
      return res.status(500).json({ message: 'Error exporting reports', error: err.message });
    }

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Reports');

    worksheet.columns = [
      { header: 'Report ID', key: 'id', width: 10 },
      { header: 'Class', key: 'class_name', width: 20 },
      { header: 'Course', key: 'course_name', width: 30 },
      { header: 'Week', key: 'week', width: 10 },
      { header: 'Date', key: 'date_lecture', width: 15 },
      { header: 'Venue', key: 'venue', width: 15 },
      { header: 'Time', key: 'scheduled_time', width: 15 },
      { header: 'Topic', key: 'topic', width: 30 },
      { header: 'Learning Outcomes', key: 'learning_outcomes', width: 40 },
      { header: 'Recommendations', key: 'recommendations', width: 40 },
      { header: 'Present', key: 'actual_present', width: 10 },
      { header: 'Registered', key: 'total_registered', width: 10 },
      { header: 'PRL Feedback', key: 'prl_feedback', width: 40 },
    ];

    results.forEach((report) => {
      worksheet.addRow({
        id: report.id,
        class_name: report.class_name,
        course_name: report.course_name,
        week: report.week,
        date_lecture: report.date_lecture,
        venue: report.venue,
        scheduled_time: report.scheduled_time,
        topic: report.topic,
        learning_outcomes: report.learning_outcomes,
        recommendations: report.recommendations,
        actual_present: report.actual_present,
        total_registered: report.total_registered,
        prl_feedback: report.prl_feedback,
      });
    });

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=reports.xlsx');

    try {
      await workbook.xlsx.write(res);
      logger.info('Reports exported successfully', { userId: req.user.id });
    } catch (err) {
      logger.error('Export reports write error:', err);
      res.status(500).json({ message: 'Error exporting reports', error: err.message });
    }
  });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => logger.info(`Backend running on http://localhost:${PORT}`));
