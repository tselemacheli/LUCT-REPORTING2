const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const ExcelJS = require('exceljs');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Updated database connection using a connection pool for better reliability
const db = mysql.createPool({
  host: process.env.DB_HOST || 'sql12.freesqldatabase.com',
  user: process.env.DB_USER || 'sql12802067',
  password: process.env.DB_PASSWORD || '79DRrghTKQ',
  database: 'sql12802067',
  port: 3306,
  connectionLimit: 10, // Adjust based on your needs
  connectTimeout: 60000, // Valid option for connection timeout (ms)
  waitForConnections: true, // Replaces 'reconnect' for connection pooling
  queueLimit: 0 // Unlimited queued requests
});

// Test the connection pool
db.getConnection((err, connection) => {
  if (err) {
    console.error('Database connection error:', err);
    process.exit(1);
  }
  console.log('MySQL Connected to FreeSQLDatabase');
  connection.release(); // Release the connection back to the pool
});

const SECRET = process.env.JWT_SECRET || 'your_secret_key'; // Use environment variable in production

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    console.log('Authenticated user:', req.user);
    next();
  });
};

// Register endpoint
app.post('/api/register', async (req, res) => {
  const { name, password, identifier, role } = req.body;
  if (!name || !password || !identifier || !role) {
    return res.status(400).json({ message: 'Missing required fields' });
  }
  const validRoles = ['student', 'lecturer', 'pl', 'prl'];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ message: 'Invalid role' });
  }
  if (!/^[a-zA-Z ]+$/.test(name) || name.trim().split(/\s+/).length > 3) {
    return res.status(400).json({ message: 'Invalid name: max 3 words, letters only' });
  }
  if (!/^\d+$/.test(password)) {
    return res.status(400).json({ message: 'Invalid password: numbers only' });
  }
  if (!identifier || (role === 'student' && !/^\d+$/.test(identifier)) || (['lecturer', 'pl', 'prl'].includes(role) && !/^[A-Za-z0-9]+$/.test(identifier))) {
    return res.status(400).json({ message: 'Invalid identifier: must be numbers for students, alphanumeric for others' });
  }
  try {
    const hashed = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (role, name, identifier, password) VALUES (?, ?, ?, ?)',
      [role, name, identifier, hashed],
      (err) => {
        if (err) {
          console.error('Registration error:', err);
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: 'Identifier already exists' });
          } else if (err.code === 'ER_NO_SUCH_TABLE') {
            return res.status(500).json({ message: 'Database table not found' });
          }
          return res.status(500).json({ message: 'Error registering user', error: err.message });
        }
        res.json({ message: 'Registered successfully' });
      });
  } catch (hashError) {
    console.error('Hashing error:', hashError);
    res.status(500).json({ message: 'Error processing password', error: hashError.message });
  }
});

// Login endpoint
app.post('/api/login', (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) {
    return res.status(400).json({ message: 'Missing identifier or password' });
  }
  db.query('SELECT * FROM users WHERE identifier = ?', [identifier], async (err, results) => {
    if (err) {
      console.error('Login query error:', err);
      return res.status(500).json({ message: 'Error querying database', error: err.message });
    }
    if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });
    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, role: user.role }, SECRET, { expiresIn: '1h' });
    res.json({ token, role: user.role });
  });
});

// Get lecturers (for Program Leader)
app.get('/api/lecturers', authenticate, (req, res) => {
  if (req.user.role !== 'pl') return res.status(403).json({ message: 'Forbidden: Only Program Leaders can access this' });
  db.query('SELECT id, name FROM users WHERE role = "lecturer"', (err, results) => {
    if (err) {
      console.error('Fetch lecturers error:', err);
      return res.status(500).json({ message: 'Error fetching lecturers', error: err.message });
    }
    res.json(results);
  });
});

// Add course (Program Leader)
app.post('/api/courses', authenticate, (req, res) => {
  if (req.user.role !== 'pl') return res.status(403).json({ message: 'Forbidden: Only Program Leaders can add courses' });
  const { name, code, facultyName } = req.body;
  if (!name || !code || !facultyName) {
    return res.status(400).json({ message: 'Missing required fields' });
  }
  db.query('INSERT INTO courses (name, code, faculty_name) VALUES (?, ?, ?)', [name, code, facultyName], (err) => {
    if (err) {
      console.error('Add course error:', err);
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(400).json({ message: 'Course code already exists' });
      }
      return res.status(500).json({ message: 'Error adding course', error: err.message });
    }
    res.json({ message: 'Course added successfully' });
  });
});

// Get courses (Program Leader, Principal Lecturer)
app.get('/api/courses', authenticate, (req, res) => {
  const query = req.query.search ? %${req.query.search}% : '%';
  db.query('SELECT * FROM courses WHERE name LIKE ? OR code LIKE ? OR faculty_name LIKE ?', [query, query, query], (err, results) => {
    if (err) {
      console.error('Fetch courses error:', err);
      return res.status(500).json({ message: 'Error fetching courses', error: err.message });
    }
    res.json(results);
  });
});

// Add class (Program Leader)
app.post('/api/classes', authenticate, (req, res) => {
  if (req.user.role !== 'pl') return res.status(403).json({ message: 'Forbidden: Only Program Leaders can add classes' });
  const { name, courseId, lecturerId } = req.body;
  if (!name || !courseId || !lecturerId) {
    return res.status(400).json({ message: 'Missing required fields' });
  }
  db.query('INSERT INTO classes (name, course_id, lecturer_id) VALUES (?, ?, ?)', [name, courseId, lecturerId], (err) => {
    if (err) {
      console.error('Add class error:', err);
      if (err.code === 'ER_NO_REFERENCED_ROW') {
        return res.status(400).json({ message: 'Invalid course or lecturer ID' });
      }
      return res.status(500).json({ message: 'Error adding class', error: err.message });
    }
    res.json({ message: 'Class added successfully' });
  });
});

// Get classes (Lecturer, Program Leader, Principal Lecturer)
app.get('/api/classes', authenticate, (req, res) => {
  let sql = 'SELECT cl.*, c.name as course_name, c.code as course_code, c.faculty_name, u.name as lecturer_name FROM classes cl JOIN courses c ON cl.course_id = c.id LEFT JOIN users u ON cl.lecturer_id = u.id';
  let params = [];
  if (req.user.role === 'lecturer') {
    sql += ' WHERE cl.lecturer_id = ?';
    params = [req.user.id];
  }
  const query = req.query.search ? %${req.query.search}% : '%';
  sql += params.length ? ' AND' : ' WHERE';
  sql += ' (cl.name LIKE ? OR c.name LIKE ?)';
  params.push(query, query);
  db.query(sql, params, (err, results) => {
    if (err) {
      console.error('Fetch classes error:', err);
      return res.status(500).json({ message: 'Error fetching classes', error: err.message });
    }
    res.json(results);
  });
});

// Get class details (Lecturer)
app.get('/api/class/:id', authenticate, (req, res) => {
  db.query(
    'SELECT cl.*, c.name as course_name, c.code as course_code, c.faculty_name, u.name as lecturer_name FROM classes cl JOIN courses c ON cl.course_id = c.id LEFT JOIN users u ON cl.lecturer_id = u.id WHERE cl.id = ?',
    [req.params.id],
    (err, results) => {
      if (err) {
        console.error('Fetch class details error:', err);
        return res.status(500).json({ message: 'Error fetching class details', error: err.message });
      }
      if (results.length === 0) return res.status(404).json({ message: 'Class not found' });
      const classInfo = results[0];
      db.query('SELECT u.id, u.name FROM enrollments e JOIN users u ON e.student_id = u.id WHERE e.class_id = ?', [req.params.id], (err, students) => {
        if (err) {
          console.error('Fetch students error:', err);
          return res.status(500).json({ message: 'Error fetching students', error: err.message });
        }
        classInfo.students = students;
        classInfo.total_registered = students.length;
        res.json(classInfo);
      });
    }
  );
});

// Enroll in class (Student)
app.post('/api/enroll', authenticate, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ message: 'Forbidden: Only students can enroll' });
  const { classId } = req.body;
  if (!classId) return res.status(400).json({ message: 'Class ID is required' });
  db.query('INSERT IGNORE INTO enrollments (student_id, class_id) VALUES (?, ?)', [req.user.id, classId], (err) => {
    if (err) {
      console.error('Enrollment error:', err);
      if (err.code === 'ER_NO_REFERENCED_ROW') {
        return res.status(400).json({ message: 'Invalid class ID' });
      } else if (err.code === 'ER_DUP_ENTRY') {
        return res.status(400).json({ message: 'Already enrolled in this class' });
      }
      return res.status(500).json({ message: 'Error enrolling', error: err.message });
    }
    res.json({ message: 'Enrolled successfully' });
  });
});

// Get available classes (Student)
app.get('/api/available-classes', authenticate, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ message: 'Forbidden: Only students can view available classes' });
  const query = req.query.search ? %${req.query.search}% : '%';
  db.query(
    'SELECT cl.id, cl.name, c.name as course_name FROM classes cl JOIN courses c ON cl.course_id = c.id WHERE cl.name LIKE ? OR c.name LIKE ?',
    [query, query],
    (err, results) => {
      if (err) {
        console.error('Fetch available classes error:', err);
        return res.status(500).json({ message: 'Error fetching available classes', error: err.message });
      }
      res.json(results);
    }
  );
});

// Get enrolled classes (Student)
app.get('/api/my-enrollments', authenticate, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ message: 'Forbidden: Only students can view their enrollments' });
  const query = req.query.search ? %${req.query.search}% : '%';
  db.query(
    'SELECT cl.id, cl.name, c.name as course_name FROM enrollments e JOIN classes cl ON e.class_id = cl.id JOIN courses c ON cl.course_id = c.id WHERE e.student_id = ? AND (cl.name LIKE ? OR c.name LIKE ?)',
    [req.user.id, query, query],
    (err, results) => {
      if (err) {
        console.error('Fetch enrollments error:', err);
        return res.status(500).json({ message: 'Error fetching enrollments', error: err.message });
      }
      res.json(results);
    }
  );
});

// Submit report (Lecturer)
app.post('/api/reports', authenticate, (req, res) => {
  if (req.user.role !== 'lecturer') return res.status(403).json({ message: 'Forbidden: Only lecturers can submit reports' });
  const { classId, week, dateLecture, venue, scheduledTime, topic, learningOutcomes, recommendations, attendances } = req.body;
  if (!classId || !week || !dateLecture || !venue || !scheduledTime || !topic || !attendances) {
    return res.status(400).json({ message: 'Missing required fields' });
  }
  db.query('SELECT COUNT(*) as total FROM enrollments WHERE class_id = ?', [classId], (err, result) => {
    if (err) {
      console.error('Fetch enrollment count error:', err);
      return res.status(500).json({ message: 'Error fetching enrollment count', error: err.message });
    }
    const total = result[0].total || 0;
    const actual = attendances.filter(a => a.present).length;
    db.query(
      'INSERT INTO reports (class_id, week, date_lecture, venue, scheduled_time, topic, learning_outcomes, recommendations, actual_present, total_registered) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [classId, week, dateLecture, venue, scheduledTime, topic, learningOutcomes, recommendations, actual, total],
      (err, insertResult) => {
        if (err) {
          console.error('Create report error:', err);
          if (err.code === 'ER_NO_REFERENCED_ROW') {
            return res.status(400).json({ message: 'Invalid class ID' });
          }
          return res.status(500).json({ message: 'Error creating report', error: err.message });
        }
        const reportId = insertResult.insertId;
        const attendanceQueries = attendances.map(a => new Promise((resolve, reject) => {
          db.query('INSERT INTO attendance (report_id, student_id, present) VALUES (?, ?, ?)', [reportId, a.studentId, a.present ? 1 : 0], (err) => {
            if (err) reject(err);
            resolve();
          });
        }));
        Promise.all(attendanceQueries)
          .then(() => res.json({ message: 'Report created successfully' }))
          .catch(err => {
            console.error('Save attendance error:', err);
            res.status(500).json({ message: 'Error saving attendance', error: err.message });
          });
      }
    );
  });
});

// Get reports (Lecturer, Program Leader, Principal Lecturer)
app.get('/api/reports', authenticate, (req, res) => {
  if (!['lecturer', 'pl', 'prl'].includes(req.user.role)) {
    return res.status(403).json({ message: 'Forbidden: Only lecturers, Program Leaders, and Principal Lecturers can access reports' });
  }
  let sql = 'SELECT r.*, cl.name as class_name, c.faculty_name, c.name as course_name, c.code as course_code, u.name as lecturer_name FROM reports r JOIN classes cl ON r.class_id = cl.id JOIN courses c ON cl.course_id = c.id LEFT JOIN users u ON cl.lecturer_id = u.id';
  let params = [];
  if (req.user.role === 'lecturer') {
    sql += ' WHERE cl.lecturer_id = ?';
    params = [req.user.id];
  } else if (req.user.role === 'pl') {
    sql += ' WHERE r.prl_feedback IS NOT NULL';
  }
  const query = req.query.search ? %${req.query.search}% : '%';
  sql += params.length ? ' AND' : ' WHERE';
  sql += ' (r.topic LIKE ? OR r.venue LIKE ? OR cl.name LIKE ?)';
  params.push(query, query, query);
  console.log('Executing reports query:', sql, 'with params:', params);
  db.query(sql, params, (err, results) => {
    if (err) {
      console.error('Fetch reports error:', err);
      if (err.code === 'ER_NO_SUCH_TABLE') {
        return res.status(500).json({ message: 'Database table not found', error: err.message });
      } else if (err.code === 'ER_NO_REFERENCED_ROW') {
        return res.status(400).json({ message: 'Invalid data reference', error: err.message });
      } else if (err.code === 'ER_SYNTAX_ERROR') {
        return res.status(500).json({ message: 'Invalid SQL syntax', error: err.message });
      }
      return res.status(500).json({ message: 'Error fetching reports', error: err.message });
    }
    res.json(results);
  });
});

// Add feedback to report (Principal Lecturer)
app.put('/api/reports/:id/feedback', authenticate, (req, res) => {
  if (req.user.role !== 'prl') return res.status(403).json({ message: 'Forbidden: Only Principal Lecturers can add feedback' });
  const { feedback } = req.body;
  if (!feedback) return res.status(400).json({ message: 'Feedback is required' });
  db.query('UPDATE reports SET prl_feedback = ? WHERE id = ?', [feedback, req.params.id], (err, result) => {
    if (err) {
      console.error('Add feedback error:', err);
      if (err.code === 'ER_NO_SUCH_TABLE') {
        return res.status(500).json({ message: 'Database table not found', error: err.message });
      }
      return res.status(500).json({ message: 'Error adding feedback', error: err.message });
    }
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Report not found' });
    res.json({ message: 'Feedback added successfully' });
  });
});

// Get student attendance (Student)
app.get('/api/my-attendance', authenticate, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ message: 'Forbidden: Only students can view their attendance' });
  const query = req.query.search ? %${req.query.search}% : '%';
  db.query(
    'SELECT r.*, a.present, cl.name as class_name, c.name as course_name, c.code as course_code, r.actual_present, r.total_registered FROM attendance a JOIN reports r ON a.report_id = r.id JOIN classes cl ON r.class_id = cl.id JOIN courses c ON cl.course_id = c.id WHERE a.student_id = ? AND (r.topic LIKE ? OR cl.name LIKE ?)',
    [req.user.id, query, query],
    (err, results) => {
      if (err) {
        console.error('Fetch attendance error:', err);
        return res.status(500).json({ message: 'Error fetching attendance', error: err.message });
      }
      res.json(results);
    }
  );
});

// Submit report rating (Student)
app.post('/api/ratings', authenticate, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ message: 'Forbidden: Only students can submit ratings' });
  const { reportId, rating, comment } = req.body;
  if (!reportId || !rating || rating < 1 || rating > 5) {
    return res.status(400).json({ message: 'Invalid report ID or rating (must be 1-5)' });
  }
  db.query(
    'INSERT INTO ratings (user_id, report_id, rating, comment) VALUES (?, ?, ?, ?)',
    [req.user.id, reportId, rating, comment || ''],
    (err) => {
      if (err) {
        console.error('Add rating error:', err);
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: 'You have already rated this report' });
        } else if (err.code === 'ER_NO_REFERENCED_ROW') {
          return res.status(400).json({ message: 'Invalid report ID' });
        }
        return res.status(500).json({ message: 'Error adding rating', error: err.message });
      }
      res.json({ message: 'Rating submitted successfully' });
    }
  );
});

// Get report ratings (Lecturer)
app.get('/api/reports/:id/ratings', authenticate, (req, res) => {
  if (req.user.role !== 'lecturer') return res.status(403).json({ message: 'Forbidden: Only lecturers can view report ratings' });
  db.query(
    'SELECT r.*, u.name FROM ratings r JOIN users u ON r.user_id = u.id WHERE r.report_id = ? AND EXISTS (SELECT 1 FROM reports rep JOIN classes c ON rep.class_id = c.id WHERE rep.id = ? AND c.lecturer_id = ?)',
    [req.params.id, req.params.id, req.user.id],
    (err, results) => {
      if (err) {
        console.error('Fetch ratings error:', err);
        return res.status(500).json({ message: 'Error fetching ratings', error: err.message });
      }
      if (results.length === 0) {
        return res.status(404).json({ message: 'No ratings found for this report' });
      }
      res.json(results);
    }
  );
});

// Get report attendance (Lecturer)
app.get('/api/reports/:id/attendance', authenticate, (req, res) => {
  if (req.user.role !== 'lecturer') return res.status(403).json({ message: 'Forbidden: Only lecturers can view attendance' });
  db.query(
    'SELECT a.*, u.name FROM attendance a JOIN users u ON a.student_id = u.id WHERE a.report_id = ? AND EXISTS (SELECT 1 FROM reports r JOIN classes c ON r.class_id = c.id WHERE r.id = ? AND c.lecturer_id = ?)',
    [req.params.id, req.params.id, req.user.id],
    (err, results) => {
      if (err) {
        console.error('Fetch attendance error:', err);
        return res.status(500).json({ message: 'Error fetching attendance', error: err.message });
      }
      if (results.length === 0) {
        return res.status(404).json({ message: 'No attendance data found for this report' });
      }
      res.json(results);
    }
  );
});

// Submit lecturer rating (Student)
app.post('/api/lecturer-ratings', authenticate, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ message: 'Forbidden: Only students can rate lecturers' });
  const { lecturerId, rating, comment } = req.body;
  if (!lecturerId || !rating || rating < 1 || rating > 5) {
    return res.status(400).json({ message: 'Invalid lecturer ID or rating (must be 1-5)' });
  }
  db.query(
    'INSERT INTO lecturer_ratings (student_id, lecturer_id, rating, comment) VALUES (?, ?, ?, ?)',
    [req.user.id, lecturerId, rating, comment || ''],
    (err) => {
      if (err) {
        console.error('Add lecturer rating error:', err);
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: 'You have already rated this lecturer' });
        } else if (err.code === 'ER_NO_REFERENCED_ROW') {
          return res.status(400).json({ message: 'Invalid lecturer ID' });
        }
        return res.status(500).json({ message: 'Error adding lecturer rating', error: err.message });
      }
      res.json({ message: 'Lecturer rating submitted successfully' });
    }
  );
});

// Get lecturer ratings for a lecturer (Lecturer)
app.get('/api/lecturer-ratings/:lecturerId', authenticate, (req, res) => {
  if (req.user.role !== 'lecturer' || req.user.id !== parseInt(req.params.lecturerId)) {
    return res.status(403).json({ message: 'Forbidden: Lecturers can only view their own ratings' });
  }
  db.query(
    'SELECT lr.*, u.name AS student_name FROM lecturer_ratings lr JOIN users u ON lr.student_id = u.id WHERE lr.lecturer_id = ?',
    [req.params.lecturerId],
    (err, results) => {
      if (err) {
        console.error('Fetch lecturer ratings error:', err);
        return res.status(500).json({ message: 'Error fetching lecturer ratings', error: err.message });
      }
      res.json(results);
    }
  );
});

// Get all lecturer ratings (Principal Lecturer)
app.get('/api/lecturer-ratings', authenticate, (req, res) => {
  if (req.user.role !== 'prl') return res.status(403).json({ message: 'Forbidden: Only Principal Lecturers can view all lecturer ratings' });
  const query = req.query.search ? %${req.query.search}% : '%';
  db.query(
    'SELECT lr.*, u1.name AS lecturer_name, u2.name AS student_name FROM lecturer_ratings lr JOIN users u1 ON lr.lecturer_id = u1.id JOIN users u2 ON lr.student_id = u2.id WHERE u1.name LIKE ?',
    [query],
    (err, results) => {
      if (err) {
        console.error('Fetch all lecturer ratings error:', err);
        if (err.code === 'ER_NO_SUCH_TABLE') {
          return res.status(500).json({ message: 'Database table not found', error: err.message });
        }
        return res.status(500).json({ message: 'Error fetching lecturer ratings', error: err.message });
      }
      res.json(results);
    }
  );
});

// Get lecturers for a student (Student)
app.get('/api/my-lecturers', authenticate, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ message: 'Forbidden: Only students can view their lecturers' });
  db.query(
    'SELECT DISTINCT u.id, u.name FROM users u JOIN classes c ON u.id = c.lecturer_id JOIN enrollments e ON c.id = e.class_id WHERE e.student_id = ?',
    [req.user.id],
    (err, results) => {
      if (err) {
        console.error('Fetch my lecturers error:', err);
        return res.status(500).json({ message: 'Error fetching lecturers', error: err.message });
      }
      res.json(results);
    }
  );
});

// Export reports (Program Leader, Principal Lecturer)
app.get('/api/reports/export', authenticate, async (req, res) => {
  if (!['pl', 'prl'].includes(req.user.role)) {
    return res.status(403).json({ message: 'Forbidden: Only Program Leaders and Principal Lecturers can export reports' });
  }
  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet('Reports');
  worksheet.columns = [
    { header: 'ID', key: 'id', width: 10 },
    { header: 'Class Name', key: 'class_name', width: 20 },
    { header: 'Week', key: 'week', width: 10 },
    { header: 'Date', key: 'date_lecture', width: 15 },
    { header: 'Venue', key: 'venue', width: 20 },
    { header: 'Time', key: 'scheduled_time', width: 15 },
    { header: 'Topic', key: 'topic', width: 30 },
    { header: 'Outcomes', key: 'learning_outcomes', width: 30 },
    { header: 'Recommendations', key: 'recommendations', width: 30 },
    { header: 'Present', key: 'actual_present', width: 10 },
    { header: 'Total', key: 'total_registered', width: 10 },
    { header: 'Feedback', key: 'prl_feedback', width: 30 },
  ];

  let sql = 'SELECT r.*, cl.name as class_name FROM reports r JOIN classes cl ON r.class_id = cl.id';
  let params = [];
  if (req.user.role === 'pl') {
    sql += ' WHERE r.prl_feedback IS NOT NULL';
  }

  db.query(sql, params, (err, results) => {
    if (err) {
      console.error('Export reports error:', err);
      return res.status(500).json({ message: 'Error exporting reports', error: err.message });
    }
    worksheet.addRows(results);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', 'attachment; filename=reports.xlsx');
    workbook.xlsx.write(res).then(() => res.end());
  });
});

// Mark attendance (Student)
app.post('/api/attendance', authenticate, (req, res) => {
  if (req.user.role !== 'student') {
    return res.status(403).json({ message: 'Forbidden: Only students can mark attendance' });
  }
  const { classId, date } = req.body;
  if (!classId || !date) {
    return res.status(400).json({ message: 'Class ID and date are required' });
  }

  // Check if the student is enrolled in the class
  db.query(
    'SELECT * FROM enrollments WHERE student_id = ? AND class_id = ?',
    [req.user.id, classId],
    (err, enrollmentResults) => {
      if (err) {
        console.error('Enrollment check error:', err);
        return res.status(500).json({ message: 'Error checking enrollment', error: err.message });
      }
      if (enrollmentResults.length === 0) {
        return res.status(400).json({ message: 'You are not enrolled in this class' });
      }

      // Check if a report exists for the class and date
      db.query(
        'SELECT * FROM reports WHERE class_id = ? AND date_lecture = ?',
        [classId, date],
        (err, reportResults) => {
          if (err) {
            console.error('Report check error:', err);
            return res.status(500).json({ message: 'Error checking report', error: err.message });
          }

          let reportId;
          if (reportResults.length > 0) {
            reportId = reportResults[0].id;
          } else {
            // Create a new report if none exists
            db.query(
              'INSERT INTO reports (class_id, week, date_lecture, venue, scheduled_time, topic, learning_outcomes, recommendations, actual_present, total_registered) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
              [classId, 0, date, 'TBD', 'TBD', 'Student-marked attendance', '', '', 1, 1],
              (err, insertResult) => {
                if (err) {
                  console.error('Create report error:', err);
                  return res.status(500).json({ message: 'Error creating report', error: err.message });
                }
                reportId = insertResult.insertId;
                insertAttendance();
              }
            );
            return;
          }

          insertAttendance();

          function insertAttendance() {
            // Insert attendance record
            db.query(
              'INSERT IGNORE INTO attendance (report_id, student_id, present) VALUES (?, ?, ?)',
              [reportId, req.user.id, 1],
              (err) => {
                if (err) {
                  console.error('Attendance insert error:', err);
                  if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ message: 'Attendance already marked for this date' });
                  }
                  return res.status(500).json({ message: 'Error marking attendance', error: err.message });
                }
                // Update report's actual_present count
                db.query(
                  'UPDATE reports SET actual_present = (SELECT COUNT(*) FROM attendance WHERE report_id = ? AND present = 1) WHERE id = ?',
                  [reportId, reportId],
                  (err) => {
                    if (err) {
                      console.error('Update report error:', err);
                      return res.status(500).json({ message: 'Error updating report', error: err.message });
                    }
                    res.json({ message: 'Attendance marked successfully' });
                  }
                );
              }
            );
          }
        }
      );
    }
  );
});

const PORT = process.env.PORT || 10000; // Updated to match Render logs
app.listen(PORT, () => console.log(Backend running on http://localhost:${PORT}));
