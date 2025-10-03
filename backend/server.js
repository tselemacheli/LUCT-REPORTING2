const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const ExcelJS = require('exceljs');

const app = express();

// Enhanced CORS configuration for production
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:3000',
      'https://luct-reporting.vercel.app',
      'https://luct-reporting-frontend.vercel.app'
    ];
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      // Allow any origin in development
      if (process.env.NODE_ENV === 'development') {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Handle preflight requests
app.options('*', cors());

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Database configuration for production
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'luct_reporting',
  port: process.env.DB_PORT || 3306,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  connectTimeout: 60000,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true,
  multipleStatements: false
};

console.log('Database Config:', {
  host: dbConfig.host,
  user: dbConfig.user,
  database: dbConfig.database,
  port: dbConfig.port,
  environment: process.env.NODE_ENV
});

const db = mysql.createPool(dbConfig);

// Test database connection
db.getConnection((err, connection) => {
  if (err) {
    console.error('Database connection failed:', err.message);
    console.log('Retrying connection...');
  } else {
    console.log('MySQL Connected successfully');
    connection.release();
  }
});

db.on('error', (err) => {
  console.error('Database error:', err);
  if (err.code === 'PROTOCOL_CONNECTION_LOST') {
    console.log('Database connection was lost. Reconnecting...');
  } else {
    throw err;
  }
});

const SECRET = process.env.JWT_SECRET || 'your_secret_key_change_in_production';

// Health check endpoint
app.get('/health', (req, res) => {
  db.getConnection((err, connection) => {
    if (err) {
      res.status(500).json({ 
        status: 'ERROR', 
        database: 'Disconnected',
        error: err.message 
      });
    } else {
      connection.ping((pingErr) => {
        connection.release();
        if (pingErr) {
          res.status(500).json({ 
            status: 'ERROR', 
            database: 'Connection failed',
            error: pingErr.message 
          });
        } else {
          res.status(200).json({ 
            status: 'OK', 
            database: 'Connected',
            timestamp: new Date().toISOString(),
            environment: process.env.NODE_ENV || 'development'
          });
        }
      });
    }
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'LUCT Reporting API is running',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: '/api/login, /api/register',
      courses: '/api/courses',
      classes: '/api/classes',
      reports: '/api/reports'
    }
  });
});

// API info endpoint
app.get('/api', (req, res) => {
  res.json({
    name: 'LUCT Reporting System API',
    version: '1.0.0',
    description: 'Backend API for Limkokwing University Reporting System',
    status: 'active'
  });
});

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  
  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err.message);
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    console.log('Authenticated user:', req.user);
    next();
  });
};

// Register endpoint
app.post('/api/register', async (req, res) => {
  const { name, password, identifier, role } = req.body;
  
  console.log('Registration attempt:', { identifier, role, name: name?.substring(0, 3) + '...' });

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

  if (!identifier || (role === 'student' && !/^\d+$/.test(identifier)) || 
      (['lecturer', 'pl', 'prl'].includes(role) && !/^[A-Za-z0-9]+$/.test(identifier))) {
    return res.status(400).json({ message: 'Invalid identifier format' });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    
    db.query(
      'INSERT INTO users (role, name, identifier, password) VALUES (?, ?, ?, ?)',
      [role, name, identifier, hashed],
      (err, result) => {
        if (err) {
          console.error('Registration database error:', err);
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: 'Identifier already exists' });
          } else if (err.code === 'ER_NO_SUCH_TABLE') {
            return res.status(500).json({ message: 'Database table not found' });
          }
          return res.status(500).json({ message: 'Error registering user', error: err.message });
        }
        
        console.log('User registered successfully:', { id: result.insertId, identifier, role });
        res.json({ 
          message: 'Registered successfully',
          user: { id: result.insertId, name, identifier, role }
        });
      }
    );
  } catch (hashError) {
    console.error('Hashing error:', hashError);
    res.status(500).json({ message: 'Error processing password', error: hashError.message });
  }
});

// Login endpoint
app.post('/api/login', (req, res) => {
  const { identifier, password } = req.body;
  
  console.log('Login attempt:', { identifier });

  if (!identifier || !password) {
    return res.status(400).json({ message: 'Missing identifier or password' });
  }

  db.query(
    'SELECT * FROM users WHERE identifier = ?', 
    [identifier], 
    async (err, results) => {
      if (err) {
        console.error('Login query error:', err);
        return res.status(500).json({ message: 'Error querying database', error: err.message });
      }
      
      if (results.length === 0) {
        console.log('Login failed: User not found', { identifier });
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      
      const user = results[0];
      console.log('User found:', { id: user.id, role: user.role, name: user.name });

      try {
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
          console.log('Login failed: Password mismatch', { identifier });
          return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign(
          { id: user.id, role: user.role, identifier: user.identifier }, 
          SECRET, 
          { expiresIn: '24h' }
        );

        console.log('Login successful:', { id: user.id, role: user.role });
        res.json({ 
          token, 
          role: user.role,
          user: {
            id: user.id,
            name: user.name,
            identifier: user.identifier
          }
        });
      } catch (compareError) {
        console.error('Password comparison error:', compareError);
        res.status(500).json({ message: 'Error validating credentials' });
      }
    }
  );
});

// Get lecturers (for Program Leader)
app.get('/api/lecturers', authenticate, (req, res) => {
  if (req.user.role !== 'pl') {
    return res.status(403).json({ message: 'Forbidden: Only Program Leaders can access this' });
  }
  
  db.query(
    'SELECT id, name, identifier FROM users WHERE role = "lecturer"', 
    (err, results) => {
      if (err) {
        console.error('Fetch lecturers error:', err);
        return res.status(500).json({ message: 'Error fetching lecturers', error: err.message });
      }
      res.json(results);
    }
  );
});

// Add course (Program Leader)
app.post('/api/courses', authenticate, (req, res) => {
  if (req.user.role !== 'pl') {
    return res.status(403).json({ message: 'Forbidden: Only Program Leaders can add courses' });
  }
  
  const { name, code, facultyName } = req.body;
  if (!name || !code || !facultyName) {
    return res.status(400).json({ message: 'Missing required fields' });
  }
  
  db.query(
    'INSERT INTO courses (name, code, faculty_name) VALUES (?, ?, ?)', 
    [name, code, facultyName], 
    (err, result) => {
      if (err) {
        console.error('Add course error:', err);
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: 'Course code already exists' });
        }
        return res.status(500).json({ message: 'Error adding course', error: err.message });
      }
      
      res.json({ 
        message: 'Course added successfully',
        course: { id: result.insertId, name, code, facultyName }
      });
    }
  );
});

// Get courses (Program Leader, Principal Lecturer)
app.get('/api/courses', authenticate, (req, res) => {
  const query = req.query.search ? `%${req.query.search}%` : '%';
  
  db.query(
    'SELECT * FROM courses WHERE name LIKE ? OR code LIKE ? OR faculty_name LIKE ? ORDER BY name',
    [query, query, query],
    (err, results) => {
      if (err) {
        console.error('Fetch courses error:', err);
        return res.status(500).json({ message: 'Error fetching courses', error: err.message });
      }
      res.json(results);
    }
  );
});

// Add class (Program Leader)
app.post('/api/classes', authenticate, (req, res) => {
  if (req.user.role !== 'pl') {
    return res.status(403).json({ message: 'Forbidden: Only Program Leaders can add classes' });
  }
  
  const { name, courseId, lecturerId } = req.body;
  if (!name || !courseId || !lecturerId) {
    return res.status(400).json({ message: 'Missing required fields' });
  }
  
  db.query(
    'INSERT INTO classes (name, course_id, lecturer_id) VALUES (?, ?, ?)',
    [name, courseId, lecturerId],
    (err, result) => {
      if (err) {
        console.error('Add class error:', err);
        if (err.code === 'ER_NO_REFERENCED_ROW') {
          return res.status(400).json({ message: 'Invalid course or lecturer ID' });
        }
        return res.status(500).json({ message: 'Error adding class', error: err.message });
      }
      
      res.json({ 
        message: 'Class added successfully',
        class: { id: result.insertId, name, courseId, lecturerId }
      });
    }
  );
});

// Get classes (Lecturer, Program Leader, Principal Lecturer)
app.get('/api/classes', authenticate, (req, res) => {
  let sql = `
    SELECT cl.*, c.name as course_name, c.code as course_code, c.faculty_name, 
           u.name as lecturer_name, u.identifier as lecturer_identifier
    FROM classes cl 
    JOIN courses c ON cl.course_id = c.id 
    LEFT JOIN users u ON cl.lecturer_id = u.id
  `;
  
  let params = [];
  const searchQuery = req.query.search ? `%${req.query.search}%` : '%';
  
  if (req.user.role === 'lecturer') {
    sql += ' WHERE cl.lecturer_id = ? AND (cl.name LIKE ? OR c.name LIKE ?)';
    params = [req.user.id, searchQuery, searchQuery];
  } else {
    sql += ' WHERE (cl.name LIKE ? OR c.name LIKE ?)';
    params = [searchQuery, searchQuery];
  }
  
  sql += ' ORDER BY cl.name';
  
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
  const classId = req.params.id;
  
  db.query(
    `SELECT cl.*, c.name as course_name, c.code as course_code, c.faculty_name, 
            u.name as lecturer_name, u.identifier as lecturer_identifier 
     FROM classes cl 
     JOIN courses c ON cl.course_id = c.id 
     LEFT JOIN users u ON cl.lecturer_id = u.id 
     WHERE cl.id = ?`,
    [classId],
    (err, results) => {
      if (err) {
        console.error('Fetch class details error:', err);
        return res.status(500).json({ message: 'Error fetching class details', error: err.message });
      }
      
      if (results.length === 0) {
        return res.status(404).json({ message: 'Class not found' });
      }
      
      const classInfo = results[0];
      
      // Check if lecturer is authorized to view this class
      if (req.user.role === 'lecturer' && classInfo.lecturer_id !== req.user.id) {
        return res.status(403).json({ message: 'Access denied to this class' });
      }
      
      db.query(
        'SELECT u.id, u.name, u.identifier FROM enrollments e JOIN users u ON e.student_id = u.id WHERE e.class_id = ?',
        [classId],
        (err, students) => {
          if (err) {
            console.error('Fetch students error:', err);
            return res.status(500).json({ message: 'Error fetching students', error: err.message });
          }
          
          classInfo.students = students;
          classInfo.total_registered = students.length;
          
          res.json(classInfo);
        }
      );
    }
  );
});

// [Keep all your other existing routes exactly as they were...]
// Enroll in class, Get available classes, Submit report, etc.
// Just ensure they use the db pool instead of direct connection

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    message: 'Endpoint not found',
    path: req.originalUrl,
    method: req.method
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔍 API info: http://localhost:${PORT}/api`);
});
