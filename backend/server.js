const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const ExcelJS = require('exceljs');

const app = express();

// Enhanced CORS configuration
app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:3000',
      'https://luct-reporting.vercel.app',
      'https://luct-reporting-frontend.vercel.app',
      'https://luct-reporting-git-main-yourusername.vercel.app'
    ];
    
    if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV === 'development') {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.options('*', cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Fixed Database configuration - removed invalid options
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'luct_reporting',
  port: process.env.DB_PORT || 3306,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  // Valid connection options for mysql2
  connectTimeout: 60000,
  acquireTimeout: 60000, // This is valid for createPool, not createConnection
  timeout: 60000, // This is valid for createPool, not createConnection
  reconnect: true, // This is valid for createPool, not createConnection
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
};

console.log('Database Configuration Loaded');
console.log('Environment:', process.env.NODE_ENV || 'development');

// Use createPool instead of createConnection for better performance
const db = mysql.createPool(dbConfig);

// Test database connection
db.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
    console.log('Please check your database configuration and ensure it is running.');
  } else {
    console.log('✅ MySQL Connected successfully');
    connection.release();
  }
});

// Handle pool errors
db.on('error', (err) => {
  console.error('❌ Database pool error:', err);
  if (err.code === 'PROTOCOL_CONNECTION_LOST') {
    console.log('Database connection was lost. Attempting to reconnect...');
  } else {
    throw err;
  }
});

const SECRET = process.env.JWT_SECRET || 'your_fallback_secret_key_change_in_production';

// Health check endpoint
app.get('/health', (req, res) => {
  db.getConnection((err, connection) => {
    if (err) {
      res.status(500).json({ 
        status: 'ERROR', 
        database: 'Disconnected',
        error: err.message,
        timestamp: new Date().toISOString()
      });
    } else {
      connection.ping((pingErr) => {
        connection.release();
        if (pingErr) {
          res.status(500).json({ 
            status: 'ERROR', 
            database: 'Ping failed',
            error: pingErr.message 
          });
        } else {
          res.status(200).json({ 
            status: 'OK', 
            database: 'Connected',
            environment: process.env.NODE_ENV || 'development',
            timestamp: new Date().toISOString()
          });
        }
      });
    }
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: '🚀 LUCT Reporting API is running',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString(),
    database: 'MySQL with Connection Pooling',
    endpoints: {
      auth: '/api/login, /api/register',
      courses: '/api/courses',
      classes: '/api/classes',
      reports: '/api/reports',
      health: '/health'
    }
  });
});

// API info endpoint
app.get('/api', (req, res) => {
  res.json({
    name: 'LUCT Reporting System API',
    version: '1.0.0',
    status: 'active',
    database: 'MySQL with Pooling',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Authentication middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  
  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
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

  try {
    const hashed = await bcrypt.hash(password, 10);
    
    db.query(
      'INSERT INTO users (role, name, identifier, password) VALUES (?, ?, ?, ?)',
      [role, name, identifier, hashed],
      (err, result) => {
        if (err) {
          console.error('Registration error:', err);
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: 'Identifier already exists' });
          }
          return res.status(500).json({ message: 'Error registering user', error: err.message });
        }
        
        res.json({ 
          message: 'Registered successfully',
          user: { id: result.insertId, name, identifier, role }
        });
      }
    );
  } catch (hashError) {
    console.error('Hashing error:', hashError);
    res.status(500).json({ message: 'Error processing password' });
  }
});

// Login endpoint
app.post('/api/login', (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ message: 'Missing identifier or password' });
  }

  db.query(
    'SELECT * FROM users WHERE identifier = ?', 
    [identifier], 
    async (err, results) => {
      if (err) {
        console.error('Login query error:', err);
        return res.status(500).json({ message: 'Error querying database' });
      }
      
      if (results.length === 0) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      
      const user = results[0];

      try {
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
          return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign(
          { id: user.id, role: user.role, identifier: user.identifier }, 
          SECRET, 
          { expiresIn: '24h' }
        );

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

// Get courses
app.get('/api/courses', authenticate, (req, res) => {
  const query = req.query.search ? `%${req.query.search}%` : '%';
  
  db.query(
    'SELECT * FROM courses WHERE name LIKE ? OR code LIKE ? OR faculty_name LIKE ? ORDER BY name',
    [query, query, query],
    (err, results) => {
      if (err) {
        console.error('Fetch courses error:', err);
        return res.status(500).json({ message: 'Error fetching courses' });
      }
      res.json(results);
    }
  );
});

// Add more endpoints here (keep your existing classes, reports, etc. endpoints)
// Just make sure they use the db pool

// Error handling
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    message: 'Endpoint not found',
    path: req.originalUrl
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📍 Health check: http://localhost:${PORT}/health`);
  console.log(`📊 Database: Connection Pool Active`);
});
