import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import Joi from 'joi';
import session from 'express-session';
import csrf from 'csrf';
import path from 'path';
import { appLogger, securityLogger, logSecurityEvent, SecurityEvents } from './logger.js';

// Load server environment variables
dotenv.config({ path: '.env.server' });

// Validate required environment variables
const requiredEnvVars = [
  'ACCESS_PASSWORD',
  'ANSWER_1', 
  'ANSWER_2',
  'ANSWER_3', 
  'ANSWER_4',
  'SECRET_CODE',
  'JWT_SECRET',
  'SESSION_SECRET',
  'CSRF_SECRET'
];

const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingEnvVars.join(', '));
  console.error('Please check your .env.server file');
  console.error('Copy .env.server.example to .env.server and fill in the values');
  process.exit(1);
}

// Extract environment variables after validation
const JWT_SECRET = process.env.JWT_SECRET!;
const SESSION_SECRET = process.env.SESSION_SECRET!;
const CSRF_SECRET = process.env.CSRF_SECRET!;
const ACCESS_PASSWORD = process.env.ACCESS_PASSWORD!;

// Validate JWT and session secret lengths for security
if (JWT_SECRET.length < 32) {
  console.error('❌ JWT_SECRET must be at least 32 characters long for security');
  process.exit(1);
}

if (SESSION_SECRET.length < 32) {
  console.error('❌ SESSION_SECRET must be at least 32 characters long for security');
  process.exit(1);
}

if (CSRF_SECRET.length < 32) {
  console.error('❌ CSRF_SECRET must be at least 32 characters long for security');
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize CSRF protection
const tokens = new csrf();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
    },
  },
}));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: { error: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logSecurityEvent('RATE_LIMIT_HIT', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.path,
      additional: { limit: 5, windowMs: 15 * 60 * 1000 }
    });
    res.status(429).json({ error: 'Too many login attempts, please try again later.' });
  }
});

// CORS with credentials
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.RENDER_EXTERNAL_URL || 'https://jurassic-security.onrender.com'
    : 'http://localhost:5173',
  credentials: true,
}));

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'strict'
  },
  name: 'quiz_session', // Custom session name
  rolling: true // Reset expiration on activity
}));

// Free tier session handling improvements
app.use((req, res, next) => {
  // Update session activity more frequently on free tier to prevent data loss
  if (process.env.RENDER && !process.env.RENDER_SERVICE_PLAN) {
    // This is a free tier Render service
    if (req.session.isAuthenticated) {
      req.session.lastActivity = Date.now();
    }
  }
  next();
});

// Request logging middleware
app.use((req, res, next) => {
  const startTime = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    appLogger.info({
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      responseTime: duration,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      sessionId: req.sessionID
    });
  });
  
  next();
});

// Session security monitoring middleware
app.use((req, res, next) => {
  // Check for potential session hijacking
  if (req.session.userId && req.session.lastActivity) {
    const timeSinceLastActivity = Date.now() - req.session.lastActivity;
    const userAgent = req.get('User-Agent');
    
    // Log suspicious session activity (more than 12 hours inactive but session still valid)
    if (timeSinceLastActivity > 12 * 60 * 60 * 1000) {
      logSecurityEvent('SESSION_EXPIRED', {
        ip: req.ip,
        userAgent: userAgent,
        userId: req.session.userId,
        endpoint: req.path,
        additional: { 
          sessionId: req.sessionID,
          timeSinceLastActivity,
          suspiciousActivity: 'Long inactive session reactivated'
        }
      });
    }
  }
  
  next();
});

// CSRF protection middleware
const csrfProtection = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  // Skip CSRF for GET requests and token endpoint
  if (req.method === 'GET' || req.path === '/api/csrf-token') {
    return next();
  }

  const token = req.headers['x-csrf-token'] as string || req.body._csrf;
  
  if (!token) {
    logSecurityEvent('CSRF_TOKEN_MISSING', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.path,
      additional: { method: req.method }
    });
    return res.status(403).json({ error: 'CSRF token required' });
  }

  // Get or create CSRF secret in session
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = tokens.secretSync();
  }

  const isValid = tokens.verify(req.session.csrfSecret, token);
  
  if (!isValid) {
    logSecurityEvent('CSRF_TOKEN_INVALID', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.path,
      additional: { method: req.method, sessionId: req.sessionID }
    });
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  next();
};

// Extend session types
declare module 'express-session' {
  interface SessionData {
    userId?: string;
    loginTime?: number;
    lastActivity?: number;
    isAuthenticated?: boolean;
    csrfSecret?: string;
  }
}

// Types
interface Question {
  id: number;
  text: string;
  icon: string;
}

interface AuthRequest extends express.Request {
  userId?: string;
}

// Quiz questions (without answers)
const questions: Question[] = [
  {
    id: 1,
    text: "How many flasks are in the lab?",
    icon: "fa-flask"
  },
  {
    id: 2,
    text: "How many test tubes are on the rack?",
    icon: "fa-vial"
  },
  {
    id: 3,
    text: "What is the emergency evacuation code?",
    icon: "fa-door-open"
  },
  {
    id: 4,
    text: "How many security cameras monitor the perimeter?",
    icon: "fa-video"
  }
];

// Server-side answers (secure) - all validated to exist above
const correctAnswers: Record<number, string> = {
  1: process.env.ANSWER_1!,
  2: process.env.ANSWER_2!, 
  3: process.env.ANSWER_3!,
  4: process.env.ANSWER_4!
};

// Middleware to verify JWT token and session
const authenticateToken = (req: AuthRequest, res: express.Response, next: express.NextFunction) => {
  const token = req.cookies.auth_token;

  // Check if session exists and is authenticated
  if (!req.session.isAuthenticated || !req.session.userId) {
    logSecurityEvent('UNAUTHORIZED_ACCESS', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.path,
      additional: { reason: 'No valid session', sessionId: req.sessionID }
    });
    return res.status(401).json({ error: 'Session required' });
  }

  if (!token) {
    logSecurityEvent('UNAUTHORIZED_ACCESS', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.path,
      additional: { reason: 'No auth token provided', sessionId: req.sessionID }
    });
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) {
      // Destroy session on invalid token
      req.session.destroy(() => {});
      logSecurityEvent('INVALID_TOKEN', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.path,
        additional: { reason: err.message, sessionId: req.sessionID }
      });
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    
    // Update session activity
    req.session.lastActivity = Date.now();
    req.userId = user.userId;
    next();
  });
};

// Input validation schemas
const loginSchema = Joi.object({
  password: Joi.string().min(1).max(200).required().trim()
});

const answerSchema = Joi.object({
  answer: Joi.string().min(1).max(100).required().trim()
});

// CSRF token endpoint
app.get('/api/csrf-token', (req, res) => {
  // Get or create CSRF secret in session
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = tokens.secretSync();
  }
  
  const csrfToken = tokens.create(req.session.csrfSecret);
  
  res.json({ csrfToken });
});

// Auth endpoint - login with password (with rate limiting)
app.post('/api/auth/login', authLimiter, csrfProtection, (req, res) => {
  // Validate input
  const { error, value } = loginSchema.validate(req.body);
  if (error) {
    logSecurityEvent('SUSPICIOUS_REQUEST', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: '/api/auth/login',
      additional: { reason: 'Invalid input validation', error: error.details[0].message }
    });
    return res.status(400).json({ error: 'Invalid input: ' + error.details[0].message });
  }

  const { password } = value;

  if (password !== ACCESS_PASSWORD) {
    logSecurityEvent('LOGIN_FAILURE', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: '/api/auth/login',
      additional: { reason: 'Invalid password' }
    });
    return res.status(401).json({ error: 'Invalid password' });
  }

  // Generate JWT token
  const token = jwt.sign(
    { userId: 'quiz-user' },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  // Set httpOnly cookie
  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  });

  // Initialize session
  req.session.userId = 'quiz-user';
  req.session.loginTime = Date.now();
  req.session.lastActivity = Date.now();
  req.session.isAuthenticated = true;

  logSecurityEvent('LOGIN_SUCCESS', {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: 'quiz-user',
    endpoint: '/api/auth/login',
    additional: { sessionId: req.sessionID }
  });

  res.json({ 
    success: true,
    message: 'Authentication successful'
  });
});

// Get questions (protected)
app.get('/api/questions', authenticateToken, (req: AuthRequest, res) => {
  res.json({ questions });
});

// Logout endpoint
app.post('/api/auth/logout', csrfProtection, (req, res) => {
  const sessionId = req.sessionID;
  const userId = req.session.userId;
  
  // Destroy session
  req.session.destroy((err) => {
    if (err) {
      appLogger.error('Session destruction failed', { error: err, sessionId });
    }
  });
  
  res.clearCookie('auth_token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
  
  res.clearCookie('quiz_session', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });

  logSecurityEvent('LOGIN_SUCCESS', {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: userId,
    endpoint: '/api/auth/logout',
    additional: { sessionId, action: 'logout' }
  });
  
  res.json({ success: true, message: 'Logged out successfully' });
});

// Submit answer (protected)
app.post('/api/questions/:questionId/answer', authenticateToken, csrfProtection, (req: AuthRequest, res) => {
  const questionId = parseInt(req.params.questionId);
  
  // Validate question ID
  if (isNaN(questionId) || !correctAnswers[questionId]) {
    return res.status(404).json({ error: 'Question not found' });
  }

  // Validate input
  const { error, value } = answerSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: 'Invalid input: ' + error.details[0].message });
  }

  const { answer } = value;
  const isCorrect = answer === correctAnswers[questionId];

  res.json({
    correct: isCorrect,
    message: isCorrect ? 'Correct!' : 'Incorrect answer'
  });
});

// Get secret code (protected, only after all questions answered correctly)
app.get('/api/completion', authenticateToken, (req: AuthRequest, res) => {
  res.json({
    secretCode: process.env.SECRET_CODE!,
    message: 'Congratulations! You\'ve completed the security clearance test.'
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server is running', timestamp: new Date().toISOString() });
});

// Serve React app in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../dist')));
  
  // Handle React Router - serve index.html for all non-API routes
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../dist/index.html'));
  });
}

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔒 Authentication endpoint: http://localhost:${PORT}/api/auth/login`);
});

export default app;