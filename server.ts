import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import Joi from 'joi';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import { appLogger, securityLogger, logSecurityEvent, SecurityEvents } from './logger.js';

// ES module equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load server environment variables
dotenv.config({ path: '.env.server' });

// Validate required environment variables
const requiredEnvVars = [
  'ANSWER_TREX_EYES',
  'ANSWER_MECHANIC_1',
  'ANSWER_MECHANIC_2',
  'ANSWER_MECHANIC_3',
  'ANSWER_ENGINEER_1',
  'ANSWER_ENGINEER_2',
  'ANSWER_ENGINEER_3',
  'ANSWER_SECURITY_1',
  'ANSWER_SECURITY_2',
  'ANSWER_SECURITY_3',
  'ANSWER_SPONSOR_1',
  'ANSWER_SPONSOR_2',
  'ANSWER_SPONSOR_3',
  'ANSWER_JANITOR_1',
  'ANSWER_JANITOR_2',
  'ANSWER_JANITOR_3',
  'ANSWER_LAWYER_1',
  'ANSWER_LAWYER_2',
  'ANSWER_LAWYER_3',
  'ANSWER_TRAINER_1',
  'ANSWER_TRAINER_2',
  'ANSWER_TRAINER_3',
  'ANSWER_MOSQUITO_YEAR',
  'ANSWER_MILLILITERS',
  'ANSWER_LAB_CODE',
  'SECRET_CODE',
  'SESSION_SECRET'
];

const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingEnvVars.join(', '));
  console.error('Please check your .env.server file');
  console.error('Copy .env.server.example to .env.server and fill in the values');
  process.exit(1);
}

// Extract environment variables after validation
const SESSION_SECRET = process.env.SESSION_SECRET!;

// Validate session secret length for security
if (SESSION_SECRET.length < 32) {
  console.error('❌ SESSION_SECRET must be at least 32 characters long for security');
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
      manifestSrc: ["'self'"],
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
    : ['http://localhost:5173', 'http://localhost:5174'],
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
    secure: false, // Temporarily disable for debugging
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax'
  },
  name: 'quiz_session', // Custom session name
  rolling: true // Reset expiration on activity
}));


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



// Extend session types
declare module 'express-session' {
  interface SessionData {
    userId?: string;
    isAuthenticated?: boolean;
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

// All available questions
const allQuestions: Question[] = [
  {
    id: 1,
    text: "What color are the T-Rex's eyes?",
    icon: "fa-eye"
  },
  {
    id: 2,
    text: "Get a Mechanic access code",
    icon: "fa-wrench"
  },
  {
    id: 3,
    text: "Get an Engineer access code",
    icon: "fa-hard-hat"
  },
  {
    id: 4,
    text: "Get a Security Guard access code",
    icon: "fa-shield-halved"
  },
  {
    id: 5,
    text: "Get a Park Sponsor access code",
    icon: "fa-briefcase"
  },
  {
    id: 6,
    text: "Get a Janitor access code",
    icon: "fa-broom"
  },
  {
    id: 7,
    text: "Get a Lawyer access code",
    icon: "fa-scale-balanced"
  },
  {
    id: 8,
    text: "Get a Dinosaur Trainer access code",
    icon: "fa-graduation-cap"
  },
  {
    id: 9,
    text: "What year was this park's mosquito fossilized?",
    icon: "fa-mosquito"
  },
  {
    id: 10,
    text: "How many milliliters of liquid are in all the lab glassware total?",
    icon: "fa-flask"
  },
  {
    id: 11,
    text: "Lab personnel access code required to report all findings + finish test",
    icon: "fa-key"
  }
];

// Access code question IDs (one will be randomly selected)
const accessCodeQuestionIds = [2, 3, 4, 5, 6, 7, 8];

// Generate random question set for a session
function getRandomQuestions(): Question[] {
  // Pick 3 random access code questions
  const shuffled = [...accessCodeQuestionIds].sort(() => Math.random() - 0.5);
  const randomAccessCodeIds = shuffled.slice(0, 3);

  // Build the question set: fixed questions + 3 random access code questions
  const selectedQuestions = [
    allQuestions.find(q => q.id === 1)!,  // T-Rex eyes
    allQuestions.find(q => q.id === randomAccessCodeIds[0])!,  // Random access code 1
    allQuestions.find(q => q.id === randomAccessCodeIds[1])!,  // Random access code 2
    allQuestions.find(q => q.id === randomAccessCodeIds[2])!,  // Random access code 3
    allQuestions.find(q => q.id === 9)!,  // Mosquito year
    allQuestions.find(q => q.id === 10)!, // Milliliters
    allQuestions.find(q => q.id === 11)!, // Lab personnel (always last)
  ];

  return selectedQuestions;
}

// Server-side answers (secure) - all validated to exist above
// Questions with single answer
const correctAnswers: Record<number, string> = {
  1: process.env.ANSWER_TREX_EYES!,
  9: process.env.ANSWER_MOSQUITO_YEAR!,
  10: process.env.ANSWER_MILLILITERS!,
  11: process.env.ANSWER_LAB_CODE!
};

// Questions with multiple possible correct answers (any one of these is correct)
const multipleCorrectAnswers: Record<number, string[]> = {
  2: [process.env.ANSWER_MECHANIC_1!, process.env.ANSWER_MECHANIC_2!, process.env.ANSWER_MECHANIC_3!],
  3: [process.env.ANSWER_ENGINEER_1!, process.env.ANSWER_ENGINEER_2!, process.env.ANSWER_ENGINEER_3!],
  4: [process.env.ANSWER_SECURITY_1!, process.env.ANSWER_SECURITY_2!, process.env.ANSWER_SECURITY_3!],
  5: [process.env.ANSWER_SPONSOR_1!, process.env.ANSWER_SPONSOR_2!, process.env.ANSWER_SPONSOR_3!],
  6: [process.env.ANSWER_JANITOR_1!, process.env.ANSWER_JANITOR_2!, process.env.ANSWER_JANITOR_3!],
  7: [process.env.ANSWER_LAWYER_1!, process.env.ANSWER_LAWYER_2!, process.env.ANSWER_LAWYER_3!],
  8: [process.env.ANSWER_TRAINER_1!, process.env.ANSWER_TRAINER_2!, process.env.ANSWER_TRAINER_3!]
};

// Simple session authentication middleware  
const authenticateToken = (req: AuthRequest, res: express.Response, next: express.NextFunction) => {
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

  req.userId = req.session.userId;
  next();
};

// Input validation schemas
const loginSchema = Joi.object({
  password: Joi.string().min(1).max(200).required().trim()
});

const answerSchema = Joi.object({
  answer: Joi.string().min(1).max(100).required().trim()
});

// Clear old auth cookies endpoint
app.post('/api/auth/clear', (req, res) => {
  // Clear any old JWT cookies that might be lingering
  res.clearCookie('auth_token');
  res.clearCookie('jwt_token'); 
  res.clearCookie('quiz_session');
  res.json({ success: true, message: 'Cookies cleared' });
});

// Auth endpoint - no longer used (authentication removed)
// Kept for backwards compatibility but always returns success
app.post('/api/auth/login', authLimiter, (req, res) => {
  res.json({
    success: true,
    message: 'Authentication successful'
  });
});

// Get questions (no auth required)
// Returns a randomized set of questions for each request
app.get('/api/questions', (req, res) => {
  const questions = getRandomQuestions();
  res.json({ questions });
});


// Submit answer (no auth required)
app.post('/api/questions/:questionId/answer', (req, res) => {
  const questionId = parseInt(req.params.questionId);

  // Validate question ID exists in either single or multiple answer maps
  const validQuestion = correctAnswers[questionId] !== undefined || multipleCorrectAnswers[questionId] !== undefined;
  if (isNaN(questionId) || !validQuestion) {
    return res.status(404).json({ error: 'Question not found' });
  }

  // Validate input
  const { error, value } = answerSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: 'Invalid input: ' + error.details[0].message });
  }

  const { answer } = value;
  let isCorrect = false;

  // Helper to extract only numbers from a string
  const extractNumbers = (str: string): string => {
    return str.replace(/\D/g, '');
  };

  // Check if question has single answer
  if (correctAnswers[questionId]) {
    // Question 1 (T-Rex eyes) is case-insensitive text
    if (questionId === 1) {
      isCorrect = answer.toLowerCase() === correctAnswers[questionId].toLowerCase();
    }
    // Questions 9, 10, 11 are numeric - strip non-numeric characters and compare
    else if (questionId === 9 || questionId === 10 || questionId === 11) {
      const numericAnswer = extractNumbers(answer);
      const numericCorrect = extractNumbers(correctAnswers[questionId]);
      isCorrect = numericAnswer === numericCorrect;
    }
    else {
      isCorrect = answer === correctAnswers[questionId];
    }
  }
  // Check if question has multiple possible answers (access codes - strip non-numeric and compare)
  else if (multipleCorrectAnswers[questionId]) {
    const numericAnswer = extractNumbers(answer);
    isCorrect = multipleCorrectAnswers[questionId].some(
      correctAnswer => extractNumbers(correctAnswer) === numericAnswer
    );
  }

  res.json({
    correct: isCorrect,
    message: isCorrect ? 'Correct!' : 'Incorrect answer'
  });
});

// Get secret code (no auth required)
app.get('/api/completion', (req, res) => {
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
// Check if we're running from the dist folder (production build)
const isProduction = __dirname.includes('dist');

if (isProduction) {
  // Server is compiled to dist/server/server.js, so we need to go up one level to dist/
  const staticPath = path.join(__dirname, '..');
  console.log('📁 Serving static files from:', staticPath);
  console.log('📁 Current directory:', __dirname);

  app.use(express.static(staticPath));

  // Handle React Router - serve index.html for all non-API routes
  app.get(/^(?!\/api).*/, (req, res) => {
    const indexPath = path.join(staticPath, 'index.html');
    console.log('📄 Serving index.html from:', indexPath);
    res.sendFile(indexPath);
  });
} else {
  console.log('🔧 Running in development mode - static files served by Vite');
}

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔒 Authentication endpoint: http://localhost:${PORT}/api/auth/login`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📂 Running from: ${__dirname}`);
});

export default app;