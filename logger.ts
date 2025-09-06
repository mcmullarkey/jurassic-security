import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';

// Create logs directory if it doesn't exist
const logDir = 'logs';

// Check if we're on Render free tier (no persistent disk)
const isRenderFreeTier = process.env.RENDER && !process.env.RENDER_SERVICE_PLAN;

// Security logger for authentication and security events
export const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss'
    }),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'jurassic-quiz-security' },
  transports: [
    // Only add file logging if not on free tier (no persistent disk)
    ...(isRenderFreeTier ? [] : [
      new DailyRotateFile({
        filename: `${logDir}/security-%DATE%.log`,
        datePattern: 'YYYY-MM-DD',
        maxFiles: '30d', // Keep 30 days of logs
        maxSize: '10m',   // Max 10MB per file
        level: 'info'
      })
    ]),
    // Console output (always available)
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
      level: process.env.NODE_ENV === 'production' ? 'warn' : 'info'
    })
  ]
});

// General application logger
export const appLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss'
    }),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'jurassic-quiz-app' },
  transports: [
    // Only add file logging if not on free tier (no persistent disk)
    ...(isRenderFreeTier ? [] : [
      new DailyRotateFile({
        filename: `${logDir}/app-%DATE%.log`,
        datePattern: 'YYYY-MM-DD',
        maxFiles: '14d', // Keep 14 days of logs
        maxSize: '5m',   // Max 5MB per file
        level: 'info'
      }),
      new winston.transports.File({
        filename: `${logDir}/error.log`,
        level: 'error'
      })
    ]),
    // Console output (always available)
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
      level: process.env.NODE_ENV === 'production' ? 'error' : 'info'
    })
  ]
});

// Security event types for consistent logging
export const SecurityEvents = {
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  RATE_LIMIT_HIT: 'RATE_LIMIT_HIT',
  INVALID_TOKEN: 'INVALID_TOKEN',
  UNAUTHORIZED_ACCESS: 'UNAUTHORIZED_ACCESS',
  SUSPICIOUS_REQUEST: 'SUSPICIOUS_REQUEST',
  SESSION_CREATED: 'SESSION_CREATED',
  SESSION_DESTROYED: 'SESSION_DESTROYED',
  SESSION_EXPIRED: 'SESSION_EXPIRED',
  SESSION_HIJACK_ATTEMPT: 'SESSION_HIJACK_ATTEMPT',
  CSRF_TOKEN_INVALID: 'CSRF_TOKEN_INVALID',
  CSRF_TOKEN_MISSING: 'CSRF_TOKEN_MISSING'
} as const;

// Helper function to log security events
export const logSecurityEvent = (
  event: keyof typeof SecurityEvents,
  details: {
    ip?: string;
    userAgent?: string;
    userId?: string;
    endpoint?: string;
    additional?: Record<string, any>;
  }
) => {
  securityLogger.warn({
    event,
    timestamp: new Date().toISOString(),
    ip: details.ip,
    userAgent: details.userAgent,
    userId: details.userId,
    endpoint: details.endpoint,
    ...details.additional
  });
};