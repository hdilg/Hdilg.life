// server.js

require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const Redis = require('ioredis');
const hpp = require('hpp');
const useragent = require('express-useragent');
const winston = require('winston');
require('winston-daily-rotate-file');
const axios = require('axios');
const xssClean = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const Joi = require('joi');


// 1. التحقق من متغيرات البيئة
const requiredEnvs = ['PORT', 'RECAPTCHA_SECRET', 'CORS_ORIGIN', 'NODE_ENV'];
const missingEnvs = requiredEnvs.filter(key => !process.env[key]);
if (missingEnvs.length) {
  console.error(`❌ Missing ENV vars: ${missingEnvs.join(', ')}`);
  process.exit(1);
}

const PORT = Number(process.env.PORT);
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET;
const CORS_WHITELIST = process.env.CORS_ORIGIN.split(',').map(u => u.trim());
const NODE_ENV = process.env.NODE_ENV;


// 2. إعداد Winston Logger مع Daily Rotate
const transport = new winston.transports.DailyRotateFile({
  filename: 'logs/%DATE%-activity.log',
  datePattern: 'YYYY-MM-DD',
  maxSize: '10m',
  maxFiles: '14d',
  zippedArchive: true
});

const logger = winston.createLogger({
  level: NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(i => `[${i.timestamp}] ${i.level.toUpperCase()}: ${i.message}`)
  ),
  transports: [
    transport,
    new winston.transports.Console()
  ],
  exitOnError: false
});


// 3. تهيئة تطبيق Express
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);


// 4. طبقات الحماية Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://www.google.com", "https://www.gstatic.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: []
    }
  },
  hsts: { maxAge: 31536000, preload: true }
}));

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || CORS_WHITELIST.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(hpp());
app.use(xssClean());
app.use(mongoSanitize({ replaceWith: '_' }));
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use(useragent.express());


// 5. Rate Limiter (مع دعم Redis اختياري)
let apiLimiter;
if (process.env.REDIS_URL) {
  const client = new Redis(process.env.REDIS_URL);
  apiLimiter = rateLimit({
    store: new RedisStore({ sendCommand: (...args) => client.call(...args) }),
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'تم تقييد طلبك مؤقتاً بسبب كثرة المحاولات.' }
  });
} else {
  apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'تم تقييد طلبك مؤقتاً بسبب كثرة المحاولات.' }
  });
}
app.use('/api/', apiLimiter);


// 6. تسجيل الطلبات
app.use((req, res, next) => {
  logger.info(`[IP: ${req.ip}] [UA: ${req.useragent.source}] ${req.method} ${req.originalUrl}`);
  next();
});


// 7. دوال مساعدة
function calcDays(start, end) {
  const s = new Date(start);
  const e = new Date(end);
  if (isNaN(s) || isNaN(e) || e < s) return 0;
  return Math.floor((e - s) / (1000 * 60 * 60 * 24)) + 1;
}

async function verifyCaptcha(token, ip) {
  if (!RECAPTCHA_SECRET) return true;
  try {
    const { data } = await axios.post(
      'https://www.google.com/recaptcha/api/siteverify',
      new URLSearchParams({ secret: RECAPTCHA_SECRET, response: token, remoteip: ip }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 5000 }
    );
    return data.success && data.score >= 0.5;
  } catch (err) {
    logger.error(`[reCAPTCHA Error] ${err.message}`);
    return false;
  }
}


// 8. بيانات الإجازات
const rawLeaves = [
  { serviceCode: "GSL25021372778", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-02-24", startDate: "2025-02-09", endDate: "2025-02-24", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25021898579", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-03-26", startDate: "2025-02-25", endDate: "2025-03-26", doctorName: "جمال راشد السر محمد احمد", jobTitle: "استشاري" },
  { serviceCode: "GSL25022385036", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-04-17", startDate: "2025-03-27", endDate: "2025-04-17", doctorName: "جمال راشد السر محمد احمد", jobTitle: "استشاري" },
  { serviceCode: "GSL25022884602", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-05-15", startDate: "2025-04-18", endDate: "2025-05-15", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25023345012", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-06-12", startDate: "2025-05-16", endDate: "2025-06-12", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25062955824", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-07-11", startDate: "2025-06-13", endDate: "2025-07-11", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25071678945", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-07-12", startDate: "2025-07-12", endDate: "2025-07-25", doctorName: "عبدالعزيز فهد هميجان الروقي", jobTitle: "استشاري" }
];
const leaves = rawLeaves.map(l => ({ ...l, days: calcDays(l.startDate, l.endDate) }));


// 9. مخطط التحقق (Joi)
const leaveSchema = Joi.object({
  serviceCode: Joi.string().alphanum().min(8).max(20).required(),
  idNumber: Joi.string().pattern(/^[0-9]{10}$/).required(),
  captchaToken: Joi.string().required()
});


// 10. المسارات (Routes)
app.post('/api/leave', async (req, res, next) => {
  try {
    // التحقق من المدخلات
    const { serviceCode, idNumber, captchaToken } = await leaveSchema.validateAsync(req.body);

    // تحقق reCAPTCHA
    if (!(await verifyCaptcha(captchaToken, req.ip))) {
      logger.warn(`[reCAPTCHA Failed] IP: ${req.ip}`);
      return res.status(403).json({ success: false, message: 'فشل التحقق الأمني.' });
    }

    // البحث في السجلات
    const record = leaves.find(l => l.serviceCode === serviceCode && l.idNumber === idNumber);
    if (!record) {
      return res.status(404).json({ success: false, message: 'لم يتم العثور على سجل.' });
    }

    // إخفاء البيانات الحساسة
    const { idNumber: _, ...safeRecord } = record;
    res.json({ success: true, record: safeRecord });

  } catch (err) {
    if (err.isJoi) {
      return res.status(400).json({ success: false, message: 'البيانات المدخلة غير صحيحة.' });
    }
    next(err);
  }
});

app.get('/api/leaves', (req, res, next) => {
  try {
    const safe = leaves.map(({ idNumber, ...r }) => r);
    res.json({ success: true, leaves: safe });
  } catch (err) {
    next(err);
  }
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// 11. معالجة الأخطاء المركزية
app.use((err, req, res, next) => {
  logger.error(err.stack);
  if (res.headersSent) return next(err);
  res.status(err.statusCode || 500).json({
    success: false,
    message: err.isOperational ? err.message : 'حدث عطل تقني، يرجى المحاولة لاحقاً.'
  });
});


// 12. إيقاف آمن للخادم
process.on('SIGTERM', () => {
  logger.info('تم إيقاف الخادم بأمان.');
  server.close(() => process.exit(0));
});


// 13. بدء التشغيل
const server = app.listen(PORT, () => {
  logger.info(`✅ الخادم يعمل على المنفذ ${PORT}`);
  logger.info(`⛔️ البيئة: ${NODE_ENV}`);
});
```[43dcd9a7-70db-4a1f-b0ae-981daa162054](https://github.com/tphdev/secure-node-app/tree/53b43fb29ca1f4ac478f6d335a65dbca3564483b/NOTES-06-xss.md?citationMarker=43dcd9a7-70db-4a1f-b0ae-981daa162054 "1")[43dcd9a7-70db-4a1f-b0ae-981daa162054](https://github.com/jordanhoughton74-git/personal-website/tree/03f210751d94369523b4587d8ef23a13ef1d9418/next.config.js?citationMarker=43dcd9a7-70db-4a1f-b0ae-981daa162054 "2")[43dcd9a7-70db-4a1f-b0ae-981daa162054](https://github.com/iiroj/react-universal-boilerplate/tree/abbe014aefdc0c65019b1021a1cd4b4ecca1090a/src%2Fserver%2Fservices%2Fmiddleware.js?citationMarker=43dcd9a7-70db-4a1f-b0ae-981daa162054 "3")
