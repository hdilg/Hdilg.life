require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const useragent = require('express-useragent');
const winston = require('winston');
const axios = require('axios');
const xssClean = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');

const app = express();
const PORT = process.env.PORT || 3000;
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || '';

// 1. حماية طبقة النقل
app.set('trust proxy', 1);

// 2. تكوين نظام التسجيل (Logging)
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(i => `[${i.timestamp}] ${i.level.toUpperCase()}: ${i.message}`)
  ),
  transports: [
    new winston.transports.File({ 
      filename: 'activity.log', 
      maxsize: 5_000_000,
      maxFiles: 3,
      handleExceptions: true
    }),
    new winston.transports.Console({
      handleExceptions: true
    })
  ],
  exitOnError: false
});

// 3. طبقات الحماية المتقدمة
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
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(hpp());
app.use(xssClean());
app.use(mongoSanitize({
  replaceWith: '_'
}));

app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use(useragent.express());

// 4. الحد من معدل الطلبات
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'تم تقييد طلبك مؤقتاً بسبب كثرة المحاولات.' },
  skip: req => req.ip === '::ffff:127.0.0.1' // استثناء localhost
});

app.use('/api/', apiLimiter);

// 5. تسجيل الطلبات
app.use((req, res, next) => {
  logger.info(`[IP: ${req.ip}] [UA: ${req.useragent.source}] ${req.method} ${req.originalUrl}`);
  next();
});

// 6. تقديم الواجهة الأمامية
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Referrer-Policy', 'same-origin');
  }
}));

// 7. حساب مدة الإجازة
function calcDays(start, end) {
  try {
    const s = new Date(start);
    const e = new Date(end);
    
    if (isNaN(s) || isNaN(e)) return 0;
    if (e < s) return 0;
    
    return Math.floor((e - s) / (1000 * 60 * 60 * 24)) + 1;
  } catch (error) {
    logger.error(`خطأ في حساب الأيام: ${error.message}`);
    return 0;
  }
}

// 8. بيانات الإجازات (مع حماية ضد التعديل)
const leaves = Object.freeze([
  { serviceCode: "GSL25021372778", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-02-24", startDate: "2025-02-09", endDate: "2025-02-24", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25021898579", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-03-26", startDate: "2025-02-25", endDate: "2025-03-26", doctorName: "جمال راشد السر محمد احمد", jobTitle: "استشاري" },
  { serviceCode: "GSL25022385036", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-04-17", startDate: "2025-03-27", endDate: "2025-04-17", doctorName: "جمال راشد السر محمد احمد", jobTitle: "استشاري" },
  { serviceCode: "GSL25022884602", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-05-15", startDate: "2025-04-18", endDate: "2025-05-15", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25023345012", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-06-12", startDate: "2025-05-16", endDate: "2025-06-12", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25062955824", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-07-11", startDate: "2025-06-13", endDate: "2025-07-11", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25071678945", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-07-12", startDate: "2025-07-12", endDate: "2025-07-25", doctorName: "عبدالعزيز فهد هميجان الروقي", jobTitle: "استشاري" }
].map(l => ({ ...l, days: calcDays(l.startDate, l.endDate) })));

// 9. التحقق من reCAPTCHA
async function verifyCaptcha(token, ip) {
  if (!RECAPTCHA_SECRET) return true;
  
  try {
    const response = await axios.post(
      'https://www.google.com/recaptcha/api/siteverify',
      new URLSearchParams({ secret: RECAPTCHA_SECRET, response: token, remoteip: ip }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 5000 }
    );
    
    return response.data.success && response.data.score >= 0.5;
  } catch (err) {
    logger.error(`[reCAPTCHA Error] ${err.message}`);
    return false;
  }
}

// 10. مسار البحث عن إجازة
app.post('/api/leave', async (req, res) => {
  try {
    const { serviceCode, idNumber, captchaToken } = req.body;

    // تحقق من صحة المدخلات
    if (typeof serviceCode !== 'string' || !/^[A-Za-z0-9]{8,20}$/.test(serviceCode) ||
        typeof idNumber !== 'string' || !/^[0-9]{10}$/.test(idNumber)) {
      return res.status(400).json({ success: false, message: 'البيانات المدخلة غير صحيحة.' });
    }

    // التحقق من reCAPTCHA
    if (!(await verifyCaptcha(captchaToken, req.ip))) {
      logger.warn(`[reCAPTCHA Failed] IP: ${req.ip}`);
      return res.status(403).json({ 
        success: false, 
        message: 'فشل التحقق الأمني. يرجى المحاولة مرة أخرى.' 
      });
    }

    // البحث في السجلات
    const record = leaves.find(l => 
      l.serviceCode === serviceCode && 
      l.idNumber === idNumber
    );

    if (!record) {
      return res.status(404).json({ 
        success: false, 
        message: 'لم يتم العثور على سجل مطابق.' 
      });
    }

    // إرجاع النتيجة مع حذف البيانات الحساسة
    const { idNumber: _, ...safeRecord } = record;
    return res.json({ success: true, record: safeRecord });
    
  } catch (error) {
    logger.error(`خطأ في معالجة الطلب: ${error.message}`);
    res.status(500).json({ 
      success: false, 
      message: 'حدث خطأ داخلي في الخادم.' 
    });
  }
});

// 11. مسار الحصول على جميع الإجازات
app.get('/api/leaves', (req, res) => {
  try {
    // حماية ضد كشف البيانات الحساسة
    const safeLeaves = leaves.map(({ idNumber, ...rest }) => rest);
    res.json({ success: true, leaves: safeLeaves });
  } catch (error) {
    logger.error(`خطأ في /api/leaves: ${error.message}`);
    res.status(500).json({ 
      success: false, 
      message: 'حدث خطأ أثناء جلب البيانات.' 
    });
  }
});

// 12. SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
    if (err) {
      logger.error(`خطأ في تحميل الواجهة: ${err.message}`);
      res.status(404).json({ success: false, message: 'الصفحة المطلوبة غير موجودة.' });
    }
  });
});

// 13. معالجة الأخطاء العامة
app.use((err, req, res, next) => {
  logger.error(`خطأ غير معالج: ${err.message}`);
  res.status(500).json({ 
    success: false, 
    message: 'حدث عطل تقني غير متوقع. يرجى المحاولة لاحقاً.' 
  });
});

// 14. إيقاف آمن للخادم
process.on('SIGTERM', () => {
  logger.info('تم إيقاف الخدمة بأمان.');
  server.close(() => {
    process.exit(0);
  });
});

// 15. بدء التشغيل
const server = app.listen(PORT, () => {
  logger.info(`✅ الخادم يعمل على المنفذ ${PORT}`);
  logger.info(`⛔️ وضع الحماية: ${process.env.NODE_ENV === 'production' ? 'تشديد كامل' : 'تطوير'}`);
});
