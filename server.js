
// server.js — منصة إدارة الإجازات المرضية

const express       = require('express');
const helmet        = require('helmet');
const cors          = require('cors');
const rateLimit     = require('express-rate-limit');
const hpp           = require('hpp');
const useragent     = require('express-useragent');
const winston       = require('winston');
const axios         = require('axios');
const xssClean      = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const path          = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || '';

app.set('trust proxy', 1);

// Logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(i => `[${i.timestamp}] ${i.level.toUpperCase()}: ${i.message}`)
  ),
  transports: [
    new winston.transports.File({ filename: 'activity.log', maxsize: 5_000_000, maxFiles: 3 }),
    new winston.transports.Console()
  ]
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(hpp());
app.use(xssClean());
app.use(mongoSanitize());
app.use(express.json({ limit: '16kb' }));
app.use(useragent.express());

// Rate Limiter
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'تم تقييد طلبك مؤقتاً.' }
}));

// Logging Request
app.use((req, res, next) => {
  logger.info(`[${req.ip}] ${req.method} ${req.url}`);
  next();
});

// Serve frontend
app.use(express.static(path.join(__dirname, 'public')));

// بيانات الإجازات
function calcDays(start, end) {
  const s = new Date(start);
  const e = new Date(end);
  if (isNaN(s) || isNaN(e) || e < s) return 0;
  return Math.floor((e - s) / (1000 * 60 * 60 * 24)) + 1;
}

const leaves = [
  { serviceCode: "GSL25021372778", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-02-24", startDate: "2025-02-09", endDate: "2025-02-24", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25021898579", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-03-26", startDate: "2025-02-25", endDate: "2025-03-26", doctorName: "جمال راشد السر محمد احمد", jobTitle: "استشاري" },
  { serviceCode: "GSL25022385036", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-04-17", startDate: "2025-03-27", endDate: "2025-04-17", doctorName: "جمال راشد السر محمد احمد", jobTitle: "استشاري" },
  { serviceCode: "GSL25022884602", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-04-18", startDate: "2025-04-18", endDate: "2025-05-15", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25023345012", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-05-16", startDate: "2025-05-16", endDate: "2025-06-12", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25062955824", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-06-13", startDate: "2025-06-13", endDate: "2025-07-11", doctorName: "هدى مصطفى خضر دبحور", jobTitle: "استشاري" },
  { serviceCode: "GSL25071678945", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-07-12", startDate: "2025-07-12", endDate: "2025-07-31", doctorName: "عبدالعزيز فهد الروقي", jobTitle: "استشاري" }
].map(l => ({ ...l, days: calcDays(l.startDate, l.endDate) }));

// API - GET all
app.get('/api/leaves', (req, res) => {
  res.json({ success: true, leaves });
});

// API - POST فردي
app.post('/api/leave', async (req, res) => {
  const { serviceCode, idNumber } = req.body;

  if (
    typeof serviceCode !== 'string' ||
    !/^[A-Za-z0-9]{8,20}$/.test(serviceCode) ||
    typeof idNumber !== 'string' ||
    !/^[0-9]{10}$/.test(idNumber)
  ) {
    return res.status(400).json({ success: false, message: 'البيانات غير صحيحة.' });
  }

  const record = leaves.find(l => l.serviceCode === serviceCode && l.idNumber === idNumber);
  if (record) {
    return res.json({ success: true, record });
  }

  res.status(404).json({ success: false, message: 'لا يوجد سجل مطابق.' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: "الصفحة غير موجودة." });
});

// تشغيل السيرفر
app.listen(PORT, () => {
  logger.info(`✅ Server running on port ${PORT}`);
});
