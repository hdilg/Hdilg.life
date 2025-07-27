// server.js
require('dotenv').config();
const express      = require('express');
const path         = require('path');
const cors         = require('cors');
const helmet       = require('helmet');
const { body, validationResult } = require('express-validator');

const app  = express();
const PORT = process.env.PORT || 3000;

// إعدادات الأمان
app.use(helmet());
app.disable('x-powered-by');
app.use(cors());
app.use(express.json({ limit: '10kb' }));

// دالة لحساب عدد الأيام شاملة اليومين
const calcDays = (start, end) => {
  const s = new Date(start);
  const e = new Date(end);
  return Math.floor((e - s) / (1000 * 3600 * 24)) + 1;
};

// بيانات الإجازات مع الحقل days
const leaves = [
  { serviceCode: "GSL25021372778", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-02-24", startDate: "2025-02-09", endDate: "2025-02-24", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25021898579", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-03-26", startDate: "2025-02-25", endDate: "2025-03-26", doctorName: "جمال راشد السر محمد احمد", jobTitle: "استشاري" },
  { serviceCode: "GSL25022385036", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-04-17", startDate: "2025-03-27", endDate: "2025-04-17", doctorName: "جمال راشد السر محمد احمد", jobTitle: "استشاري" },
  { serviceCode: "GSL25022884602", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-04-18", startDate: "2025-04-18", endDate: "2025-05-15", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25023345012", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-05-16", startDate: "2025-05-16", endDate: "2025-06-12", doctorName: "هدى مصطفى خضر دحبور", jobTitle: "استشاري" },
  { serviceCode: "GSL25062955824", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-06-13", startDate: "2025-06-13", endDate: "2025-07-11", doctorName: "هدى مصطفى خضر دبحور", jobTitle: "استشاري" },
  { serviceCode: "GSL25071678945", idNumber: "1088576044", name: "عبدالإله سليمان عبدالله الهديلج", reportDate: "2025-07-12", startDate: "2025-07-12", endDate: "2025-07-25", doctorName: "عبدالعزيز فهد هميجان الروقي", jobTitle: "استشاري" }
].map(l => ({ ...l, days: calcDays(l.startDate, l.endDate) }));

// مسار API للاستعلام
app.post('/api/leave', [
  body('serviceCode')
    .trim()
    .isLength({ min: 8, max: 20 }).withMessage('رمز الخدمة يجب أن يكون بين 8 و20 خانة')
    .matches(/^[A-Za-z0-9]+$/).withMessage('رمز الخدمة أحرف وأرقام فقط'),
  body('idNumber')
    .trim()
    .isLength({ min: 10, max: 10 }).withMessage('رقم الهوية/الإقامة يجب أن يكون 10 أرقام')
    .isNumeric().withMessage('رقم الهوية/الإقامة أرقام فقط')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: errors.array().map(err => err.msg).join('، ')
    });
  }

  const { serviceCode, idNumber } = req.body;
  const record = leaves.find(l => l.serviceCode === serviceCode && l.idNumber === idNumber);

  if (!record) {
    return res.status(404).json({
      success: false,
      message: 'لا توجد إجازة مطابقة للمعلومات المدخلة'
    });
  }

  return res.json({
    success: true,
    record
  });
});

// تقديم الملفات الثابتة (المجلد public يحتوي index.html، CSS، الصور…)
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`✅ الخادم يعمل على http://localhost:${PORT}`);
});
