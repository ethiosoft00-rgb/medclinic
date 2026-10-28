import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import Groq from "groq-sdk";
import multer from 'multer';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const upload = multer({ storage: multer.memoryStorage() });

const supabase = createClient(
  process.env.SUPABASE_URL, 
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY
);

if (!process.env.GROQ_API_KEY) {
    console.warn("⚠️ WARNING: GROQ_API_KEY is missing in .env. AI features will not work.");
}
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY || 'missing-key' });

// FIXED: Using the current supported Groq model
const ACTIVE_MODEL = "openai/gpt-oss-120b"; 
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ============================================================
   HELPERS & MIDDLEWARE
   ============================================================ */
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
}
const role = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Forbidden' });

async function audit(user, action, entity, entityId, details = {}) {
  try {
    await supabase.from('audit_log').insert([{
      user_id: user?.id, user_name: user?.name, action, entity, entity_id: String(entityId ?? ''), details
    }]);
  } catch (e) { console.error("Audit Error:", e); }
}

/* ============================================================
   AUTH ROUTES
   ============================================================ */
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) return res.status(400).json({ error: 'Missing credentials' });

  const { data: user, error } = await supabase.from('profiles').select('*').eq('email', identifier).single();
  if (error || !user) return res.status(401).json({ error: 'Invalid email or password.' });

  let ok = false;
  if (user.password_hash) ok = await bcrypt.compare(password, user.password_hash);
  else if (user.password === password) {
    const hash = await bcrypt.hash(password, 10);
    await supabase.from('profiles').update({ password_hash: hash, password: null }).eq('id', user.id);
    ok = true;
  }
  if (!ok) return res.status(401).json({ error: 'Invalid email or password.' });

  const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  delete user.password; delete user.password_hash;
  await audit(user, 'login', 'profiles', user.id, {});
  res.json({ success: true, user, token });
});

app.post('/api/auth/register', loginLimiter, async (req, res) => {
  const { name, email, password, phone } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, password required' });
  const { data: existing } = await supabase.from('profiles').select('id').eq('email', email).maybeSingle();
  if (existing) return res.status(400).json({ error: 'Email already registered.' });

  const hash = await bcrypt.hash(password, 10);
  const { data: profile, error } = await supabase.from('profiles').insert([{ name, email, password_hash: hash, role: 'patient', phone }]).select().single();
  if (error) return res.status(500).json({ error: error.message });

  await supabase.from('patients').insert([{ name, phone }]);
  const token = jwt.sign({ id: profile.id, email, name, role: 'patient' }, JWT_SECRET, { expiresIn: '7d' });
  delete profile.password; delete profile.password_hash;
  res.json({ success: true, user: profile, token });
});

app.get('/api/auth/me', auth, async (req, res) => {
  const { data: user, error } = await supabase.from('profiles').select('id, name, email, role, phone').eq('id', req.user.id).single();
  if (error || !user) return res.status(404).json({ error: 'Not found' });
  res.json({ user });
});

app.get('/api/config', (req, res) => res.json({ url: process.env.SUPABASE_URL, anonKey: process.env.SUPABASE_ANON_KEY }));

/* ============================================================
   PATIENTS & HISTORY
   ============================================================ */
app.get('/api/patients', auth, async (req, res) => {
  const { q } = req.query;
  let query = supabase.from('patients').select('*').order('created_at', { ascending: false });
  if (q) query = query.ilike('name', `%${q}%`);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/patients', auth, role('admin', 'nurse', 'doctor'), async (req, res) => {
  const { name, dob, sex, phone, region, allergies, insurance_type } = req.body;
  const { data, error } = await supabase.from('patients').insert([{ name, dob, sex, phone, region, allergies, insurance_type }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await audit(req.user, 'create_patient', 'patients', data.id, { name });
  res.json({ success: true, patient: data });
});

app.get('/api/patients/:id/history', auth, async (req, res) => {
  const { id } = req.params;
  const [visits, prescriptions, invoices, appointments] = await Promise.all([
    supabase.from('visits').select('*').eq('patient_id', id).order('created_at', { ascending: false }),
    supabase.from('prescriptions').select('*').eq('patient_id', id).order('created_at', { ascending: false }),
    supabase.from('invoices').select('*').eq('patient_id', id).order('created_at', { ascending: false }),
    supabase.from('appointments').select('*').eq('patient_id', id).order('scheduled_at', { ascending: false })
  ]);
  res.json({
    visits: visits.data || [], prescriptions: prescriptions.data || [],
    invoices: invoices.data || [], appointments: appointments.data || []
  });
});

/* ============================================================
   USERS
   ============================================================ */
app.post('/api/users', auth, role('admin'), async (req, res) => {
  const { name, email, password, role: r } = req.body;
  const { data: existing } = await supabase.from('profiles').select('id').eq('email', email).maybeSingle();
  if (existing) return res.status(400).json({ error: 'Email already registered.' });
  const hash = await bcrypt.hash(password, 10);
  const { data, error } = await supabase.from('profiles').insert([{ name, email, password_hash: hash, role: r }]).select('id, name, email, role').single();
  if (error) return res.status(500).json({ error: error.message });
  await audit(req.user, 'create_user', 'profiles', data.id, { role: r });
  res.json({ success: true, user: data });
});

app.get('/api/users', auth, async (req, res) => {
  const { data, error } = await supabase.from('profiles').select('id, name, email, role');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

/* ============================================================
   QUEUE & VISITS
   ============================================================ */
app.get('/api/queue', auth, async (req, res) => {
  const { data, error } = await supabase.from('queue_tickets').select('*').neq('status', 'Completed').order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/queue', auth, role('admin', 'nurse', 'doctor'), async (req, res) => {
  try {
    const { patient_name, symptom = '', phone, allergies, insurance, patient_id, vitals } = req.body;
    const isUrgent = /chest|bleed|shortness|unconscious/i.test(symptom);
    const priority = isUrgent ? 'urgent' : 'routine';
    const ticket_number = 'A-' + Math.floor(Math.random() * 1000);

    const { data, error } = await supabase.from('queue_tickets').insert([{
      ticket_number, patient_name, symptom, status: 'Waiting', priority, phone,
      allergies, insurance, patient_id: patient_id || null, vitals: vitals || null
    }]).select().single();
    if (error) throw error;
    await audit(req.user, 'queue_add', 'queue_tickets', data.id, { patient_name });
    res.json({ success: true, data });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/queue/:id/complete', auth, role('admin', 'doctor', 'nurse'), async (req, res) => {
  try {
    const { note, prescriptions = [], lab_results } = req.body;
    const { data: ticket } = await supabase.from('queue_tickets').select('*').eq('id', req.params.id).single();
    if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

    const { data: visit, error: ve } = await supabase.from('visits').insert([{
      patient_id: ticket.patient_id, queue_ticket_id: ticket.id,
      doctor_id: req.user.id, doctor_name: req.user.name,
      symptoms: ticket.symptom, allergies: ticket.allergies,
      note, lab_results: lab_results || null
    }]).select().single();
    if (ve) throw ve;

    if (prescriptions.length) {
      const rows = prescriptions.map(p => ({
        visit_id: visit.id, patient_id: ticket.patient_id, patient_name: ticket.patient_name,
        doctor_id: req.user.id, doctor_name: req.user.name,
        medicine_name: p.medicine_name, dosage: p.dosage, quantity: p.quantity || 1
      }));
      await supabase.from('prescriptions').insert(rows);
    }

    await supabase.from('queue_tickets').update({ status: 'Completed', doctor_note: note }).eq('id', ticket.id);
    await audit(req.user, 'visit_complete', 'visits', visit.id, { patient: ticket.patient_name });
    res.json({ success: true, visit });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ============================================================
   STOCK & PRESCRIPTIONS
   ============================================================ */
app.get('/api/stock', auth, async (req, res) => {
  const { data, error } = await supabase.from('stock_items').select('*').order('medicine_name');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/prescriptions', auth, async (req, res) => {
  const { status, patient_id } = req.query;
  let query = supabase.from('prescriptions').select('*').order('created_at', { ascending: false });
  if (status) query = query.eq('status', status);
  if (patient_id) query = query.eq('patient_id', patient_id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/prescriptions/:id/dispense', auth, role('pharmacist', 'admin'), async (req, res) => {
  try {
    const { data: presc } = await supabase.from('prescriptions').select('*').eq('id', req.params.id).single();
    if (!presc) return res.status(404).json({ error: 'Not found' });
    if (presc.status === 'dispensed') return res.status(400).json({ error: 'Already dispensed' });

    const { data: stock } = await supabase.from('stock_items').select('*').ilike('medicine_name', presc.medicine_name).single();
    if (!stock) return res.status(400).json({ error: 'Medicine not in stock' });
    if (stock.quantity < presc.quantity) return res.status(400).json({ error: 'Insufficient stock' });

    await supabase.from('stock_items').update({ quantity: stock.quantity - presc.quantity }).eq('id', stock.id);
    await supabase.from('prescriptions').update({ status: 'dispensed', dispensed_by: req.user.id, dispensed_at: new Date().toISOString() }).eq('id', presc.id);
    await audit(req.user, 'dispense', 'prescriptions', presc.id, { medicine: presc.medicine_name });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ============================================================
   APPOINTMENTS, BILLING, AUDIT
   ============================================================ */
app.get('/api/appointments', auth, async (req, res) => {
  let query = supabase.from('appointments').select('*').order('scheduled_at');
  if (req.user.role === 'patient') query = query.eq('patient_id', req.user.id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/appointments', auth, async (req, res) => {
  const { patient_id, patient_name, doctor_id, doctor_name, scheduled_at, reason } = req.body;
  const { data, error } = await supabase.from('appointments').insert([{ patient_id, patient_name, doctor_id, doctor_name, scheduled_at, reason, status: 'scheduled' }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  await audit(req.user, 'appointment_create', 'appointments', data.id, {});
  res.json({ success: true, appointment: data });
});

app.get('/api/invoices', auth, async (req, res) => {
  let query = supabase.from('invoices').select('*').order('created_at', { ascending: false });
  if (req.user.role === 'patient') query = query.eq('patient_id', req.user.id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/audit', auth, role('admin'), async (req, res) => {
  const { data, error } = await supabase.from('audit_log').select('*').order('created_at', { ascending: false }).limit(500);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

/* ============================================================
   MESSAGES
   ============================================================ */
app.get('/api/messages/:userId/:otherUserId', auth, async (req, res) => {
  const { userId, otherUserId } = req.params;
  const { data, error } = await supabase.from('messages').select('*')
    .or(`and(sender_id.eq.${userId},receiver_id.eq.${otherUserId}),and(sender_id.eq.${otherUserId},receiver_id.eq.${userId})`)
    .order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/messages', auth, upload.single('file'), async (req, res) => {
  const { sender_id, receiver_id, sender_name, text, message_type } = req.body;
  let fileUrl = null; let fileName = null;
  if (req.file) {
    fileName = req.file.originalname;
    const filePath = `${Date.now()}_${fileName}`;
    const { error: upErr } = await supabase.storage.from('clinic-files').upload(filePath, req.file.buffer, { contentType: req.file.mimetype });
    if (!upErr) { const { data: url } = supabase.storage.from('clinic-files').getPublicUrl(filePath); fileUrl = url.publicUrl; }
  }
  const { data, error } = await supabase.from('messages').insert([{ sender_id, receiver_id, sender_name, text, file_url: fileUrl, file_name: fileName, message_type: message_type || 'text', is_read: false }]).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, message: data });
});

app.get('/api/messages/unread/:userId', auth, async (req, res) => {
  const { data, error } = await supabase.from('messages').select('sender_id').eq('receiver_id', req.params.userId).eq('is_read', false);
  if (error) return res.json({ counts: {} });
  const counts = {}; data.forEach(m => { counts[m.sender_id] = (counts[m.sender_id] || 0) + 1; });
  res.json({ counts });
});

app.post('/api/messages/read', auth, async (req, res) => {
  const { userId, otherUserId } = req.body;
  await supabase.from('messages').update({ is_read: true }).eq('receiver_id', userId).eq('sender_id', otherUserId).eq('is_read', false);
  res.json({ success: true });
});

/* ============================================================
   AI ROUTES (UPDATED FOR MULTI-LANGUAGE)
   ============================================================ */
const langMap = {
  en: 'English', am: 'Amharic', om: 'Afaan Oromoo', ti: 'Tigrinya',
  so: 'Somali', aa: 'Afar', gz: 'Gurage', wal: 'Wolaytta'
};

app.post('/api/ai-chat', auth, async (req, res) => {
  try {
    const { prompt, context, language } = req.body;
    if (!process.env.GROQ_API_KEY) {
       return res.status(500).json({ error: 'Server is missing GROQ_API_KEY in .env file.' });
    }

    const targetLang = langMap[language] || 'English';
    const c = await groq.chat.completions.create({
      messages: [
        { role: "system", content: `You are MedClinic AI, a helpful medical assistant. You MUST answer ENTIRELY in ${targetLang}. Context data: ${JSON.stringify(context).substring(0, 2000)}.` },
        { role: "user", content: prompt }
      ],
      model: ACTIVE_MODEL
    });
    res.json({ reply: c.choices[0].message.content });
  } catch (err) { 
    console.error("Groq Chat Error:", err.message);
    res.status(500).json({ error: err.message }); 
  }
});

app.post('/api/scan-report', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    if (!process.env.GROQ_API_KEY) return res.status(500).json({ error: 'Server is missing GROQ_API_KEY.' });

    const { language } = req.body;
    const targetLang = langMap[language] || 'English';

    const prompt = `You are a medical AI. A patient uploaded a lab report named "${req.file.originalname}". 
    Generate a realistic mock medical lab result (e.g., Complete Blood Count, Lipid Panel) in JSON format.
    CRITICAL INSTRUCTION: Translate the string VALUES (like test_name, parameter, status, clinical_notes) into ${targetLang}, but keep the JSON KEYS in English.
    Include fields: test_name, results (array of {parameter, value, normal_range, status}), and clinical_notes.`;

    const c = await groq.chat.completions.create({
      messages: [{ role: "system", content: prompt }],
      model: ACTIVE_MODEL
    });

    res.json({ success: true, analysis: c.choices[0].message.content });
  } catch (err) {
    console.error("Groq Scan Error:", err.message);
    res.status(500).json({ error: 'AI Scan failed: ' + err.message });
  }
});

// Change from app.listen(...) to this:
if (process.env.NODE_ENV !== 'production') {
    app.listen(process.env.PORT || 3000, () => console.log(`✅ Server running on http://localhost:3000`));
}

export default app;