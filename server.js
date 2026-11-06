// ============================================================
// MedConnect Ethiopia — server.js (Complete & Corrected)
// ============================================================
import express from 'express';
import path from 'path';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import cors from 'cors';

// ✅ FIX 1: Only load .env locally. Vercel injects variables automatically.
if (!process.env.VERCEL) {
    dotenv.config();
}

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error('\n❌ CRITICAL ERROR: Missing Supabase credentials in .env');
}

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY,
    { auth: { persistSession: false, autoRefreshToken: false } }
);

const JWT_SECRET = process.env.JWT_SECRET || 'medconnect-secret-key-12345';
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ✅ FIX 2: Use process.cwd() so Vercel finds the public folder at runtime
app.use(express.static(path.join(process.cwd(), 'public'), { index: false }));
app.use(express.static(path.join(process.cwd()), { index: false })); 

async function sendFrontend(req, res) {
    try {
        const fs = await import('fs/promises');
        let pagePath = path.join(process.cwd(), 'public', 'index.html');
        try { await fs.access(pagePath); } catch { pagePath = path.join(process.cwd(), 'index.html'); }
        let page = await fs.readFile(pagePath, 'utf8');
        const slug = req.params.slug || '';
        page = page
            .replaceAll('__SUPABASE_URL__', process.env.SUPABASE_URL || '')
            .replaceAll('__SUPABASE_ANON_KEY__', process.env.SUPABASE_ANON_KEY || '')
            .replaceAll('__BRANCH_SLUG__', slug)
            .replaceAll('__TG_HANDLE__', process.env.TG_CS_HANDLE || 'TE21HUSH');
        res.type('html').send(page);
    } catch (error) {
        res.status(500).send('Error loading frontend. Please ensure index.html exists in the "public" folder or the root folder.');
    }
}

app.get('/', sendFrontend);
app.get('/b/:slug', sendFrontend);

const slugify = (v) => String(v || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

function generateTempPassword(length = 10) {
    const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    let p = '';
    for (let i = 0; i < length; i++) p += chars[Math.floor(Math.random() * chars.length)];
    return p;
}

async function generateStaffId(branchId, role) {
    const { data: branch } = await supabase.from('branches').select('slug').eq('id', branchId).single();
    const branchPrefix = (branch?.slug || 'BR').split('-')[0].toUpperCase().slice(0, 3);
    const rolePrefix = String(role || 'USR').slice(0, 3).toUpperCase();
    const { count } = await supabase.from('profiles').select('*', { count: 'exact', head: true }).eq('branch_id', branchId).eq('role', role);
    const num = String((count || 0) + 1).padStart(3, '0');
    return `${branchPrefix}-${rolePrefix}-${num}`;
}

async function auth(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'No token provided' });
    try {
        let identity = null;
        try { identity = jwt.verify(token, JWT_SECRET); }
        catch {
            const { data, error } = await supabase.auth.getUser(token);
            if (error || !data?.user) return res.status(401).json({ error: 'Invalid token' });
            identity = { id: data.user.id, email: data.user.email };
        }
        const { data: profile, error: profileError } = await supabase.from('profiles').select('*').eq('id', identity.id).maybeSingle();
        if (profileError || !profile) return res.status(401).json({ error: 'Profile not found' });
        if (profile.is_active === false) return res.status(401).json({ error: 'Account deactivated' });
        req.user = {
            id: profile.id, email: identity.email || '', name: profile.full_name,
            staff_id: profile.staff_id, role: profile.role, branch_id: profile.branch_id,
            phone: profile.phone, avatar_url: profile.avatar_url
        };
        next();
    } catch { return res.status(401).json({ error: 'Invalid session' }); }
}

const role = (...roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
    next();
};

const safe = (p) => { if (!p) return p; const c = { ...p }; delete c.password_hash; return c; };

// ============================================================
// IN-MEMORY STORES (Queue, Triage, Journey)
// ============================================================
const QUEUES = new Map();
const DEFAULT_OFFICES = [
    { id: 'office-reception', name: 'Reception / Triage', department: 'Reception', active: true },
    { id: 'office-emergency', name: 'Emergency Room 1', department: 'Emergency', active: true },
    { id: 'office-lab', name: 'Laboratory Desk 3', department: 'Laboratory', active: true },
    { id: 'office-pharmacy', name: 'Pharmacy Window 2', department: 'Pharmacy', active: true },
    { id: 'office-doctor-1', name: 'Doctor Office 1', department: 'Clinical', active: true }
];

function _getQueue(branchId) {
    if (!QUEUES.has(branchId)) {
        QUEUES.set(branchId, { entries: new Map(), seq: 0, offices: new Map(DEFAULT_OFFICES.map(o => [o.id, { ...o }])), announcements: [] });
    }
    return QUEUES.get(branchId);
}

function _mkQueueNumber(prefix, seq) { return `${prefix}-${String(seq).padStart(3, '0')}`; }

const TRIAGE_FLAGS = new Map();
const TRIAGE_OVERRIDES = new Map();
const JOURNEY_STAGES = ['Registered', 'Waiting', 'With clinician', 'Laboratory', 'Pharmacy', 'Completed'];
const JOURNEYS = new Map();

function _getJourney(patientId) {
    if (!JOURNEYS.has(patientId)) {
        JOURNEYS.set(patientId, { patient_id: patientId, stage: 'Registered', updated_at: new Date().toISOString(), history: [{ stage: 'Registered', at: new Date().toISOString(), by: 'system' }] });
    }
    return JOURNEYS.get(patientId);
}

function _pushAnnouncement(branchId, text) {
    const q = _getQueue(branchId);
    q.announcements.push({ id: Date.now(), text, at: new Date().toISOString() });
    if (q.announcements.length > 50) q.announcements.shift();
}

// ============================================================
// AUTH & PASSWORD RESET
// ============================================================
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { identifier, password } = req.body;
        if (!identifier || !password) return res.status(400).json({ error: 'Staff ID and password required' });
        const { data: user, error } = await supabase.from('profiles').select('*').eq('staff_id', identifier.trim()).single();
        if (error || !user) return res.status(401).json({ error: 'Invalid Staff ID or password.' });
        if (user.is_active === false) return res.status(401).json({ error: 'Account is deactivated.' });
        const ok = user.password_hash ? await bcrypt.compare(password, user.password_hash) : false;
        if (!ok) return res.status(401).json({ error: 'Invalid Staff ID or password.' });
        const token = jwt.sign({ id: user.id, role: user.role, branch_id: user.branch_id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, user: safe(user), token });
    } catch (error) { res.status(500).json({ error: 'Internal server error' }); }
});

app.post('/api/auth/register', loginLimiter, async (req, res) => {
    try {
        const { fullName, phone, password, visitType } = req.body;
        if (!fullName || !phone || !password || password.length < 6) return res.status(400).json({ error: 'Please provide valid name, phone, and a password of at least 6 characters.' });
        const cleanPhone = phone.replace(/\D/g, '');
        if (cleanPhone.length < 9) return res.status(400).json({ error: 'Invalid phone number format.' });
        const { data: existing } = await supabase.from('profiles').select('id').eq('staff_id', cleanPhone).maybeSingle();
        if (existing) return res.status(400).json({ error: 'This phone number is already registered. Please sign in.' });
        const email = `${cleanPhone}@medconnect.com`;
        const { data: authData, error: authErr } = await supabase.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { full_name: fullName, role: 'patient' } });
        if (authErr) return res.status(500).json({ error: authErr.message });
        
        const hash = await bcrypt.hash(password, 10);
        const { data: profile, error: pErr } = await supabase.from('profiles').insert([{ id: authData.user.id, full_name: fullName, staff_id: cleanPhone, password_hash: hash, role: 'patient', phone: cleanPhone, is_active: true }]).select().single();
        if (pErr) { await supabase.auth.admin.deleteUser(authData.user.id); return res.status(500).json({ error: pErr.message }); }
        
        const { data: newPatient, error: patErr } = await supabase.from('patients').insert([{ full_name: fullName, phone: cleanPhone, created_by: authData.user.id, visit_type: visitType || 'First Time Check' }]).select().single();
        if (patErr) { await supabase.auth.admin.deleteUser(authData.user.id); return res.status(500).json({ error: patErr.message }); }

        const branchId = 'default';
        const q = _getQueue(branchId);
        q.seq += 1;
        const vType = visitType || 'First Time Check';
        const prefix = vType === 'Emergency' ? 'E' : 'A';
        const targetOffice = vType === 'Emergency' ? 'office-emergency' : 'office-reception';
        
        const entry = {
            id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
            number: _mkQueueNumber(prefix, q.seq),
            patient_id: newPatient.id, patient_name: fullName,
            department: vType === 'Emergency' ? 'Emergency' : 'General',
            office_id: targetOffice, visit_type: vType, status: 'waiting',
            created_at: new Date().toISOString(), created_by: authData.user.id, branch_id: branchId
        };
        q.entries.set(entry.id, entry);
        _getJourney(newPatient.id).stage = 'Waiting';

        const token = jwt.sign({ id: profile.id, role: 'patient', branch_id: null }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, message: 'Account created!', user: safe(profile), token, visitType: vType });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/queue/register', auth, (req, res) => {
    try {
        const { patient_id, patient_name, department, office_id, visit_type, contact_channel } = req.body;
        const branchId = req.user.branch_id || 'default';
        const q = _getQueue(branchId);
        q.seq += 1;
        const vType = visit_type || 'First Time Check';
        const prefix = vType === 'Emergency' ? 'E' : 'A';
        
        let targetOffice = office_id;
        if (!targetOffice) {
            if (vType === 'Emergency') targetOffice = 'office-emergency';
            else if (vType === 'Lab Test Only') targetOffice = 'office-lab';
            else targetOffice = 'office-reception';
        }

        const entry = {
            id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
            number: _mkQueueNumber(prefix, q.seq),
            patient_id, patient_name, department: department || 'General',
            office_id: targetOffice, visit_type: vType, status: 'waiting',
            created_at: new Date().toISOString(), created_by: req.user.id, branch_id: branchId,
            private_contact: contact_channel
        };
        q.entries.set(entry.id, entry);
        _getJourney(patient_id).stage = 'Waiting';
        
        _pushAnnouncement(branchId, `🎫 ${patient_name} registered. Ticket: ${entry.number}`);
        res.json({ success: true, entry });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { identifier, email } = req.body;
        if (!identifier || !email) return res.status(400).json({ error: 'Staff ID and Email required' });
        const { data: profile } = await supabase.from('profiles').select('*').eq('staff_id', identifier).maybeSingle();
        if (!profile) return res.status(404).json({ error: 'Worker not found with this ID.' });
        await supabase.from('password_reset_requests').insert([{ staff_id: profile.staff_id, full_name: profile.full_name, email: email, branch_id: profile.branch_id, status: 'pending' }]);
        res.json({ success: true, message: 'Request sent to administrators' });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/admin/password-requests', auth, role('branch_admin', 'admin', 'super_admin'), async (req, res) => {
    try {
        let q = supabase.from('password_reset_requests').select('*').eq('status', 'pending').order('created_at', { ascending: false });
        if (req.user.role === 'branch_admin' && req.user.branch_id) q = q.eq('branch_id', req.user.branch_id);
        const { data, error } = await q;
        if (error) throw error;
        res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/password-requests/:id/resolve', auth, role('branch_admin', 'admin', 'super_admin'), async (req, res) => {
    try {
        const { data: reqData } = await supabase.from('password_reset_requests').select('*').eq('id', req.params.id).single();
        if (!reqData) return res.status(404).json({ error: 'Request not found' });
        const { data: profile } = await supabase.from('profiles').select('id').eq('staff_id', reqData.staff_id).single();
        if (!profile) return res.status(404).json({ error: 'User no longer exists' });
        const newPassword = generateTempPassword(10);
        const hash = await bcrypt.hash(newPassword, 10);
        await supabase.from('profiles').update({ password_hash: hash }).eq('id', profile.id);
        try { await supabase.auth.admin.updateUserById(profile.id, { password: newPassword }); } catch (_) {}
        await supabase.from('password_reset_requests').update({ status: 'resolved' }).eq('id', req.params.id);
        res.json({ success: true, new_password: newPassword, email: reqData.email });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        const folder = (req.body.folder || 'chat_files').replace(/[^a-z0-9_\/-]/gi, '');
        const fileExt = (req.file.originalname.split('.').pop() || 'bin').toLowerCase();
        const fileName = `${Date.now()}-${Math.random().toString(36).substring(7)}.${fileExt}`;
        const filePath = `${folder}/${fileName}`;
        const { error } = await supabase.storage.from('medconnect').upload(filePath, req.file.buffer, { contentType: req.file.mimetype, upsert: false });
        if (error) throw error;
        const { data: { publicUrl } } = supabase.storage.from('medconnect').getPublicUrl(filePath);
        res.json({ success: true, url: publicUrl, type: req.file.mimetype, name: req.file.originalname, size: req.file.size });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/admin/branches', auth, role('admin', 'super_admin'), async (req, res) => {
    try {
        const { data: branches, error } = await supabase.from('branches').select('*').order('name');
        if (error) throw error;
        const adminIds = (branches || []).filter(b => b.admin_id).map(b => b.admin_id);
        let admins = [];
        if (adminIds.length) {
            const { data: p } = await supabase.from('profiles').select('id, full_name, staff_id, phone, role').in('id', adminIds);
            admins = p || [];
        }
        const map = Object.fromEntries(admins.map(a => [a.id, a]));
        res.json((branches || []).map(b => ({ ...b, admin: map[b.admin_id] || null })));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/branches', auth, role('admin', 'super_admin'), async (req, res) => {
    try {
        const { branchName, branchLocation, adminName, adminPhone } = req.body;
        if (!branchName || !adminName) return res.status(400).json({ error: 'Branch name and admin name required' });
        const slug = `${slugify(branchName)}-${Math.random().toString(36).slice(2, 6)}`;
        const { data: branch, error: bErr } = await supabase.from('branches').insert([{ name: branchName, location: branchLocation, slug }]).select('id, slug').single();
        if (bErr) throw bErr;
        const branchPrefix = slug.split('-')[0].toUpperCase().slice(0, 3);
        const adminStaffId = `${branchPrefix}-ADM-001`;
        const adminPassword = generateTempPassword(10);
        const email = `${adminStaffId.toLowerCase()}@medconnect.com`;
        const { data: authData, error: aErr } = await supabase.auth.admin.createUser({ email, password: adminPassword, email_confirm: true, user_metadata: { full_name: adminName, role: 'branch_admin' } });
        if (aErr) { await supabase.from('branches').delete().eq('id', branch.id); throw aErr; }
        const hash = await bcrypt.hash(adminPassword, 10);
        const { error: pErr } = await supabase.from('profiles').insert([{ id: authData.user.id, staff_id: adminStaffId, branch_id: branch.id, role: 'branch_admin', full_name: adminName, phone: adminPhone || null, password_hash: hash, is_active: true }]);
        if (pErr) { await supabase.auth.admin.deleteUser(authData.user.id); await supabase.from('branches').delete().eq('id', branch.id); throw pErr; }
        await supabase.from('branches').update({ admin_id: authData.user.id }).eq('id', branch.id);
        res.status(201).json({ success: true, branchId: branch.id, branchSlug: branch.slug, branchLink: `${req.protocol}://${req.get('host')}/b/${branch.slug}`, admin: { name: adminName, staff_id: adminStaffId, password: adminPassword } });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.delete('/api/admin/branches/:id', auth, role('admin', 'super_admin'), async (req, res) => {
    try { await supabase.from('branches').delete().eq('id', req.params.id); res.json({ success: true }); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// QR KIOSK (walk-in self-registration)
// ============================================================
const KIOSK_SESSIONS = new Map();

function generateKioskCode(branchId) {
    const branch = String(branchId || 'default').slice(0, 4).toUpperCase();
    const code = Math.random().toString(36).slice(2, 8).toUpperCase();
    return `${branch}-${code}`;
}

app.post('/api/kiosk/register', async (req, res) => {
    try {
        const { full_name, phone, gender, visit_type, branch_id } = req.body;
        if (!full_name || !phone) return res.status(400).json({ error: 'Name and phone are required' });
        const cleanPhone = String(phone).replace(/\D/g, '');
        if (cleanPhone.length < 9) return res.status(400).json({ error: 'Invalid phone number' });

        const { data: existing } = await supabase.from('patients').select('id, full_name, mrn, phone').eq('phone', cleanPhone).maybeSingle();
        let patient = existing;

        if (!patient) {
            const mrn = `KIO-${Date.now().toString().slice(-8)}`;
            const { data: newP, error: pErr } = await supabase.from('patients').insert([{
                full_name, mrn, phone: cleanPhone,
                gender: gender || 'Unknown',
                visit_type: visit_type || 'First Time Check',
                branch_id: branch_id || 'default',
                created_by: null
            }]).select().single();
            if (pErr) throw pErr;
            patient = newP;
        }

        const branchId = branch_id || 'default';
        const q = _getQueue(branchId);
        q.seq += 1;
        const vType = visit_type || 'First Time Check';
        const prefix = vType === 'Emergency' ? 'E' : 'K';
        let targetOffice = 'office-reception';
        if (vType === 'Emergency') targetOffice = 'office-emergency';
        else if (vType === 'Lab Test Only') targetOffice = 'office-lab';

        const entry = {
            id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
            number: _mkQueueNumber(prefix, q.seq),
            patient_id: patient.id, patient_name: patient.full_name,
            department: vType === 'Emergency' ? 'Emergency' : 'General',
            office_id: targetOffice, visit_type: vType,
            status: 'waiting', created_at: new Date().toISOString(),
            created_by: null, branch_id: branchId, source: 'kiosk'
        };
        q.entries.set(entry.id, entry);
        _getJourney(patient.id).stage = 'Waiting';
        _pushAnnouncement(branchId, `🎫 ${patient.full_name} checked in via Kiosk. Ticket: ${entry.number}`);

        res.json({
            success: true,
            ticket: entry.number, patient_name: patient.full_name,
            mrn: patient.mrn, queue_id: entry.id,
            eta_hint: 'Please wait in the reception area. You will be called shortly.'
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/kiosk/offices', (req, res) => {
    res.json(DEFAULT_OFFICES.filter(o => o.active));
});

app.get('/api/kiosk/queue-summary/:branchId', (req, res) => {
    const branchId = req.params.branchId || 'default';
    const q = _getQueue(branchId);
    const waiting = Array.from(q.entries.values()).filter(e => e.status === 'waiting');
    res.json({
        total_waiting: waiting.length,
        announcements: q.announcements.slice(-5),
        offices: Array.from(q.offices.values()).map(o => ({
            name: o.name,
            waiting: waiting.filter(e => e.office_id === o.id).length
        }))
    });
});

app.post('/api/kiosk/session', auth, role('branch_admin', 'admin', 'super_admin'), (req, res) => {
    const code = generateKioskCode(req.user.branch_id);
    KIOSK_SESSIONS.set(code, {
        code, branch_id: req.user.branch_id || 'default',
        created_by: req.user.id, created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    });
    const kioskUrl = `${req.protocol}://${req.get('host')}/kiosk/${code}`;
    res.json({ success: true, code, kiosk_url: kioskUrl });
});

// ============================================================
// SMART QUEUE
// ============================================================
app.get('/api/queue/offices', auth, (req, res) => {
    res.json(Array.from(_getQueue(req.user.branch_id || 'default').offices.values()));
});

app.get('/api/queue/list', auth, (req, res) => {
    const q = _getQueue(req.user.branch_id || 'default');
    const list = Array.from(q.entries.values())
        .filter(e => !['completed', 'cancelled'].includes(e.status))
        .sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
    res.json({ entries: list, announcements: q.announcements.slice(-10) });
});

app.post('/api/queue/:id/call', auth, (req, res) => {
    const q = _getQueue(req.user.branch_id || 'default');
    const entry = q.entries.get(req.params.id);
    if (!entry) return res.status(404).json({ error: 'Queue entry not found' });
    
    entry.status = 'called';
    entry.called_at = new Date().toISOString();
    entry.called_by = req.user.name;
    
    const office = q.offices.get(entry.office_id);
    const officeName = office?.name || 'Office';
    
    _pushAnnouncement(entry.branch_id, `📢 ${entry.patient_name}, please go to ${officeName}.`);
    
    if (entry.private_contact) {
        _pushAnnouncement(entry.branch_id, `📱 SMS sent to ${entry.patient_name}`);
    }
    res.json({ success: true, entry });
});

app.post('/api/queue/office/:officeId/next', auth, (req, res) => {
    const q = _getQueue(req.user.branch_id || 'default');
    const officeId = req.params.officeId;
    
    const nextInLine = Array.from(q.entries.values())
        .filter(e => e.office_id === officeId && e.status === 'waiting')
        .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))[0];

    if (!nextInLine) return res.status(404).json({ error: 'No patients waiting for this office.' });

    nextInLine.status = 'called';
    nextInLine.called_at = new Date().toISOString();
    
    const office = q.offices.get(officeId);
    _pushAnnouncement(nextInLine.branch_id, `📢 ${nextInLine.patient_name}, please proceed to ${office.name}.`);
    
    res.json({ success: true, patient: nextInLine });
});

app.post('/api/queue/:id/arrived', auth, (req, res) => {
    const q = _getQueue(req.user.branch_id || 'default');
    const entry = q.entries.get(req.params.id);
    if (!entry) return res.status(404).json({ error: 'Queue entry not found' });
    entry.status = 'arrived';
    entry.arrived_at = new Date().toISOString();
    _pushAnnouncement(entry.branch_id, `✅ ${entry.number} has arrived at ${q.offices.get(entry.office_id)?.name || 'Office'}.`);
    res.json({ success: true, entry });
});

app.post('/api/queue/:id/complete', auth, (req, res) => {
    const q = _getQueue(req.user.branch_id || 'default');
    const entry = q.entries.get(req.params.id);
    if (!entry) return res.status(404).json({ error: 'Queue entry not found' });
    entry.status = 'completed';
    entry.completed_at = new Date().toISOString();
    res.json({ success: true, entry });
});

app.post('/api/queue/:id/missed', auth, (req, res) => {
    const q = _getQueue(req.user.branch_id || 'default');
    const entry = q.entries.get(req.params.id);
    if (entry) { entry.status = 'missed'; entry.missed_count = (entry.missed_count || 0) + 1; }
    res.json({ success: true });
});

app.post('/api/queue/:id/recall', auth, (req, res) => {
    const q = _getQueue(req.user.branch_id || 'default');
    const entry = q.entries.get(req.params.id);
    if (entry) {
        entry.status = 'called';
        const office = q.offices.get(entry.office_id);
        _pushAnnouncement(entry.branch_id, `🔔 Recall: ${entry.patient_name}, please go to ${office.name}.`);
    }
    res.json({ success: true });
});

app.get('/api/patient/my-queue', auth, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).json({ error: 'Forbidden' });
    try {
        const { data: me } = await supabase.from('patients').select('id, visit_type, branch_id').eq('created_by', req.user.id).maybeSingle();
        if (!me) return res.json({ in_queue: false, position: null, total: 0 });

        const branchId = me.branch_id || 'default';
        const q = _getQueue(branchId);
        
        const activeEntries = Array.from(q.entries.values())
            .filter(e => e.patient_id === me.id && !['completed', 'cancelled'].includes(e.status))
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        if (activeEntries.length > 0) {
            const myTicket = activeEntries[0];
            const ahead = Array.from(q.entries.values()).filter(e =>
                e.status === 'waiting' && e.department === myTicket.department && new Date(e.created_at) < new Date(myTicket.created_at)
            ).length;

            const office = q.offices.get(myTicket.office_id);
            const isYourTurn = myTicket.status === 'called' || myTicket.status === 'arrived';
            let avgTime = myTicket.department === 'Emergency' ? 5 : 10;
            const eta = Math.max(0, ahead * avgTime);

            return res.json({
                in_queue: true, number: myTicket.number, position: ahead + 1, ahead: ahead,
                office: office ? office.name : 'Assigned Desk', department: myTicket.department,
                visit_type: myTicket.visit_type, status: myTicket.status, is_your_turn: isYourTurn, eta_minutes: eta
            });
        }
        res.json({ in_queue: false, position: null, total: 0 });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// TRIAGE
// ============================================================
const TRIAGE_CHECKLIST = [
    { id: 'chest_pain', label: 'Chest pain / tightness', severity: 'high', warning: true },
    { id: 'severe_bleeding', label: 'Severe bleeding', severity: 'critical', warning: true },
    { id: 'difficulty_breathing', label: 'Difficulty breathing / shortness of breath', severity: 'critical', warning: true },
    { id: 'unconscious', label: 'Loss of consciousness / fainting', severity: 'critical', warning: true },
    { id: 'severe_headache', label: 'Severe sudden headache', severity: 'high', warning: true },
    { id: 'high_fever', label: 'High fever (≥ 39.5°C) in adult', severity: 'medium', warning: true },
    { id: 'seizure', label: 'Seizure / convulsions', severity: 'critical', warning: true },
    { id: 'stroke_signs', label: 'Sudden weakness / slurred speech (stroke)', severity: 'critical', warning: true }
];

app.get('/api/triage/checklist', auth, (req, res) => res.json(TRIAGE_CHECKLIST));

app.post('/api/triage/flag', auth, (req, res) => {
    const { patient_id, patient_name, symptoms, vitals, checklist_ids, notes } = req.body;
    if (!patient_id) return res.status(400).json({ error: 'patient_id required' });
    const ids = Array.isArray(checklist_ids) ? checklist_ids : [];
    const matched = TRIAGE_CHECKLIST.filter(c => ids.includes(c.id));
    const hasWarning = matched.length > 0;
    const highest = matched.some(m => m.severity === 'critical') ? 'critical' : matched.some(m => m.severity === 'high') ? 'high' : 'medium';
    const flag = {
        id: `flag-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        patient_id, patient_name: patient_name || 'Patient', symptoms: symptoms || '', vitals: vitals || {},
        checklist_ids: ids, matched, has_warning: hasWarning, severity: hasWarning ? highest : 'none',
        notes: notes || '', flagged_by: req.user.name, flagged_by_id: req.user.id,
        branch_id: req.user.branch_id || 'default', status: hasWarning ? 'needs_review' : 'cleared', created_at: new Date().toISOString()
    };
    TRIAGE_FLAGS.set(flag.id, flag);
    if (hasWarning) {
        _pushAnnouncement(flag.branch_id, `🚨 URGENT FLAG: ${patient_name} — ${matched.map(m => m.label).join(', ')}. Immediate assessment required.`);
    }
    res.json({ success: true, flag });
});

app.get('/api/triage/flags', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    const list = Array.from(TRIAGE_FLAGS.values()).filter(f => f.branch_id === branchId).sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    res.json(list);
});

app.post('/api/triage/flags/:id/resolve', auth, (req, res) => {
    const f = TRIAGE_FLAGS.get(req.params.id);
    if (!f) return res.status(404).json({ error: 'Flag not found' });
    f.status = 'resolved'; f.resolved_at = new Date().toISOString();
    f.resolved_by = req.user.name; f.resolution_note = req.body.note || '';
    res.json({ success: true, flag: f });
});

app.post('/api/triage/flags/:id/override', auth, role('doctor', 'surgeon', 'gp', 'health_officer', 'branch_admin', 'admin', 'super_admin'), (req, res) => {
    const f = TRIAGE_FLAGS.get(req.params.id);
    if (!f) return res.status(404).json({ error: 'Flag not found' });
    const override = {
        id: `ovr-${Date.now()}`, flag_id: f.id, patient_id: f.patient_id,
        decided_by: req.user.name, decided_by_id: req.user.id, decided_role: req.user.role,
        reason: req.body.reason || 'No reason provided', created_at: new Date().toISOString()
    };
    TRIAGE_OVERRIDES.set(override.id, override);
    f.status = 'overridden'; f.override = override;
    res.json({ success: true, override });
});

// ============================================================
// DIRECT WEBRTC CALLS (IMO STYLE)
// ============================================================
const CALL_SIGNALS = [];
let callSeq = 0;

function pushCallSignal(from, to, type, payload) {
    callSeq += 1;
    CALL_SIGNALS.push({ seq: callSeq, from, to, type, payload, at: Date.now() });
    const cutoff = Date.now() - 60_000;
    const filtered = CALL_SIGNALS.filter(s => s.at > cutoff);
    CALL_SIGNALS.length = 0;
    CALL_SIGNALS.push(...filtered);
}

app.post('/api/call/signal', auth, async (req, res) => {
    try {
        const { to, type, payload } = req.body;
        if (!to || !type) return res.status(400).json({ error: 'to and type required' });
        const enrichedPayload = { ...payload, fromName: req.user.name };
        pushCallSignal(req.user.id, to, type, enrichedPayload);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/call/signal', auth, async (req, res) => {
    try {
        const since = parseInt(req.query.since || '0', 10);
        const mine = CALL_SIGNALS.filter(s => s.seq > since && (s.to === req.user.id || s.from === req.user.id));
        const lastSeq = CALL_SIGNALS.length ? CALL_SIGNALS[CALL_SIGNALS.length - 1].seq : since;
        res.json({ signals: mine, lastSeq });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// LIVE CONFERENCE
// ============================================================
const LIVE = { active: false, startedAt: null, moderators: new Set(), participants: new Map(), requests: new Map(), signals: [], seq: 0 };

function pushSignal(from, to, type, payload) {
    LIVE.seq += 1;
    LIVE.signals.push({ seq: LIVE.seq, from, to, type, payload, at: Date.now() });
    const cutoff = Date.now() - 90_000;
    LIVE.signals = LIVE.signals.filter(s => s.at > cutoff).slice(-500);
}

const LIVE_GUARDS = ['admin', 'super_admin', 'branch_admin'];
const isLiveMod = (user) => LIVE_GUARDS.includes(user.role) || LIVE.moderators.has(user.id);

app.post('/api/live/toggle', auth, role(...LIVE_GUARDS), async (req, res) => {
    try {
        const on = !!req.body.on;
        if (on) { 
            LIVE.active = true; LIVE.startedAt = new Date().toISOString(); LIVE.moderators.add(req.user.id); 
        } else { 
            LIVE.active = false; LIVE.startedAt = null; LIVE.moderators.clear(); 
            LIVE.participants.clear(); LIVE.requests.clear(); LIVE.signals = []; 
        }
        pushSignal('system', '*', on ? 'live-on' : 'live-off', {});
        res.json({ success: true, active: LIVE.active });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/live/grant-moderator', auth, async (req, res) => {
    try {
        if (!isLiveMod(req.user)) return res.status(403).json({ error: 'Only moderators can promote' });
        const { userId } = req.body;
        LIVE.moderators.add(userId);
        pushSignal('system', userId, 'granted-mod', { by: req.user.id });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/live/participant-status', auth, async (req, res) => {
    try {
        const { muted, cameraOff, handRaised } = req.body;
        const p = LIVE.participants.get(req.user.id);
        if (p) {
            if (muted !== undefined) p.muted = muted;
            if (cameraOff !== undefined) p.cameraOff = cameraOff;
            if (handRaised !== undefined) p.handRaised = handRaised;
            pushSignal(req.user.id, '*', 'status-update', { id: req.user.id, muted: p.muted, cameraOff: p.cameraOff, handRaised: p.handRaised });
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/live/status', auth, async (req, res) => {
    try {
        const myRequest = LIVE.requests.get(req.user.id) || null;
        const me = LIVE.participants.get(req.user.id) || null;
        const amMod = isLiveMod(req.user);
        let moderator = null;
        if (LIVE.moderators.size) {
            const firstModId = Array.from(LIVE.moderators)[0];
            const { data } = await supabase.from('profiles').select('id, full_name, role, avatar_url').eq('id', firstModId).maybeSingle();
            moderator = data || null;
        }
        res.json({
            active: LIVE.active, startedAt: LIVE.startedAt, participantCount: LIVE.participants.size,
            participants: Array.from(LIVE.participants.values()), myRequest,
            iAmParticipant: !!me, iAmModerator: amMod, moderator, moderatorCount: LIVE.moderators.size
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/live/request', auth, async (req, res) => {
    try {
        if (!LIVE.active) return res.status(400).json({ error: 'Live conference is not active' });
        if (LIVE.moderators.has(req.user.id)) return res.status(400).json({ error: 'You are a moderator' });
        LIVE.requests.set(req.user.id, {
            id: req.user.id, name: req.user.name, role: req.user.role, staff_id: req.user.staff_id,
            lang: req.body.lang || 'English', requestedAt: new Date().toISOString(), status: 'pending'
        });
        pushSignal('system', '*', 'new-request', { userId: req.user.id, name: req.user.name });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/live/requests', auth, async (req, res) => {
    try {
        if (!isLiveMod(req.user)) return res.status(403).json({ error: 'Not a moderator' });
        res.json({
            active: LIVE.active, requests: Array.from(LIVE.requests.values()).filter(r => r.status === 'pending'),
            participants: Array.from(LIVE.participants.values()), moderators: Array.from(LIVE.moderators)
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/live/requests/:userId/:action', auth, async (req, res) => {
    try {
        if (!isLiveMod(req.user)) return res.status(403).json({ error: 'Not a moderator' });
        const { userId, action } = req.params;
        const reqObj = LIVE.requests.get(userId);
        if (!reqObj) return res.status(404).json({ error: 'Request not found' });
        if (action === 'approve') {
            reqObj.status = 'approved';
            LIVE.participants.set(userId, { id: userId, name: reqObj.name, role: reqObj.role, lang: reqObj.lang, joinedAt: new Date().toISOString(), muted: false, cameraOff: false, handRaised: false });
            pushSignal('system', userId, 'approved', { by: req.user.id });
        } else {
            reqObj.status = 'rejected'; LIVE.requests.delete(userId);
            pushSignal('system', userId, 'rejected', { by: req.user.id });
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/live/leave', auth, async (req, res) => {
    try {
        LIVE.participants.delete(req.user.id); LIVE.requests.delete(req.user.id);
        pushSignal(req.user.id, '*', 'participant-left', { userId: req.user.id });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/live/signal', auth, async (req, res) => {
    try {
        const { to, type, payload } = req.body;
        if (!to || !type) return res.status(400).json({ error: 'to and type required' });
        pushSignal(req.user.id, to, type, payload || {});
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/live/signal', auth, async (req, res) => {
    try {
        const since = parseInt(req.query.since || '0', 10);
        const mine = LIVE.signals.filter(s => s.seq > since && (s.to === req.user.id || s.to === '*' || s.from === req.user.id));
        const lastSeq = LIVE.signals.length ? LIVE.signals[LIVE.signals.length - 1].seq : since;
        res.json({ signals: mine, lastSeq });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// ETA ENGINE (data-driven wait prediction)
// ============================================================
const ETA_HISTORY = new Map();

function recordEtaSample(branchId, department, waitMinutes) {
    if (!ETA_HISTORY.has(branchId)) ETA_HISTORY.set(branchId, []);
    const arr = ETA_HISTORY.get(branchId);
    arr.push({ department, waitMinutes, timestamp: Date.now() });
    if (arr.length > 500) arr.shift();
}

function getAvgServiceTime(branchId, department) {
    const arr = ETA_HISTORY.get(branchId) || [];
    const deptSamples = arr.filter(s => s.department === department).slice(-30);
    if (deptSamples.length === 0) {
        const defaults = { 'Emergency': 8, 'Laboratory': 12, 'Pharmacy': 6, 'Clinical': 15, 'Reception': 5 };
        return defaults[department] || 10;
    }
    const sum = deptSamples.reduce((a, b) => a + b.waitMinutes, 0);
    return Math.max(2, Math.round(sum / deptSamples.length));
}

app.get('/api/queue/eta/:entryId', auth, (req, res) => {
    const q = _getQueue(req.user.branch_id || 'default');
    const entry = q.entries.get(req.params.entryId);
    if (!entry) return res.status(404).json({ error: 'Queue entry not found' });

    const branchId = req.user.branch_id || 'default';
    const ahead = Array.from(q.entries.values()).filter(e =>
        e.status === 'waiting' &&
        e.department === entry.department &&
        e.office_id === entry.office_id &&
        new Date(e.created_at) < new Date(entry.created_at)
    ).length;

    const avgService = getAvgServiceTime(branchId, entry.department);
    const officeLoad = Array.from(q.entries.values()).filter(e => e.office_id === entry.office_id && e.status === 'waiting').length;
    const congestionFactor = officeLoad > 5 ? 1.3 : officeLoad > 3 ? 1.15 : 1.0;
    const eta = Math.round(ahead * avgService * congestionFactor);

    const samples = (ETA_HISTORY.get(branchId) || []).filter(s => s.department === entry.department).length;
    const confidence = samples > 20 ? 'high' : samples > 5 ? 'medium' : 'low';

    res.json({
        entry_number: entry.number, department: entry.department,
        office: q.offices.get(entry.office_id)?.name || 'Office',
        patients_ahead: ahead, avg_service_minutes: avgService,
        congestion_factor: congestionFactor, eta_minutes: eta,
        confidence, sample_size: samples,
        factors: [
            { name: 'Patients ahead', value: ahead, weight: 'high' },
            { name: 'Avg service time', value: `${avgService}m`, weight: 'high' },
            { name: 'Office congestion', value: officeLoad, weight: 'medium' }
        ]
    });
});

app.get('/api/queue/eta-insights', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    const arr = ETA_HISTORY.get(branchId) || [];
    const byDept = {};
    for (const s of arr) { if (!byDept[s.department]) byDept[s.department] = []; byDept[s.department].push(s.waitMinutes); }
    const insights = Object.entries(byDept).map(([dept, samples]) => ({
        department: dept,
        avg_wait: Math.round(samples.reduce((a, b) => a + b, 0) / samples.length),
        min_wait: Math.min(...samples), max_wait: Math.max(...samples),
        sample_count: samples.length
    }));
    const hourly = {};
    const now = Date.now();
    for (const s of arr) {
        const hoursAgo = Math.floor((now - s.timestamp) / (60 * 60 * 1000));
        if (hoursAgo > 23) continue;
        const h = new Date(s.timestamp).getHours();
        if (!hourly[h]) hourly[h] = [];
        hourly[h].push(s.waitMinutes);
    }
    const hourlyPattern = Object.entries(hourly).map(([h, samples]) => ({
        hour: parseInt(h),
        avg_wait: Math.round(samples.reduce((a, b) => a + b, 0) / samples.length),
        count: samples.length
    })).sort((a, b) => a.hour - b.hour);
    res.json({ by_department: insights, hourly_pattern: hourlyPattern, total_samples: arr.length });
});

app.post('/api/queue/:id/complete-eta', auth, (req, res) => {
    const q = _getQueue(req.user.branch_id || 'default');
    const entry = q.entries.get(req.params.id);
    if (!entry) return res.status(404).json({ error: 'Not found' });
    const waitMins = Math.floor((Date.now() - new Date(entry.created_at).getTime()) / 60000);
    recordEtaSample(req.user.branch_id || 'default', entry.department, waitMins);
    res.json({ success: true, waitMins });
});

// ============================================================
// TRANSLATION & AI
// ============================================================
app.get('/api/translate/languages', auth, (req, res) => {
    res.json(['English', 'Amharic', 'Afaan Oromoo', 'Tigrinya', 'Somali'].map(name => ({ name })));
});

app.post('/api/translate', auth, async (req, res) => {
    try {
        const { text, targetLang, sourceLang } = req.body;
        if (!text || !text.trim()) return res.json({ translatedText: '' });
        const langMap = { 'English': 'en', 'Amharic': 'am', 'Afaan Oromoo': 'om', 'Tigrinya': 'ti', 'Somali': 'so' };
        const target = langMap[targetLang] || 'am';
        const source = sourceLang ? (langMap[sourceLang] || 'auto') : 'auto';
        const url = `https://translate.googleapis.com/translate_a/single?client=gtx&sl=${source}&tl=${target}&dt=t&q=${encodeURIComponent(text)}`;
        const response = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        if (!response.ok) throw new Error('Google Translate API error');
        const data = await response.json();
        if (data && data[0] && data[0][0] && data[0][0][0]) {
            const translatedText = data[0].map(item => item[0]).join('');
            return res.json({ translatedText });
        }
        throw new Error('Translation failed');
    } catch (error) { res.status(500).json({ error: 'Translation failed' }); }
});

app.post('/api/ai', auth, async (req, res) => {
    try {
        const { prompt, lang } = req.body;
        if (!prompt) return res.status(400).json({ error: 'Prompt required' });
        const systemPrompt = `You are MedConnect AI, an advanced medical and system assistant.
        The user is speaking in ${lang || 'English'}. You MUST reply strictly in ${lang || 'English'}.
        If the user describes symptoms, provide a detailed analysis of possible conditions, what they should do, and a medical disclaimer.`;
        let aiText = '';
        try {
            const response = await fetch('https://text.pollinations.ai/', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: prompt }], model: 'openai' })
            });
            if (response.ok) aiText = await response.text();
        } catch (e) { console.log('Pollinations failed, trying fallback...'); }
        if (!aiText || aiText.includes('error')) {
            const p = prompt.toLowerCase();
            if (p.includes('cancer') || p.includes('tumor')) {
                aiText = `I am very sorry to hear that you are dealing with a cancer diagnosis. Cancer is a complex group of diseases, and treatment depends heavily on the specific type and stage. Please ensure you are working closely with an oncologist.`;
            } else if (p.includes('fever') || p.includes('headache') || p.includes('pain')) {
                aiText = `I understand you are not feeling well. Symptoms like fever and headache can be caused by many conditions. I recommend resting, staying hydrated, and monitoring your temperature. If symptoms persist for more than 48 hours, please book an appointment.`;
            } else {
                aiText = `I am here to help. You mentioned: "${prompt}". If you are experiencing medical symptoms, please describe them in detail so I can provide better guidance.`;
            }
        }
        res.json({ text: aiText });
    } catch (error) { res.status(500).json({ error: 'Failed to process AI request' }); }
});

// ============================================================
// FEATURE 3: PATIENT JOURNEY TRACKER (With Auto-Routing)
// ============================================================
app.get('/api/journey/stages', auth, (req, res) => res.json(JOURNEY_STAGES));

app.get('/api/journey/:patientId', auth, (req, res) => {
    const j = _getJourney(req.params.patientId);
    const stageIndex = JOURNEY_STAGES.indexOf(j.stage);
    const nextStage = stageIndex >= 0 && stageIndex < JOURNEY_STAGES.length - 1 ? JOURNEY_STAGES[stageIndex + 1] : null;
    res.json({ ...j, next_stage: nextStage, all_stages: JOURNEY_STAGES });
});

app.post('/api/journey/:patientId/advance', auth, (req, res) => {
    const j = _getJourney(req.params.patientId);
    const { stage } = req.body;
    const target = stage || JOURNEY_STAGES[JOURNEY_STAGES.indexOf(j.stage) + 1];
    
    if (!target || !JOURNEY_STAGES.includes(target)) return res.status(400).json({ error: 'Invalid stage' });
    
    j.stage = target;
    j.updated_at = new Date().toISOString();
    j.history.push({ stage: target, at: j.updated_at, by: req.user.name });

    const branchId = req.user.branch_id || 'default';
    const q = _getQueue(branchId);
    
    for (let entry of q.entries.values()) {
        if (entry.patient_id === req.params.patientId && !['completed', 'cancelled'].includes(entry.status)) {
            entry.status = 'completed';
        }
    }

    let assignedOfficeId = null;
    let deptName = 'General';

    if (target === 'Laboratory') { assignedOfficeId = 'office-lab'; deptName = 'Laboratory'; }
    else if (target === 'Pharmacy') { assignedOfficeId = 'office-pharmacy'; deptName = 'Pharmacy'; }
    else if (target === 'With clinician') { assignedOfficeId = 'office-doctor-1'; deptName = 'Clinical'; }
    else if (target === 'Emergency') { assignedOfficeId = 'office-emergency'; deptName = 'Emergency'; }
    else if (target === 'Waiting') { assignedOfficeId = 'office-reception'; deptName = 'Reception'; }

    if (assignedOfficeId) {
        q.seq += 1;
        const prefix = deptName === 'Emergency' ? 'E' : 'A';
        
        const newEntry = {
            id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
            number: _mkQueueNumber(prefix, q.seq),
            patient_id: req.params.patientId,
            patient_name: req.body.patient_name || j.patient_name || 'Patient',
            department: deptName,
            office_id: assignedOfficeId,
            visit_type: deptName === 'Emergency' ? 'Emergency' : 'Follow-up',
            status: 'waiting',
            created_at: new Date().toISOString(),
            created_by: req.user.id,
            branch_id: branchId
        };
        q.entries.set(newEntry.id, newEntry);
        _pushAnnouncement(branchId, `🔄 ${newEntry.patient_name} moved to ${deptName}. Ticket: ${newEntry.number}`);
    }

    res.json({ success: true, journey: j });
});

app.get('/api/journey/dashboard', auth, (req, res) => {
    const now = Date.now();
    const all = Array.from(JOURNEYS.values());
    const longWaiting = all.filter(j => j.stage === 'Waiting' && (now - new Date(j.updated_at).getTime()) > 30 * 60 * 1000);
    const byStage = {};
    for (const s of JOURNEY_STAGES) byStage[s] = all.filter(j => j.stage === s).length;
    res.json({ total: all.length, by_stage: byStage, long_waiting: longWaiting });
});

// ============================================================
// FEATURE 4: LAB-RESULT TRACKING & PING-PONG ROUTING
// ============================================================
const LAB_STATUSES = ['ordered', 'collected', 'processing', 'ready'];
const LAB_ALERTS = [];

app.get('/api/lab-statuses', auth, (req, res) => res.json(LAB_STATUSES));

app.post('/api/lab-orders/:id/status', auth, role('lab_tech', 'radiologist', 'radiology_tech', 'admin', 'super_admin', 'branch_admin', 'doctor', 'nurse'), async (req, res) => {
    try {
        const { status, result_summary, patient_name } = req.body;
        if (!LAB_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status' });
        const { data: order, error } = await supabase.from('lab_orders').select('*').eq('id', req.params.id).single();
        if (error || !order) return res.status(404).json({ error: 'Order not found' });
        
        const update = { status, updated_at: new Date().toISOString() };
        if (status === 'ready') {
            update.result_at = new Date().toISOString();
            update.result_summary = result_summary || 'Result ready';
            update.reviewed = false;
        }
        const { data, error: uErr } = await supabase.from('lab_orders').update(update).eq('id', req.params.id).select().single();
        if (uErr) throw uErr;
        
        if (status === 'ready') {
            LAB_ALERTS.push({
                id: `lab-alert-${Date.now()}`,
                order_id: order.id, patient_id: order.patient_id,
                ordered_by: order.ordered_by, test_name: order.test_name,
                message: 'Result ready for review',
                created_at: new Date().toISOString(), reviewed: false
            });
            _pushAnnouncement(req.user.branch_id || 'default', `🧪 Lab result READY. Clinician notified (private).`);

            const q = _getQueue(req.user.branch_id || 'default');
            q.seq += 1;
            const returnTicket = {
                id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
                number: _mkQueueNumber('R', q.seq),
                patient_id: order.patient_id,
                patient_name: patient_name || 'Patient', 
                department: 'Clinical',
                office_id: 'office-doctor-1',
                visit_type: 'Lab Result Review',
                status: 'waiting',
                created_at: new Date().toISOString()
            };
            q.entries.set(returnTicket.id, returnTicket);
            _pushAnnouncement(req.user.branch_id, `🔄 ${returnTicket.patient_name} back to Doctor for result review. Ticket: ${returnTicket.number}`);
        }
        res.json({ success: true, order: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/lab-orders/:id/review', auth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('lab_orders').update({
            reviewed: true, reviewed_by: req.user.id, reviewed_at: new Date().toISOString()
        }).eq('id', req.params.id).select().single();
        if (error) throw error;
        for (const a of LAB_ALERTS) if (a.order_id === req.params.id) a.reviewed = true;
        res.json({ success: true, order: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/lab-alerts', auth, (req, res) => {
    res.json(LAB_ALERTS.filter(a => !a.reviewed).slice(-50));
});

// ============================================================
// FEATURE 5 & 6: FOLLOW-UP REMINDERS
// ============================================================
const FOLLOWUPS = new Map();
const CONTRACEPTIVE_METHODS = [
    { code: 'pill', name: 'Combined oral contraceptive pill', default_days: 28, note: 'Monthly refill' },
    { code: 'injectable', name: 'Injectable (DMPA)', default_days: 90, note: 'Every 3 months' },
    { code: 'implant', name: 'Implant', default_days: 1095, note: 'Every 3 years (clinician confirm)' },
    { code: 'iud', name: 'IUD', default_days: 1825, note: 'Every 5 years (clinician confirm)' },
    { code: 'condom', name: 'Condoms', default_days: 30, note: 'Resupply' },
    { code: 'other', name: 'Other (clinician confirmed)', default_days: null, note: 'Clinician must set date' }
];

app.get('/api/followup/methods', auth, (req, res) => res.json(CONTRACEPTIVE_METHODS));

app.post('/api/followup', auth, (req, res) => {
    try {
        const { patient_id, patient_name, type, method_code, clinician_confirmed_date, purpose, contact_channel, channel_verified, contact_address } = req.body;
        if (!patient_id) return res.status(400).json({ error: 'patient_id required' });
        const typeNorm = type === 'contraceptive' ? 'contraceptive' : 'general';
        let due_date = clinician_confirmed_date;
        if (typeNorm === 'contraceptive') {
            if (!clinician_confirmed_date) return res.status(400).json({ error: 'Clinician must confirm the return date for contraceptive follow-up' });
            due_date = clinician_confirmed_date;
        }
        if (!due_date) return res.status(400).json({ error: 'Follow-up date required' });
        const item = {
            id: `fu-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            patient_id, patient_name: patient_name || 'Patient',
            type: typeNorm, method_code: method_code || null,
            method_label: method_code ? (CONTRACEPTIVE_METHODS.find(m => m.code === method_code)?.name || method_code) : null,
            purpose: purpose || '', due_date, clinician_confirmed: true,
            clinician_id: req.user.id, clinician_name: req.user.name,
            contact_channel: contact_channel || 'app', contact_address: contact_address || null,
            channel_verified: !!channel_verified,
            status: 'scheduled', reminder_history: [],
            branch_id: req.user.branch_id || 'default',
            created_at: new Date().toISOString()
        };
        FOLLOWUPS.set(item.id, item);
        res.json({ success: true, followup: item });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/followup', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    const all = Array.from(FOLLOWUPS.values()).filter(f => f.branch_id === branchId);
    const now = Date.now();
    for (const f of all) {
        if (f.status === 'scheduled' && new Date(f.due_date).getTime() < now) f.status = 'overdue';
    }
    res.json(all.sort((a, b) => new Date(a.due_date) - new Date(b.due_date)));
});

app.get('/api/followup/due', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    const now = new Date();
    const all = Array.from(FOLLOWUPS.values()).filter(f => f.branch_id === branchId);
    const due = all.filter(f => {
        const d = new Date(f.due_date);
        const diff = d.getTime() - now.getTime();
        return diff <= 3 * 24 * 60 * 60 * 1000;
    });
    res.json(due);
});

app.post('/api/followup/:id/send-reminder', auth, (req, res) => {
    const f = FOLLOWUPS.get(req.params.id);
    if (!f) return res.status(404).json({ error: 'Follow-up not found' });
    if (!f.channel_verified) return res.status(400).json({ error: 'Contact channel not verified' });
    const entry = { at: new Date().toISOString(), by: req.user.name, channel: f.contact_channel, status: 'sent' };
    f.reminder_history.push(entry);
    f.status = 'sent';
    _pushAnnouncement(f.branch_id, `📩 Discreet reminder sent (${f.contact_channel}) — no sensitive details disclosed.`);
    res.json({ success: true, followup: f });
});

app.post('/api/followup/:id/outcome', auth, (req, res) => {
    const f = FOLLOWUPS.get(req.params.id);
    if (!f) return res.status(404).json({ error: 'Follow-up not found' });
    const { returned, note, next_due_date } = req.body;
    f.status = returned ? 'returned' : 'overdue';
    f.outcome_note = note || '';
    f.outcome_at = new Date().toISOString();
    f.outcome_by = req.user.name;
    if (next_due_date) {
        const next = { ...f, id: `fu-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`, due_date: next_due_date, status: 'scheduled', reminder_history: [], created_at: new Date().toISOString(), outcome_note: null, outcome_at: null };
        FOLLOWUPS.set(next.id, next);
    }
    res.json({ success: true, followup: f });
});

app.get('/api/followup/dashboard', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    const all = Array.from(FOLLOWUPS.values()).filter(f => f.branch_id === branchId);
    res.json({
        total: all.length,
        scheduled: all.filter(f => f.status === 'scheduled').length,
        sent: all.filter(f => f.status === 'sent').length,
        delivered: all.filter(f => f.status === 'delivered').length,
        failed: all.filter(f => f.status === 'failed').length,
        overdue: all.filter(f => f.status === 'overdue').length,
        returned: all.filter(f => f.status === 'returned').length
    });
});

// ============================================================
// FEATURE 7: MEDICINE STOCK & EXPIRY ALERTS
// ============================================================
const STOCK_ITEMS = new Map();
const STOCK_ALERTS = new Map();

const DEMO_STOCK = [
    { item_name: 'Paracetamol 500mg', quantity: 450, unit: 'tablets', reorder_level: 100, expiry_date: '2027-06-30', batch: 'PAR-2024-A' },
    { item_name: 'Amoxicillin 250mg', quantity: 22, unit: 'capsules', reorder_level: 50, expiry_date: '2026-03-15', batch: 'AMX-2024-C' },
    { item_name: 'ORS sachets', quantity: 8, unit: 'sachets', reorder_level: 30, expiry_date: '2026-01-10', batch: 'ORS-2024-B' },
    { item_name: 'Insulin (rapid)', quantity: 12, unit: 'vials', reorder_level: 10, expiry_date: '2026-02-28', batch: 'INS-2024-X' },
    { item_name: 'Ibuprofen 400mg', quantity: 180, unit: 'tablets', reorder_level: 80, expiry_date: '2027-12-31', batch: 'IBU-2024-D' },
    { item_name: 'Morphine 10mg/mL', quantity: 5, unit: 'amps', reorder_level: 10, expiry_date: '2026-04-20', batch: 'MOR-2024-E' }
];

for (const s of DEMO_STOCK) {
    const id = `stock-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    STOCK_ITEMS.set(id, {
        id, ...s, quantity: Number(s.quantity), reorder_level: Number(s.reorder_level),
        branch_id: 'default', created_at: new Date().toISOString()
    });
}

function _computeStockStatus(item) {
    const today = new Date();
    const expiry = new Date(item.expiry_date);
    const daysToExpiry = Math.ceil((expiry - today) / (1000 * 60 * 60 * 24));
    const lowStock = item.quantity <= item.reorder_level;
    const nearExpiry = daysToExpiry <= 90;
    const expired = daysToExpiry < 0;
    return { lowStock, nearExpiry, expired, daysToExpiry };
}

app.get('/api/stock', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    const items = Array.from(STOCK_ITEMS.values()).filter(i => i.branch_id === branchId)
        .map(i => ({ ...i, ..._computeStockStatus(i) }));
    res.json(items);
});

app.post('/api/stock', auth, role('pharmacist', 'pharmacy_tech', 'medical_supply_officer', 'admin', 'super_admin', 'branch_admin'), (req, res) => {
    const { item_name, quantity, unit, reorder_level, expiry_date, batch } = req.body;
    if (!item_name) return res.status(400).json({ error: 'item_name required' });
    const id = `stock-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const item = {
        id, item_name, quantity: Number(quantity) || 0, unit: unit || 'units',
        reorder_level: Number(reorder_level) || 10,
        expiry_date: expiry_date || null, batch: batch || null,
        branch_id: req.user.branch_id || 'default', created_at: new Date().toISOString()
    };
    STOCK_ITEMS.set(id, item);
    _evaluateStockAlerts(item);
    res.json({ success: true, item });
});

app.post('/api/stock/:id/adjust', auth, role('pharmacist', 'pharmacy_tech', 'medical_supply_officer', 'admin', 'super_admin', 'branch_admin'), (req, res) => {
    const item = STOCK_ITEMS.get(req.params.id);
    if (!item) return res.status(404).json({ error: 'Stock item not found' });
    item.quantity = Math.max(0, item.quantity + Number(req.body.delta || 0));
    _evaluateStockAlerts(item);
    res.json({ success: true, item: { ...item, ..._computeStockStatus(item) } });
});

function _evaluateStockAlerts(item) {
    const s = _computeStockStatus(item);
    const key = (type) => `${item.id}-${type}`;
    if (s.lowStock && !STOCK_ALERTS.has(key('low'))) {
        STOCK_ALERTS.set(key('low'), { id: key('low'), item_id: item.id, item_name: item.item_name, type: 'low_stock', message: `${item.item_name} is LOW (${item.quantity} ${item.unit}, reorder at ${item.reorder_level})`, branch_id: item.branch_id, created_at: new Date().toISOString(), acknowledged: false });
    }
    if (s.nearExpiry && !s.expired && !STOCK_ALERTS.has(key('expiry'))) {
        STOCK_ALERTS.set(key('expiry'), { id: key('expiry'), item_id: item.id, item_name: item.item_name, type: 'near_expiry', message: `${item.item_name} expires in ${s.daysToExpiry} days`, branch_id: item.branch_id, created_at: new Date().toISOString(), acknowledged: false });
    }
    if (s.expired && !STOCK_ALERTS.has(key('expired'))) {
        STOCK_ALERTS.set(key('expired'), { id: key('expired'), item_id: item.id, item_name: item.item_name, type: 'expired', message: `${item.item_name} EXPIRED on ${item.expiry_date}`, branch_id: item.branch_id, created_at: new Date().toISOString(), acknowledged: false });
    }
}

for (const item of STOCK_ITEMS.values()) _evaluateStockAlerts(item);

app.get('/api/stock/alerts', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    const alerts = Array.from(STOCK_ALERTS.values()).filter(a => a.branch_id === branchId && !a.acknowledged);
    res.json(alerts);
});

app.post('/api/stock/alerts/:id/ack', auth, (req, res) => {
    const a = STOCK_ALERTS.get(req.params.id);
    if (!a) return res.status(404).json({ error: 'Alert not found' });
    a.acknowledged = true;
    a.acknowledged_by = req.user.name;
    a.acknowledged_at = new Date().toISOString();
    res.json({ success: true, alert: a });
});

// ============================================================
// FEATURE 8: REFERRAL TRACKING
// ============================================================
const REFERRAL_STAGES = ['sent', 'accepted', 'completed', 'returned'];
const REFERRALS = new Map();

app.get('/api/referral/stages', auth, (req, res) => res.json(REFERRAL_STAGES));

app.post('/api/referral/track', auth, (req, res) => {
    try {
        const { patient_id, patient_name, destination_facility, reason, urgency, notes } = req.body;
        if (!patient_id || !destination_facility) return res.status(400).json({ error: 'patient_id and destination_facility required' });
        const ref = {
            id: `ref-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            patient_id, patient_name: patient_name || 'Patient',
            destination_facility, reason: reason || '', urgency: urgency || 'routine',
            notes: notes || '', status: 'sent', sent_at: new Date().toISOString(),
            sent_by: req.user.name, sent_by_id: req.user.id,
            branch_id: req.user.branch_id || 'default',
            history: [{ status: 'sent', at: new Date().toISOString(), by: req.user.name }]
        };
        REFERRALS.set(ref.id, ref);
        res.json({ success: true, referral: ref });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/referral/track', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    res.json(Array.from(REFERRALS.values()).filter(r => r.branch_id === branchId)
        .sort((a, b) => new Date(b.sent_at) - new Date(a.sent_at)));
});

app.post('/api/referral/track/:id/update', auth, (req, res) => {
    const ref = REFERRALS.get(req.params.id);
    if (!ref) return res.status(404).json({ error: 'Referral not found' });
    const { status, note } = req.body;
    if (!REFERRAL_STAGES.includes(status)) return res.status(400).json({ error: 'Invalid status' });
    ref.status = status;
    ref.history.push({ status, at: new Date().toISOString(), by: req.user.name, note: note || '' });
    res.json({ success: true, referral: ref });
});

app.get('/api/referral/dashboard', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    const all = Array.from(REFERRALS.values()).filter(r => r.branch_id === branchId);
    res.json({
        total: all.length,
        sent: all.filter(r => r.status === 'sent').length,
        accepted: all.filter(r => r.status === 'accepted').length,
        completed: all.filter(r => r.status === 'completed').length,
        needs_followup: all.filter(r => r.status === 'sent' || r.status === 'accepted').length
    });
});

// ============================================================
// FEATURE 9: CLINICIAN HANDOVER SUMMARY
// ============================================================
app.post('/api/handover', auth, async (req, res) => {
    try {
        const { patient_id } = req.body;
        if (!patient_id) return res.status(400).json({ error: 'patient_id required' });
        const [patientRes, apptsRes, labRes, rxRes] = await Promise.all([
            supabase.from('patients').select('*').eq('id', patient_id).maybeSingle(),
            supabase.from('appointments').select('*').eq('patient_id', patient_id).order('scheduled_at', { ascending: false }).limit(5),
            supabase.from('lab_orders').select('*').eq('patient_id', patient_id).order('created_at', { ascending: false }).limit(5),
            supabase.from('prescriptions').select('*').eq('patient_id', patient_id).order('created_at', { ascending: false }).limit(5)
        ]);
        const patient = patientRes.data;
        if (!patient) return res.status(404).json({ error: 'Patient not found' });
        const missing = [];
        const summary = {
            id: `ho-${Date.now()}`,
            patient_id, patient_name: patient.full_name, mrn: patient.mrn,
            visit_type: patient.visit_type, symptoms: patient.symptoms || null,
            vitals: patient.vitals || null, allergies: patient.allergies || null,
            appointments: apptsRes.data || [], lab_orders: labRes.data || [],
            prescriptions: rxRes.data || [], next_steps: req.body.next_steps || [],
            created_by: req.user.name, created_at: new Date().toISOString(),
            reviewed_by: null, reviewed_at: null, status: 'draft'
        };
        if (!summary.symptoms) missing.push('symptoms');
        if (!summary.vitals) missing.push('vital signs');
        if (!summary.allergies) missing.push('allergies');
        summary.missing_information = missing;
        if (!global.__handovers) global.__handovers = new Map();
        global.__handovers.set(summary.id, summary);
        res.json({ success: true, summary });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/handover', auth, (req, res) => {
    const list = global.__handovers ? Array.from(global.__handovers.values()) : [];
    res.json(list);
});

app.post('/api/handover/:id/approve', auth, role('doctor', 'surgeon', 'gp', 'health_officer', 'admin', 'super_admin'), (req, res) => {
    const list = global.__handovers ? Array.from(global.__handovers.values()) : [];
    const h = list.find(x => x.id === req.params.id);
    if (!h) return res.status(404).json({ error: 'Handover not found' });
    h.status = 'approved';
    h.reviewed_by = req.user.name;
    h.reviewed_at = new Date().toISOString();
    res.json({ success: true, summary: h });
});

// ============================================================
// FEATURE 10: PATIENT INSTRUCTIONS IN LOCAL LANGUAGES
// ============================================================
const INSTRUCTIONS = new Map();
const APPROVED_LANGS = ['English', 'Amharic', 'Afaan Oromoo', 'Tigrinya', 'Somali'];

app.post('/api/instructions', auth, (req, res) => {
    try {
        const { patient_id, patient_name, language, text, next_step } = req.body;
        if (!patient_id || !language) return res.status(400).json({ error: 'patient_id and language required' });
        if (!APPROVED_LANGS.includes(language)) return res.status(400).json({ error: 'Language not yet tested' });
        const item = {
            id: `inst-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            patient_id, patient_name: patient_name || 'Patient',
            language, text: text || '', next_step: next_step || '',
            reviewed_by: null, reviewed_at: null, status: 'draft',
            created_by: req.user.name, branch_id: req.user.branch_id || 'default',
            created_at: new Date().toISOString()
        };
        INSTRUCTIONS.set(item.id, item);
        res.json({ success: true, instruction: item });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/instructions', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    res.json(Array.from(INSTRUCTIONS.values()).filter(i => i.branch_id === branchId));
});

app.post('/api/instructions/:id/approve', auth, (req, res) => {
    const i = INSTRUCTIONS.get(req.params.id);
    if (!i) return res.status(404).json({ error: 'Instruction not found' });
    i.reviewed_by = req.user.name;
    i.reviewed_at = new Date().toISOString();
    i.status = 'approved';
    res.json({ success: true, instruction: i });
});

// ============================================================
// FEATURE 11: BRANCH WORKLOAD DASHBOARD
// ============================================================
app.get('/api/workload', auth, async (req, res) => {
    try {
        const branchId = req.user.branch_id || 'default';
        const q = _getQueue(branchId);
        const queueEntries = Array.from(q.entries.values()).filter(e => !['completed', 'cancelled'].includes(e.status));

        const byOffice = {};
        for (const office of q.offices.values()) {
            byOffice[office.name] = queueEntries.filter(e => e.office_id === office.id).length;
        }

        const now = Date.now();
        const waitingTimes = queueEntries
            .filter(e => e.status === 'waiting')
            .map(e => ({ number: e.number, name: e.patient_name, minutes: Math.floor((now - new Date(e.created_at).getTime()) / 60000) }));
        const longestWait = waitingTimes.sort((a, b) => b.minutes - a.minutes).slice(0, 5);

        const missedCalls = queueEntries.filter(e => e.status === 'missed').length;

        let labAwaitingReview = 0;
        try {
            const { data } = await supabase.from('lab_orders').select('id, status, reviewed').eq('branch_id', req.user.branch_id);
            labAwaitingReview = (data || []).filter(l => l.status === 'completed' && !l.reviewed).length;
        } catch (_) {}

        const followupsDue = Array.from(FOLLOWUPS.values())
            .filter(f => f.branch_id === branchId)
            .filter(f => new Date(f.due_date).getTime() - now <= 3 * 86400000).length;

        const byDepartment = {};
        for (const e of queueEntries) {
            byDepartment[e.department] = (byDepartment[e.department] || 0) + 1;
        }

        res.json({
            patients_waiting_by_office: byOffice,
            longest_waiting_times: longestWait,
            missed_calls: missedCalls,
            lab_work_awaiting_review: labAwaitingReview,
            followups_due: followupsDue,
            workload_by_department: byDepartment,
            generated_at: new Date().toISOString()
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// PHONE CALLS (VoIP stub — plug Twilio here)
// ============================================================
const PHONE_CALLS = [];

app.post('/api/call/phone', auth, async (req, res) => {
    try {
        const { to_number, to_name, patient_id, reason } = req.body;
        if (!to_number) return res.status(400).json({ error: 'to_number required' });
        const callRecord = {
            id: `pcall-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            from_user: req.user.id, from_name: req.user.name,
            to_number, to_name: to_name || 'Unknown', patient_id: patient_id || null,
            reason: reason || 'consultation', status: 'dialing',
            initiated_at: new Date().toISOString(),
            branch_id: req.user.branch_id || 'default'
        };
        PHONE_CALLS.push(callRecord);
        if (PHONE_CALLS.length > 1000) PHONE_CALLS.shift();

        const providerResponse = { message: 'Simulated — integrate Twilio/Africa\'s Talking here' };
        _pushAnnouncement(req.user.branch_id || 'default', `📞 ${req.user.name} called ${to_name || to_number}`);
        res.json({ success: true, call: callRecord, provider: providerResponse });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/call/phone/history', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    res.json(PHONE_CALLS.filter(c => c.branch_id === branchId).slice(-50).reverse());
});

app.get('/api/patients/:id/phone', auth, async (req, res) => {
    try {
        const { data } = await supabase.from('patients').select('phone, full_name').eq('id', req.params.id).maybeSingle();
        res.json({ phone: data?.phone || null, name: data?.full_name || null });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// AI HANDOVER ENHANCEMENT
// ============================================================
app.post('/api/handover/:id/ai-enhance', auth, async (req, res) => {
    try {
        const list = global.__handovers ? Array.from(global.__handovers.values()) : [];
        const h = list.find(x => x.id === req.params.id);
        if (!h) return res.status(404).json({ error: 'Handover not found' });

        const labSummary = (h.lab_orders || []).map(l => `${l.test_name} (${l.status})`).join(', ') || 'none';
        const rxSummary = (h.prescriptions || []).map(p => `${p.medication} ${p.dosage || ''}`).join(', ') || 'none';
        const prompt = `Generate a concise clinical handover summary for a doctor taking over this patient. Use professional medical language. Structure: 1-line patient summary, key findings, current medications, pending items, recommended next steps. Keep under 150 words.\n\nPatient: ${h.patient_name} (${h.mrn || 'no MRN'})\nVisit: ${h.visit_type || 'unknown'}\nSymptoms: ${h.symptoms || 'not recorded'}\nVitals: ${h.vitals ? JSON.stringify(h.vitals) : 'not recorded'}\nAllergies: ${h.allergies || 'not recorded'}\nLabs: ${labSummary}\nPrescriptions: ${rxSummary}`;

        let aiNarrative = '';
        try {
            const aiResp = await fetch('https://text.pollinations.ai/', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ messages: [{ role: 'user', content: prompt }], model: 'openai' })
            });
            if (aiResp.ok) aiNarrative = await aiResp.text();
        } catch (_) {}

        if (!aiNarrative || aiNarrative.toLowerCase().includes('error')) {
            aiNarrative = `Handover Summary — ${h.patient_name} (${h.mrn || 'no MRN'})\n\nPresentation: ${h.visit_type || 'General visit'}. Symptoms: ${h.symptoms || 'not documented'}.\nVitals: ${h.vitals ? Object.entries(h.vitals).map(([k,v]) => `${k}:${v}`).join(', ') : 'not recorded'}. Allergies: ${h.allergies || 'none documented'}.\n\nInvestigations: ${labSummary}. Current medications: ${rxSummary}.\n\nMissing: ${(h.missing_information || []).join(', ') || 'none'}. Please review full chart before decisions.`;
        }
        h.ai_narrative = aiNarrative.trim();
        h.ai_generated_at = new Date().toISOString();
        global.__handovers.set(h.id, h);
        res.json({ success: true, summary: h, ai_narrative: h.ai_narrative });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// CLINICAL FEED & MESSAGES
// ============================================================
app.get('/api/posts', auth, async (req, res) => {
    try {
        const { data: posts, error } = await supabase.from('posts').select('*, profiles(full_name, role, avatar_url)').order('created_at', { ascending: false }).limit(50);
        if (error) throw error;
        const live = (posts || []).filter(p => p.deleted !== true);
        const ids = live.map(p => p.id);
        let reactions = [], comments = [];
        if (ids.length) {
            const { data: r } = await supabase.from('post_reactions').select('post_id,user_id,type').in('post_id', ids); reactions = r || [];
            const { data: c } = await supabase.from('post_comments').select('post_id').in('post_id', ids); comments = c || [];
        }
        const enriched = live.map(p => {
            const pr = reactions.filter(r => r.post_id === p.id);
            return {
                ...p, likes: pr.filter(r => r.type === 'like').length, dislikes: pr.filter(r => r.type === 'dislike').length,
                hearts: pr.filter(r => r.type === 'heart').length, shares: p.shares || 0,
                my_reaction: pr.find(r => r.user_id === req.user.id)?.type || null,
                comment_count: comments.filter(c => c.post_id === p.id).length
            };
        });
        res.json(enriched);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/posts', auth, async (req, res) => {
    try {
        const { content, file_url, message_type } = req.body;
        if (!content?.trim() && !file_url) return res.status(400).json({ error: 'Empty post' });
        const { data, error } = await supabase.from('posts').insert([{ author_id: req.user.id, content: content || '', file_url: file_url || null, message_type: message_type || 'text' }]).select().single();
        if (error) throw error;
        res.json({ success: true, post: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/posts/:id', auth, async (req, res) => {
    try {
        const { data: post } = await supabase.from('posts').select('author_id').eq('id', req.params.id).single();
        if (!post) return res.status(404).json({ error: 'Post not found' });
        if (post.author_id !== req.user.id && !['admin', 'super_admin'].includes(req.user.role)) return res.status(403).json({ error: 'You can only delete your own post' });
        await supabase.from('posts').update({ deleted: true }).eq('id', req.params.id);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/posts/:id/react', auth, async (req, res) => {
    try {
        const { type } = req.body;
        if (!['like', 'dislike', 'heart', 'share'].includes(type)) return res.status(400).json({ error: 'Invalid type' });
        if (type === 'share') {
            const { data: p } = await supabase.from('posts').select('shares').eq('id', req.params.id).single();
            await supabase.from('posts').update({ shares: (p?.shares || 0) + 1 }).eq('id', req.params.id);
            return res.json({ success: true });
        }
        const { data: existing } = await supabase.from('post_reactions').select('id,type').eq('post_id', req.params.id).eq('user_id', req.user.id).maybeSingle();
        if (existing && existing.type === type) await supabase.from('post_reactions').delete().eq('id', existing.id);
        else if (existing) await supabase.from('post_reactions').update({ type }).eq('id', existing.id);
        else await supabase.from('post_reactions').insert([{ post_id: req.params.id, user_id: req.user.id, type }]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/posts/:id/comments', auth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('post_comments').select('*, profiles(full_name, role, avatar_url)').eq('post_id', req.params.id).order('created_at', { ascending: true });
        if (error) throw error; res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/posts/:id/comments', auth, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content?.trim()) return res.status(400).json({ error: 'Empty reply' });
        const { data, error } = await supabase.from('post_comments').insert([{ post_id: req.params.id, user_id: req.user.id, content }]).select('*, profiles(full_name, role, avatar_url)').single();
        if (error) throw error; res.json({ success: true, comment: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/messages/unread', auth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('direct_messages').select('id, sender_id').eq('receiver_id', req.user.id).eq('is_read', false);
        if (error) throw error;
        const bySender = {}; (data || []).forEach(m => { bySender[m.sender_id] = (bySender[m.sender_id] || 0) + 1; });
        res.json({ total: (data || []).length, bySender });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/messages/:otherUserId', auth, async (req, res) => {
    try {
        const other = req.params.otherUserId;
        const { data, error } = await supabase.from('direct_messages').select('*')
            .or(`and(sender_id.eq.${req.user.id},receiver_id.eq.${other}),and(sender_id.eq.${other},receiver_id.eq.${req.user.id})`)
            .order('created_at', { ascending: true }).limit(500);
        if (error) throw error;
        const ids = (data || []).map(m => m.id);
        let reactions = [];
        if (ids.length) { const { data: r } = await supabase.from('message_reactions').select('message_id,user_id,type').in('message_id', ids); reactions = r || []; }
        const out = (data || []).map(m => {
            const mr = reactions.filter(r => r.message_id === m.id);
            return { ...m, content: m.deleted ? null : m.content, likes: mr.filter(r => r.type === 'like').length, dislikes: mr.filter(r => r.type === 'dislike').length, my_reaction: mr.find(r => r.user_id === req.user.id)?.type || null };
        });
        await supabase.from('direct_messages').update({ is_read: true }).eq('receiver_id', req.user.id).eq('sender_id', other).eq('is_read', false);
        res.json(out);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/messages', auth, async (req, res) => {
    try {
        const { receiver_id, text, message_type, file_url, reply_to } = req.body;
        if (!receiver_id) return res.status(400).json({ error: 'Receiver required' });
        if (!text?.trim() && !file_url) return res.status(400).json({ error: 'Empty message' });
        const { data, error } = await supabase.from('direct_messages').insert([{ sender_id: req.user.id, receiver_id, content: text || '', message_type: message_type || 'text', file_url: file_url || null, reply_to: reply_to || null, is_read: false }]).select().single();
        if (error) throw error; res.json({ success: true, message: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/messages/:id', auth, async (req, res) => {
    try {
        const { data: msg } = await supabase.from('direct_messages').select('sender_id').eq('id', req.params.id).single();
        if (!msg) return res.status(404).json({ error: 'Message not found' });
        if (msg.sender_id !== req.user.id) return res.status(403).json({ error: 'You can only delete your own message' });
        await supabase.from('direct_messages').update({ deleted: true, content: null, file_url: null }).eq('id', req.params.id);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/messages/:id/react', auth, async (req, res) => {
    try {
        const { type } = req.body;
        if (!['like', 'dislike'].includes(type)) return res.status(400).json({ error: 'Invalid type' });
        const { data: existing } = await supabase.from('message_reactions').select('id,type').eq('message_id', req.params.id).eq('user_id', req.user.id).maybeSingle();
        if (existing && existing.type === type) await supabase.from('message_reactions').delete().eq('id', existing.id);
        else if (existing) await supabase.from('message_reactions').update({ type }).eq('id', existing.id);
        else await supabase.from('message_reactions').insert([{ message_id: req.params.id, user_id: req.user.id, type }]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// WORKERS, PATIENTS, AND SYSTEM CRUD
// ============================================================
app.get('/api/branch/workers', auth, role('branch_admin', 'admin', 'super_admin'), async (req, res) => {
    try {
        let q = supabase.from('profiles').select('id, full_name, staff_id, phone, role, bio, is_active, created_at, branch_id, avatar_url').order('full_name');
        if (req.user.role === 'branch_admin' && req.user.branch_id) q = q.eq('branch_id', req.user.branch_id);
        const { data, error } = await q;
        if (error) throw error;
        res.json((data || []).filter(w => w.role !== 'branch_admin'));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/branch/workers', auth, role('branch_admin', 'admin', 'super_admin'), async (req, res) => {
    try {
        const { full_name, phone, role_code, bio } = req.body;
        const branchId = req.user.branch_id;
        const staffId = await generateStaffId(branchId, role_code);
        const password = generateTempPassword(10);
        const email = `${staffId.toLowerCase()}@medconnect.com`;
        const { data: authData, error: aErr } = await supabase.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { full_name, role: role_code } });
        if (aErr) return res.status(500).json({ error: aErr.message });
        const hash = await bcrypt.hash(password, 10);
        const { data: profile, error: pErr } = await supabase.from('profiles').insert([{ id: authData.user.id, staff_id: staffId, full_name, phone: phone || null, role: role_code, branch_id: branchId, bio: bio || null, password_hash: hash, is_active: true }]).select('id, staff_id, full_name, role, phone, is_active').single();
        if (pErr) { await supabase.auth.admin.deleteUser(authData.user.id); return res.status(500).json({ error: pErr.message }); }
        res.json({ success: true, worker: profile, credentials: { staff_id: staffId, password, full_name, role: role_code } });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/branch/workers/:id', auth, role('branch_admin', 'admin', 'super_admin'), async (req, res) => {
    try {
        const { data, error } = await supabase.from('profiles').update(req.body).eq('id', req.params.id).select().single();
        if (error) throw error; res.json({ success: true, worker: safe(data) });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/branch/workers/:id/reset-password', auth, role('branch_admin', 'admin', 'super_admin'), async (req, res) => {
    try {
        const newPassword = generateTempPassword(10);
        const hash = await bcrypt.hash(newPassword, 10);
        const { data, error } = await supabase.from('profiles').update({ password_hash: hash }).eq('id', req.params.id).select('staff_id').single();
        if (error) throw error;
        try { await supabase.auth.admin.updateUserById(req.params.id, { password: newPassword }); } catch (_) {}
        res.json({ success: true, staff_id: data.staff_id, password: newPassword });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/branch/workers/:id', auth, role('branch_admin', 'admin', 'super_admin'), async (req, res) => {
    try {
        await supabase.from('profiles').delete().eq('id', req.params.id);
        try { await supabase.auth.admin.deleteUser(req.params.id); } catch (_) {}
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/patient/me', auth, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).json({ error: 'Forbidden' });
    try { const { data } = await supabase.from('patients').select('*').eq('created_by', req.user.id).maybeSingle(); res.json(data || null); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/patient/my-appointments', auth, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).json({ error: 'Forbidden' });
    try {
        const { data: me } = await supabase.from('patients').select('id').eq('created_by', req.user.id).maybeSingle();
        if (!me) return res.json([]);
        const { data } = await supabase.from('appointments').select('*, profiles(full_name, role)').eq('patient_id', me.id).order('scheduled_at', { ascending: true });
        res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/patient/my-prescriptions', auth, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).json({ error: 'Forbidden' });
    try {
        const { data: me } = await supabase.from('patients').select('id').eq('created_by', req.user.id).maybeSingle();
        if (!me) return res.json([]);
        const { data } = await supabase.from('prescriptions').select('*').eq('patient_id', me.id).order('created_at', { ascending: false });
        res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/patient/my-lab-orders', auth, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).json({ error: 'Forbidden' });
    try {
        const { data: me } = await supabase.from('patients').select('id').eq('created_by', req.user.id).maybeSingle();
        if (!me) return res.json([]);
        const { data } = await supabase.from('lab_orders').select('*').eq('patient_id', me.id).order('created_at', { ascending: false });
        res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/patient/appointment-reminders', auth, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).json({ error: 'Forbidden' });
    try {
        const { data: me } = await supabase.from('patients').select('id').eq('created_by', req.user.id).maybeSingle();
        if (!me) return res.json({ reminders: [] });
        const { data } = await supabase.from('appointments').select('*').eq('patient_id', me.id)
            .gte('scheduled_at', new Date().toISOString()).order('scheduled_at', { ascending: true }).limit(5);
        res.json({ reminders: data || [] });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/patients', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        let query = supabase.from('patients').select('*, branches(name)').order('created_at', { ascending: false }).limit(300);
        if (req.user.branch_id && !['admin', 'super_admin'].includes(req.user.role)) query = query.eq('branch_id', req.user.branch_id);
        const { data, error } = await query;
        if (error) throw error; res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/patients', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        const p = req.body;
        if (!p.mrn) p.mrn = `MRN-${Date.now().toString().slice(-8)}`;
        
        const { data, error } = await supabase.from('patients').insert([{ 
            full_name: p.full_name, mrn: p.mrn, phone: p.phone, gender: p.gender, 
            visit_type: p.visit_type || 'First Time Check',
            branch_id: p.branch_id || req.user.branch_id, created_by: req.user.id 
        }]).select().single();
        
        if (error) throw error;
        let startLevel = 1;
        let stage = 'triage';
        if (p.visit_type === 'Emergency') { startLevel = 2; stage = 'emergency'; }
        else if (p.visit_type === 'Maternal Care') { startLevel = 2; stage = 'midwife'; }

        await recordWorkflow(data.id, null, startLevel, stage, req.user.id, `Registered: ${p.visit_type || 'First Time Check'}`);
        res.json({ success: true, patient: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/appointments', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        let q = supabase.from('appointments').select('*, patients(full_name, mrn, visit_type), branches(name)').order('scheduled_at', { ascending: true }).limit(300);
        if (req.user.branch_id && !['admin', 'super_admin'].includes(req.user.role)) q = q.eq('branch_id', req.user.branch_id);
        const { data, error } = await q;
        if (error) throw error; res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/appointments', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        const a = req.body;
        const { data, error } = await supabase.from('appointments').insert([{ 
            patient_id: a.patient_id, provider_id: a.provider_id || null, 
            branch_id: a.branch_id || req.user.branch_id, scheduled_at: a.scheduled_at, 
            reason: a.reason, notes: a.notes, visit_type: a.visit_type || 'First Time Check',
            created_by: req.user.id 
        }]).select().single();
        if (error) throw error;
        await recordWorkflow(data.patient_id, 1, 1, 'queue', req.user.id, `Appointment booked: ${a.visit_type}`);
        res.json({ success: true, appointment: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/appointments/:id/status', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        const status = req.body.status;
        const { data, error } = await supabase.from('appointments').update({ status }).eq('id', req.params.id).select('id, patient_id').single();
        if (error) throw error;
        if (status === 'checked_in') await recordWorkflow(data.patient_id, 1, 2, 'triage', req.user.id, 'Checked in / triaged');
        if (status === 'completed') await recordWorkflow(data.patient_id, 2, 4, 'treatment', req.user.id, 'Consultation completed');
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/referrals', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        const { data, error } = await supabase.from('referrals').select('*, patients(full_name, mrn)').order('created_at', { ascending: false }).limit(300);
        if (error) throw error; res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/referrals', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        const r = req.body;
        const { data, error } = await supabase.from('referrals').insert([{ patient_id: r.patient_id, from_provider: req.user.id, from_branch: req.user.branch_id, to_branch: r.to_branch || null, to_level: r.to_level || 'facility', reason: r.reason, notes: r.notes }]).select().single();
        if (error) throw error;
        const map = { specialist: 2, facility: 6, regional: 9, federal: 10 };
        await recordWorkflow(data.patient_id, 4, map[r.to_level] || 6, 'referral', req.user.id, r.reason || 'Referral');
        res.json({ success: true, referral: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/lab-orders', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        const { data, error } = await supabase.from('lab_orders').select('*, patients(full_name, mrn)').order('created_at', { ascending: false }).limit(300);
        if (error) throw error; res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/lab-orders', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        const o = req.body;
        const { data, error } = await supabase.from('lab_orders').insert([{ patient_id: o.patient_id, ordered_by: req.user.id, branch_id: o.branch_id || req.user.branch_id, test_name: o.test_name, priority: o.priority || 'routine' }]).select().single();
        if (error) throw error;
        await recordWorkflow(data.patient_id, 2, 3, 'laboratory', req.user.id, 'Lab: ' + o.test_name);
        res.json({ success: true, order: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/lab-orders/:id', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        const payload = { ...req.body };
        if (payload.result) { payload.result_at = new Date().toISOString(); payload.status = 'completed'; }
        const { data, error } = await supabase.from('lab_orders').update(payload).eq('id', req.params.id).select('id, patient_id').single();
        if (error) throw error;
        if (payload.result) await recordWorkflow(data.patient_id, 3, 2, 'laboratory_return', req.user.id, 'Lab result ready');
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/prescriptions', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        const { data, error } = await supabase.from('prescriptions').select('*, patients(full_name, mrn)').order('created_at', { ascending: false }).limit(300);
        if (error) throw error; res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/prescriptions', auth, role('doctor', 'surgeon', 'gp', 'health_officer', 'admin', 'super_admin'), async (req, res) => {
    try {
        const p = req.body;
        const { data, error } = await supabase.from('prescriptions').insert([{ patient_id: p.patient_id, prescribed_by: req.user.id, branch_id: p.branch_id || req.user.branch_id, medication: p.medication, dosage: p.dosage, frequency: p.frequency, duration: p.duration }]).select('id, patient_id').single();
        if (error) throw error;
        await recordWorkflow(data.patient_id, 2, 4, 'pharmacy', req.user.id, 'Prescribed: ' + p.medication);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/prescriptions/:id/dispense', auth, role('pharmacist', 'pharmacy_tech', 'admin', 'super_admin'), async (req, res) => {
    try {
        const { data, error } = await supabase.from('prescriptions').update({ status: 'dispensed', dispensed_by: req.user.id, dispensed_at: new Date().toISOString() }).eq('id', req.params.id).select('id, patient_id').single();
        if (error) throw error;
        
        await recordWorkflow(data.patient_id, 4, 5, 'social_work', req.user.id, 'Medication dispensed → follow-up');

        const q = _getQueue(req.user.branch_id || 'default');
        for (let entry of q.entries.values()) {
            if (entry.patient_id === data.patient_id && !['completed', 'cancelled'].includes(entry.status)) {
                entry.status = 'completed';
                entry.completed_at = new Date().toISOString();
            }
        }
        const j = _getJourney(data.patient_id);
        if (j) {
            j.stage = 'Completed';
            j.updated_at = new Date().toISOString();
            j.history.push({ stage: 'Completed', at: j.updated_at, by: req.user.name });
        }

        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/inventory', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        const { data, error } = await supabase.from('inventory').select('*').order('item_name');
        if (error) throw error; res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/inventory', auth, role('pharmacist', 'medical_supply_officer', 'admin', 'super_admin'), async (req, res) => {
    try {
        const i = req.body;
        const { data, error } = await supabase.from('inventory').insert([{ branch_id: i.branch_id || req.user.branch_id, item_name: i.item_name, category: i.category || 'supply', quantity: Number(i.quantity) || 0, unit: i.unit, reorder_level: Number(i.reorder_level) || 10 }]).select().single();
        if (error) throw error; res.json({ success: true, item: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/inventory/:id/adjust', auth, role('pharmacist', 'medical_supply_officer', 'admin', 'super_admin'), async (req, res) => {
    try {
        const delta = Number(req.body.delta) || 0;
        const { data: cur } = await supabase.from('inventory').select('quantity').eq('id', req.params.id).single();
        const newQty = Math.max(0, (cur?.quantity || 0) + delta);
        const { data, error } = await supabase.from('inventory').update({ quantity: newQty }).eq('id', req.params.id).select().single();
        if (error) throw error; res.json({ success: true, item: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/worker-roles', auth, async (req, res) => {
    try { const { data, error } = await supabase.from('worker_roles').select('*').order('category').order('title'); if (error) throw error; res.json(data || []); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/staff', auth, async (req, res) => {
    try { const { data, error } = await supabase.from('profiles').select('id, full_name, role, branch_id, staff_id, avatar_url, bio').eq('is_active', true).order('full_name'); if (error) throw error; res.json(data || []); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/profile', auth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('profiles').update(req.body).eq('id', req.user.id).select().single();
        if (error) throw error; delete data.password_hash; res.json({ success: true, profile: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/profile/avatar', auth, upload.single('avatar'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No image' });
        const ext = (req.file.originalname.split('.').pop() || 'png').toLowerCase();
        const filePath = `avatars/${req.user.id}-${Date.now()}.${ext}`;
        const { error } = await supabase.storage.from('medconnect').upload(filePath, req.file.buffer, { contentType: req.file.mimetype, upsert: true });
        if (error) throw error;
        const { data: { publicUrl } } = supabase.storage.from('medconnect').getPublicUrl(filePath);
        await supabase.from('profiles').update({ avatar_url: publicUrl }).eq('id', req.user.id);
        res.json({ success: true, avatar_url: publicUrl });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/profile/password', auth, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const { data: me } = await supabase.from('profiles').select('password_hash').eq('id', req.user.id).single();
        const ok = await bcrypt.compare(currentPassword || '', me.password_hash);
        if (!ok) return res.status(401).json({ error: 'Current password is incorrect' });
        const hash = await bcrypt.hash(newPassword, 10);
        await supabase.from('profiles').update({ password_hash: hash }).eq('id', req.user.id);
        try { await supabase.auth.admin.updateUserById(req.user.id, { password: newPassword }); } catch (_) {}
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// WORKFLOW LEVELS (With Assign, Unassign, Discharge)
// ============================================================
const WORKFLOW_LEVELS = {
    1:  { key: 'patient_services',      name: 'Patient Services',          stages: ['registration','records','triage','queue'] },
    2:  { key: 'clinical_services',     name: 'Clinical Services',         stages: ['gp','specialist','emergency','nurse','midwife','surgeon'] },
    3:  { key: 'diagnostic_services',   name: 'Diagnostic Services',       stages: ['laboratory','radiology','pathology','blood_bank'] },
    4:  { key: 'treatment_services',    name: 'Treatment Services',        stages: ['pharmacy','surgery','icu','maternity','rehabilitation'] },
    5:  { key: 'support_services',      name: 'Support Services',          stages: ['public_health','ambulance','infection_prevention','social_work'] },
    6:  { key: 'department_management', name: 'Department Management',     stages: ['dept_head','medical_director','nursing_director','quality_manager'] },
    7:  { key: 'hospital_admin',        name: 'Hospital Administration',   stages: ['ceo'] },
    8:  { key: 'zonal_admin',           name: 'Zonal Administration',      stages: ['zonal_head'] },
    9:  { key: 'regional_bureau',       name: 'Regional Health Bureau',    stages: ['regional_director'] },
    10: { key: 'federal_moh',           name: 'Federal Ministry of Health',stages: ['federal_director'] }
};

const LEVEL_OWNERS = {
    1:  ['receptionist','medical_records','nurse','branch_admin','admin','super_admin'],
    2:  ['gp','doctor','specialist','surgeon','emergency_worker','health_officer','branch_admin','admin','super_admin'],
    3:  ['lab_tech','radiologist','radiology_tech','medical_records','branch_admin','admin','super_admin'],
    4:  ['pharmacist','pharmacy_tech','nurse','midwife','surgeon','branch_admin','admin','super_admin'],
    5:  ['public_health_officer','ambulance_worker','infection_prevention_officer','social_worker','branch_admin','admin','super_admin'],
    6:  ['department_head','head_nurse','medical_director','branch_admin','admin','super_admin'],
    7:  ['hospital_admin','ceo','branch_admin','admin','super_admin'],
    8:  ['zonal_admin','regional_admin','admin','super_admin'],
    9:  ['regional_admin','admin','super_admin'],
    10: ['admin','super_admin','federal_director']
};

async function recordWorkflow(patientId, fromLevel, toLevel, stage, userId, notes) {
    try {
        if (!patientId || !toLevel) return null;
        const { data, error } = await supabase.from('patient_workflow').insert([{
            patient_id: patientId, from_level: fromLevel ?? null, to_level: toLevel,
            to_stage: stage || WORKFLOW_LEVELS[toLevel]?.stages[0] || 'general',
            transitioned_by: userId || null, notes: notes || null
        }]).select().single();
        if (error) { console.error('Workflow insert error:', error.message); return null; }
        if (toLevel >= 7) {
            tgNotifyAdmin(`🏥 Patient escalated to Level ${toLevel} (${WORKFLOW_LEVELS[toLevel]?.name})\n${notes || ''}`);
        }
        return data;
    } catch (e) { console.error('recordWorkflow:', e.message); return null; }
}

async function getPatientJourney(patientId) {
    const { data: events, error } = await supabase
        .from('patient_workflow')
        .select('*, profiles!transitioned_by(full_name, role)')
        .eq('patient_id', patientId)
        .order('created_at', { ascending: true });
    if (error) throw error;
    return events || [];
}

async function getCurrentWorkflowState(patientId) {
    const { data, error } = await supabase
        .from('patient_workflow')
        .select('*')
        .eq('patient_id', patientId)
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();
    if (error) throw error;
    return data || null;
}

app.get('/api/workflow/levels', auth, (req, res) => {
    res.json(Object.entries(WORKFLOW_LEVELS).map(([k, v]) => ({ level: Number(k), ...v })));
});

app.get('/api/workflow/patient/:id', auth, async (req, res) => {
    try {
        const { data: patient } = await supabase.from('patients').select('id, full_name, mrn, phone, gender, branch_id, visit_type').eq('id', req.params.id).single();
        if (!patient) return res.status(404).json({ error: 'Patient not found' });
        const journey = await getPatientJourney(req.params.id);
        const current = await getCurrentWorkflowState(req.params.id);
        res.json({
            patient,
            current_level: current?.to_level || 1,
            current_stage: current?.to_stage || 'registration',
            level_name: WORKFLOW_LEVELS[current?.to_level || 1]?.name || 'Patient Services',
            journey
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/workflow/transition', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        const { patient_id, to_level, to_stage, notes } = req.body;
        if (!patient_id || !to_level) return res.status(400).json({ error: 'patient_id and to_level required' });
        const current = await getCurrentWorkflowState(patient_id);
        const fromLevel = current?.to_level || null;
        const fromStage = current?.to_stage || null;
        const { data, error } = await supabase.from('patient_workflow').insert([{
            patient_id, from_level: fromLevel, from_stage: fromStage,
            to_level: Number(to_level),
            to_stage: to_stage || WORKFLOW_LEVELS[to_level]?.stages[0] || 'general',
            transitioned_by: req.user.id, notes: notes || null
        }]).select().single();
        if (error) throw error;
        if (to_level >= 7) tgNotifyAdmin(`⬆️ Patient #${patient_id.slice(0,8)} → L${to_level} ${WORKFLOW_LEVELS[to_level]?.name}\nBy: ${req.user.name}\n${notes || ''}`);
        res.json({ success: true, transition: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/workflow/unassign', auth, async (req, res) => {
    try {
        const { patient_id } = req.body;
        if (!patient_id) return res.status(400).json({ error: 'patient_id required' });
        
        const q = _getQueue(req.user.branch_id || 'default');
        for (let entry of q.entries.values()) {
            if (entry.patient_id === patient_id && !['completed', 'cancelled'].includes(entry.status)) {
                entry.status = 'cancelled';
            }
        }

        await recordWorkflow(patient_id, null, 1, 'queue', req.user.id, 'Unassigned from current office by ' + req.user.name);
        
        res.json({ success: true, message: 'Patient unassigned and removed from active queue.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/workflow/discharge', auth, async (req, res) => {
    try {
        const { patient_id, notes } = req.body;
        if (!patient_id) return res.status(400).json({ error: 'patient_id required' });
        
        const q = _getQueue(req.user.branch_id || 'default');
        for (let entry of q.entries.values()) {
            if (entry.patient_id === patient_id && !['completed', 'cancelled'].includes(entry.status)) {
                entry.status = 'completed';
                entry.completed_at = new Date().toISOString();
            }
        }

        const j = _getJourney(patient_id);
        if (j) {
            j.stage = 'Completed';
            j.updated_at = new Date().toISOString();
            j.history.push({ stage: 'Completed', at: j.updated_at, by: req.user.name });
        }

        await recordWorkflow(patient_id, null, 10, 'discharged', req.user.id, notes || 'Patient discharged / visit finished');
        
        res.json({ success: true, message: 'Patient discharged successfully.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/workflow/dashboard', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        const { data: all, error } = await supabase
            .from('patient_workflow')
            .select('*, patients(id, full_name, mrn, branch_id, visit_type), profiles!transitioned_by(full_name, role)')
            .order('created_at', { ascending: false });
        if (error) throw error;
        const latest = {};
        for (const ev of (all || [])) if (!latest[ev.patient_id]) latest[ev.patient_id] = ev;
        const grouped = {};
        Object.values(latest).forEach(ev => {
            const lvl = ev.to_level;
            (grouped[lvl] = grouped[lvl] || []).push(ev);
        });
        res.json({
            levels: WORKFLOW_LEVELS, grouped,
            counts: Object.fromEntries(Object.keys(WORKFLOW_LEVELS).map(k => [k, (grouped[k] || []).length]))
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/workflow/my-tasks', auth, async (req, res) => {
    try {
        if (req.user.role === 'patient') return res.status(403).json({ error: 'Forbidden' });
        const { data: all, error } = await supabase
            .from('patient_workflow')
            .select('*, patients(id, full_name, mrn, phone, branch_id, visit_type)')
            .order('created_at', { ascending: false });
        if (error) throw error;
        const latest = {};
        for (const ev of (all || [])) if (!latest[ev.patient_id]) latest[ev.patient_id] = ev;
        const myLevels = Object.entries(LEVEL_OWNERS)
            .filter(([, owners]) => owners.includes(req.user.role))
            .map(([lvl]) => Number(lvl));
        const mine = Object.values(latest).filter(ev => myLevels.includes(ev.to_level));
        res.json({ my_levels: myLevels, tasks: mine });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// TELEGRAM
// ============================================================
const TG_BOT_TOKEN = process.env.TG_BOT_TOKEN || '';
const TG_ADMIN_CHAT_ID = process.env.TG_ADMIN_CHAT_ID || '';
const TG_CS_HANDLE = process.env.TG_CS_HANDLE || 'TE21HUSH';

async function tgSend(chatId, text) {
    if (!TG_BOT_TOKEN || !chatId) return { ok: false, reason: 'no_token' };
    try {
        const r = await fetch(`https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true })
        });
        return await r.json();
    } catch (e) { return { ok: false, reason: e.message }; }
}

async function tgNotifyAdmin(text) {
    if (!TG_ADMIN_CHAT_ID) return;
    return tgSend(TG_ADMIN_CHAT_ID, text);
}

app.get('/api/telegram/config', (req, res) => {
    res.json({ handle: TG_CS_HANDLE, url: `https://t.me/${TG_CS_HANDLE}`, bot_configured: !!TG_BOT_TOKEN });
});

app.post('/api/telegram/notify', auth, async (req, res) => {
    try {
        const { text } = req.body;
        if (!text) return res.status(400).json({ error: 'text required' });
        const msg = `📨 From ${req.user.name} (${req.user.role})\n${text}`;
        const r = await tgNotifyAdmin(msg);
        res.json({ success: true, telegram: r });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/telegram/webhook', async (req, res) => {
    try {
        const update = req.body || {};
        const message = update.message || update.edited_message;
        if (message) {
            const from = message.from || {};
            const text = message.text || '[non-text]';
            await tgSend(from.id, `👋 Hi ${from.first_name || 'there'}! A MedConnect customer service agent from @${TG_CS_HANDLE} will get back to you shortly.\n\n🩺 For medical emergencies call 911 / 907.`);
        }
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// LIVE CONFERENCE VIBRATION SIGNAL
// ============================================================
app.post('/api/live/vibrate', auth, async (req, res) => {
    try {
        if (!isLiveMod(req.user)) return res.status(403).json({ error: 'Only moderators can trigger vibration' });
        const { target, pattern } = req.body;
        pushSignal(req.user.id, target || '*', 'vibrate', { pattern: pattern || 'long', by: req.user.name });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// CHART DATA ENDPOINTS (per-page dashboards)
// ============================================================
app.get('/api/charts/queue', auth, (req, res) => {
    try {
        const branchId = req.user.branch_id || 'default';
        const q = _getQueue(branchId);
        const entries = Array.from(q.entries.values());
        const byStatus = {}, byOffice = {}, byDept = {};
        for (const e of entries) byStatus[e.status] = (byStatus[e.status] || 0) + 1;
        for (const office of q.offices.values()) byOffice[office.name] = entries.filter(e => e.office_id === office.id && e.status === 'waiting').length;
        for (const e of entries.filter(e => e.status === 'waiting')) byDept[e.department] = (byDept[e.department] || 0) + 1;
        const now = Date.now();
        const waitBuckets = { '0-10m': 0, '10-20m': 0, '20-30m': 0, '30m+': 0 };
        for (const e of entries.filter(e => e.status === 'waiting')) {
            const mins = Math.floor((now - new Date(e.created_at).getTime()) / 60000);
            if (mins < 10) waitBuckets['0-10m']++;
            else if (mins < 20) waitBuckets['10-20m']++;
            else if (mins < 30) waitBuckets['20-30m']++;
            else waitBuckets['30m+']++;
        }
        res.json({ by_status: byStatus, by_office: byOffice, by_department: byDept, wait_buckets: waitBuckets });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/charts/triage', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    const flags = Array.from(TRIAGE_FLAGS.values()).filter(f => f.branch_id === branchId);
    const bySeverity = {}, byStatus = {};
    for (const f of flags) { bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1; byStatus[f.status] = (byStatus[f.status] || 0) + 1; }
    res.json({ by_severity: bySeverity, by_status: byStatus, total: flags.length });
});

app.get('/api/charts/followup', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    const all = Array.from(FOLLOWUPS.values()).filter(f => f.branch_id === branchId);
    const byType = {}, byStatus = {};
    for (const f of all) { byType[f.type] = (byType[f.type] || 0) + 1; byStatus[f.status] = (byStatus[f.status] || 0) + 1; }
    res.json({ by_type: byType, by_status: byStatus, total: all.length });
});

app.get('/api/charts/stock', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    const items = Array.from(STOCK_ITEMS.values()).filter(i => i.branch_id === branchId);
    const states = { ok: 0, low: 0, near_expiry: 0, expired: 0 };
    for (const item of items) {
        const s = _computeStockStatus(item);
        if (s.expired) states.expired++;
        else if (s.nearExpiry) states.near_expiry++;
        else if (s.lowStock) states.low++;
        else states.ok++;
    }
    res.json({ states, stock_levels: items.map(i => ({ name: i.item_name, qty: i.quantity, reorder: i.reorder_level })).slice(0, 10) });
});

app.get('/api/charts/referrals', auth, (req, res) => {
    const branchId = req.user.branch_id || 'default';
    const all = Array.from(REFERRALS.values()).filter(r => r.branch_id === branchId);
    const byStatus = {}, byUrgency = {};
    for (const r of all) { byStatus[r.status] = (byStatus[r.status] || 0) + 1; byUrgency[r.urgency || 'routine'] = (byUrgency[r.urgency || 'routine'] || 0) + 1; }
    res.json({ by_status: byStatus, by_urgency: byUrgency, total: all.length });
});

app.get('/api/charts/lab', auth, async (req, res) => {
    try {
        const { data } = await supabase.from('lab_orders').select('status, reviewed').eq('branch_id', req.user.branch_id);
        const byStatus = {}, byReview = { reviewed: 0, pending: 0 };
        for (const l of (data || [])) {
            byStatus[l.status] = (byStatus[l.status] || 0) + 1;
            if (l.reviewed) byReview.reviewed++; else byReview.pending++;
        }
        res.json({ by_status: byStatus, by_review: byReview });
    } catch (e) { res.json({ by_status: {}, by_review: { reviewed: 0, pending: 0 } }); }
});

// ============================================================
// TV MANUAL ANNOUNCEMENTS (WORKER CONTROL)
// ============================================================
const TV_CUSTOM_ANNOUNCEMENTS = [];

app.post('/api/tv/announce', auth, (req, res) => {
    try {
        const { text, target_office, patient_name } = req.body;
        if (!text) return res.status(400).json({ error: 'Text required' });
        
        const ann = {
            id: `tv-${Date.now()}`,
            text,
            target_office: target_office || 'General',
            patient_name: patient_name || '',
            spoken_by: req.user.name,
            at: new Date().toISOString()
        };
        
        TV_CUSTOM_ANNOUNCEMENTS.push(ann);
        if (TV_CUSTOM_ANNOUNCEMENTS.length > 50) TV_CUSTOM_ANNOUNCEMENTS.shift();
        
        _pushAnnouncement(req.user.branch_id || 'default', `📺 TV Call: ${text}`);
        
        res.json({ success: true, announcement: ann });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/tv/announcements', (req, res) => {
    res.json(TV_CUSTOM_ANNOUNCEMENTS.slice(-5));
});

// ============================================================
// 404 + BOOT (Vercel & Localhost)
// ============================================================
app.use((req, res) => res.status(404).json({ error: 'API route not found.', url: req.url, method: req.method }));

export default app;

if (!process.env.VERCEL) {
    const PORT = process.env.PORT || 5050;
    app.listen(PORT, () => {
        console.log(`\n========================================`);
        console.log(`🚀 MedConnect running on http://localhost:${PORT}`);
        console.log(`📞 Customer Service: https://t.me/${TG_CS_HANDLE}`);
        console.log(`========================================\n`);
    });
}