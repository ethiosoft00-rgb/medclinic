// ============================================================
// MedConnect Ethiopia — server.js (Part 1 of 2)
// ============================================================
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import cors from 'cors';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, '.env') });

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
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

async function sendFrontend(req, res) {
    try {
        const fs = await import('fs/promises');
        let page = await fs.readFile(path.join(__dirname, 'public', 'index.html'), 'utf8');
        const slug = req.params.slug || '';
        page = page
            .replaceAll('__SUPABASE_URL__', process.env.SUPABASE_URL || '')
            .replaceAll('__SUPABASE_ANON_KEY__', process.env.SUPABASE_ANON_KEY || '')
            .replaceAll('__BRANCH_SLUG__', slug)
            .replaceAll('__TG_HANDLE__', process.env.TG_CS_HANDLE || 'TE21HUSH');
        res.type('html').send(page);
    } catch (error) {
        console.error('Frontend Error:', error);
        res.status(500).send('Error loading frontend.');
    }
}

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
    const { count } = await supabase.from('profiles')
        .select('*', { count: 'exact', head: true })
        .eq('branch_id', branchId).eq('role', role);
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
        const { data: profile, error: profileError } = await supabase
            .from('profiles').select('*').eq('id', identity.id).maybeSingle();
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

app.get('/', sendFrontend);
app.get('/b/:slug', sendFrontend);

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
        const { fullName, phone, password } = req.body;
        if (!fullName || !phone || !password || password.length < 6) {
            return res.status(400).json({ error: 'Please provide valid name, phone, and a password of at least 6 characters.' });
        }
        const cleanPhone = phone.replace(/\D/g, '');
        if (cleanPhone.length < 9) return res.status(400).json({ error: 'Invalid phone number format.' });
        const { data: existing } = await supabase.from('profiles').select('id').eq('staff_id', cleanPhone).maybeSingle();
        if (existing) return res.status(400).json({ error: 'This phone number is already registered. Please sign in.' });
        const email = `${cleanPhone}@medconnect.com`;
        const { data: authData, error: authErr } = await supabase.auth.admin.createUser({
            email, password, email_confirm: true, user_metadata: { full_name: fullName, role: 'patient' }
        });
        if (authErr) {
            if (authErr.message.includes('already registered')) return res.status(400).json({ error: 'This phone number is already registered.' });
            return res.status(500).json({ error: authErr.message });
        }
        const hash = await bcrypt.hash(password, 10);
        const { data: profile, error: pErr } = await supabase.from('profiles').insert([{
            id: authData.user.id, full_name: fullName, staff_id: cleanPhone, password_hash: hash,
            role: 'patient', phone: cleanPhone, is_active: true
        }]).select().single();
        if (pErr) { await supabase.auth.admin.deleteUser(authData.user.id); return res.status(500).json({ error: pErr.message }); }
        await supabase.from('patients').insert([{ full_name: fullName, phone: cleanPhone, created_by: authData.user.id, visit_type: 'First Time Check' }]);
        const token = jwt.sign({ id: profile.id, role: 'patient', branch_id: null }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, message: 'Account created!', user: safe(profile), token });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { identifier, email } = req.body;
        if (!identifier || !email) return res.status(400).json({ error: 'Staff ID and Email required' });
        
        const { data: profile } = await supabase.from('profiles').select('*').eq('staff_id', identifier).maybeSingle();
        if (!profile) return res.status(404).json({ error: 'Worker not found with this ID.' });

        await supabase.from('password_reset_requests').insert([{
            staff_id: profile.staff_id,
            full_name: profile.full_name,
            email: email,
            branch_id: profile.branch_id,
            status: 'pending'
        }]);
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

// ============================================================
// FILE UPLOAD
// ============================================================
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

// ============================================================
// BRANCHES
// ============================================================
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
// MedConnect Ethiopia — server.js (Part 2 of 2)
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
// DIRECT WEBRTC CALLS (MESSAGES)
// ============================================================
const CALL_SIGNALS = []; // Stores direct call signals
let callSeq = 0;

function pushCallSignal(from, to, type, payload) {
    callSeq += 1;
    CALL_SIGNALS.push({ seq: callSeq, from, to, type, payload, at: Date.now() });
    const cutoff = Date.now() - 60_000;
    // Keep only last minute of signals
    const filtered = CALL_SIGNALS.filter(s => s.at > cutoff);
    CALL_SIGNALS.length = 0;
    CALL_SIGNALS.push(...filtered);
}

app.post('/api/call/signal', auth, async (req, res) => {
    try {
        const { to, type, payload } = req.body;
        if (!to || !type) return res.status(400).json({ error: 'to and type required' });
        pushCallSignal(req.user.id, to, type, payload || {});
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
// LIVE CONFERENCE (GROUP CALLS)
// ============================================================
// Added statuses for mute, camera, raise-hand, reactions
const LIVE = { 
    active: false, 
    startedAt: null, 
    moderators: new Set(), 
    participants: new Map(), 
    requests: new Map(), 
    signals: [], 
    seq: 0 
};

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
            LIVE.active = true; 
            LIVE.startedAt = new Date().toISOString(); 
            LIVE.moderators.add(req.user.id); 
        } else { 
            LIVE.active = false; 
            LIVE.startedAt = null; 
            LIVE.moderators.clear(); 
            LIVE.participants.clear(); 
            LIVE.requests.clear(); 
            LIVE.signals = []; 
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

// NEW: Toggle user status (mute, camera, raise hand)
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

app.get('/api/patient/my-queue', auth, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).json({ error: 'Forbidden' });
    try {
        const { data: me } = await supabase.from('patients').select('id, visit_type').eq('created_by', req.user.id).maybeSingle();
        if (!me) return res.json({ position: null, total: 0, ahead: 0, currentlyServing: null });
        
        const start = new Date(); start.setHours(0,0,0,0); const end = new Date(start); end.setDate(end.getDate() + 1);
        const { data: appts } = await supabase.from('appointments').select('id, patient_id, status, scheduled_at, visit_type').gte('scheduled_at', start.toISOString()).lt('scheduled_at', end.toISOString()).order('scheduled_at', { ascending: true });
        
        const sortedAppts = (appts || []).sort((a, b) => {
            if (a.visit_type === 'Emergency' && b.visit_type !== 'Emergency') return -1;
            if (b.visit_type === 'Emergency' && a.visit_type !== 'Emergency') return 1;
            return new Date(a.scheduled_at) - new Date(b.scheduled_at);
        });

        const mine = sortedAppts.find(a => a.patient_id === me.id);
        const idx = mine ? sortedAppts.findIndex(a => a.id === mine.id) : -1;
        const serving = (sortedAppts || []).find(a => a.status === 'checked_in');
        
        res.json({ 
            position: idx >= 0 ? idx + 1 : null, 
            total: (sortedAppts || []).length, 
            ahead: Math.max(0, idx), 
            currentlyServing: serving ? { at: serving.scheduled_at, type: serving.visit_type } : null, 
            myStatus: mine?.status || null,
            myVisitType: mine?.visit_type || me.visit_type || 'First Time Check'
        });
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
            full_name: p.full_name, 
            mrn: p.mrn, 
            phone: p.phone, 
            gender: p.gender, 
            visit_type: p.visit_type || 'First Time Check',
            branch_id: p.branch_id || req.user.branch_id, 
            created_by: req.user.id 
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
            patient_id: a.patient_id, 
            provider_id: a.provider_id || null, 
            branch_id: a.branch_id || req.user.branch_id, 
            scheduled_at: a.scheduled_at, 
            reason: a.reason, 
            notes: a.notes, 
            visit_type: a.visit_type || 'First Time Check',
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
            patient_id: patientId,
            from_level: fromLevel ?? null,
            to_level: toLevel,
            to_stage: stage || WORKFLOW_LEVELS[toLevel]?.stages[0] || 'general',
            transitioned_by: userId || null,
            notes: notes || null
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
