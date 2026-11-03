// ============================================================
// MedConnect Ethiopia — server.js (Complete & Fixed)
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

const HASAB_LANGS = {
    'English': 'eng',
    'Amharic': 'amh',
    'Afaan Oromoo': 'orm',
    'Tigrinya': 'tig',
    'Somali': 'som',
    'Sidama': 'sid'
};

// HELPERS
async function sendFrontend(req, res) {
    try {
        const fs = await import('fs/promises');
        let page = await fs.readFile(path.join(__dirname, 'public', 'index.html'), 'utf8');
        const slug = req.params.slug || '';
        page = page
            .replaceAll('__SUPABASE_URL__', process.env.SUPABASE_URL || '')
            .replaceAll('__SUPABASE_ANON_KEY__', process.env.SUPABASE_ANON_KEY || '')
            .replaceAll('__BRANCH_SLUG__', slug);
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
        try {
            identity = jwt.verify(token, JWT_SECRET);
        } catch {
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
    } catch {
        return res.status(401).json({ error: 'Invalid session' });
    }
}

const role = (...roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
    next();
};

// ROUTES
app.get('/', sendFrontend);
app.get('/b/:slug', sendFrontend);

// AUTHENTICATION
app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        if (!identifier || !password) return res.status(400).json({ error: 'Staff ID and password required' });

        const { data: user, error } = await supabase.from('profiles')
            .select('*').eq('staff_id', identifier.trim()).single();

        if (error || !user) return res.status(401).json({ error: 'Invalid Staff ID or password.' });
        if (user.is_active === false) return res.status(401).json({ error: 'Account is deactivated.' });
        
        const ok = user.password_hash ? await bcrypt.compare(password, user.password_hash) : false;
        if (!ok) return res.status(401).json({ error: 'Invalid Staff ID or password.' });

        const token = jwt.sign(
            { id: user.id, role: user.role, branch_id: user.branch_id },
            JWT_SECRET, { expiresIn: '7d' }
        );
        delete user.password_hash;
        res.json({ success: true, user, token });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/register', loginLimiter, async (req, res) => {
    try {
        const { fullName, phone, password } = req.body;
        if (!fullName || !phone || password.length < 6) return res.status(400).json({ error: 'Invalid data' });
        const { data: existing } = await supabase.from('profiles').select('id').eq('staff_id', phone).maybeSingle();
        if (existing) return res.status(400).json({ error: 'Phone already registered' });

        const email = `${phone}@medconnect.com`;
        const { data: authData, error: authErr } = await supabase.auth.admin.createUser({
            email, password, email_confirm: true,
            user_metadata: { full_name: fullName, role: 'patient' }
        });
        if (authErr) throw authErr;

        const hash = await bcrypt.hash(password, 10);
        const { data: profile, error: pErr } = await supabase.from('profiles').insert([{
            id: authData.user.id, full_name: fullName, staff_id: phone,
            password_hash: hash, role: 'patient', phone
        }]).select().single();
        if (pErr) throw pErr;
        await supabase.from('patients').insert([{ full_name: fullName, phone }]);

        const token = jwt.sign({ id: profile.id, role: 'patient' }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, message: 'Account created!', user: profile, token });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// FILE UPLOAD
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        const folder = (req.body.folder || 'chat_files').replace(/[^a-z0-9_\/-]/gi, '');
        const fileExt = (req.file.originalname.split('.').pop() || 'bin').toLowerCase();
        const fileName = `${Date.now()}-${Math.random().toString(36).substring(7)}.${fileExt}`;
        const filePath = `${folder}/${fileName}`;

        const { error } = await supabase.storage.from('medconnect').upload(filePath, req.file.buffer, {
            contentType: req.file.mimetype, upsert: false
        });
        if (error) throw error;

        const { data: { publicUrl } } = supabase.storage.from('medconnect').getPublicUrl(filePath);
        res.json({
            success: true, url: publicUrl,
            type: req.file.mimetype, name: req.file.originalname,
            size: req.file.size
        });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// BRANCHES
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
        const { data: branch, error: bErr } = await supabase.from('branches').insert([{
            name: branchName, location: branchLocation, slug
        }]).select('id, slug').single();
        if (bErr) throw bErr;

        const branchPrefix = slug.split('-')[0].toUpperCase().slice(0, 3);
        const adminStaffId = `${branchPrefix}-ADM-001`;
        const adminPassword = generateTempPassword(10);
        const email = `${adminStaffId.toLowerCase()}@medconnect.com`;

        const { data: authData, error: aErr } = await supabase.auth.admin.createUser({
            email, password: adminPassword, email_confirm: true,
            user_metadata: { full_name: adminName, role: 'branch_admin' }
        });
        if (aErr) {
            await supabase.from('branches').delete().eq('id', branch.id);
            throw aErr;
        }

        const hash = await bcrypt.hash(adminPassword, 10);
        const { error: pErr } = await supabase.from('profiles').insert([{
            id: authData.user.id, staff_id: adminStaffId, branch_id: branch.id,
            role: 'branch_admin', full_name: adminName, phone: adminPhone || null,
            password_hash: hash, is_active: true
        }]);
        if (pErr) {
            await supabase.auth.admin.deleteUser(authData.user.id);
            await supabase.from('branches').delete().eq('id', branch.id);
            throw pErr;
        }

        await supabase.from('branches').update({ admin_id: authData.user.id }).eq('id', branch.id);
        res.status(201).json({
            success: true,
            branchId: branch.id,
            branchSlug: branch.slug,
            branchLink: `${req.protocol}://${req.get('host')}/b/${branch.slug}`,
            admin: { name: adminName, staff_id: adminStaffId, password: adminPassword }
        });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.delete('/api/admin/branches/:id', auth, role('admin', 'super_admin'), async (req, res) => {
    try {
        await supabase.from('branches').delete().eq('id', req.params.id);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// CLINICAL FEED
app.get('/api/posts', auth, async (req, res) => {
    try {
        const { data: posts, error } = await supabase
            .from('posts')
            .select('*, profiles(full_name, role, avatar_url)')
            .order('created_at', { ascending: false })
            .limit(50);
        if (error) throw error;

        const live = (posts || []).filter(p => p.deleted !== true);
        const ids = live.map(p => p.id);
        let reactions = [], comments = [];
        if (ids.length) {
            const { data: r } = await supabase.from('post_reactions').select('post_id,user_id,type').in('post_id', ids);
            reactions = r || [];
            const { data: c } = await supabase.from('post_comments').select('post_id').in('post_id', ids);
            comments = c || [];
        }
        const enriched = live.map(p => {
            const pr = reactions.filter(r => r.post_id === p.id);
            return {
                ...p,
                likes: pr.filter(r => r.type === 'like').length,
                dislikes: pr.filter(r => r.type === 'dislike').length,
                hearts: pr.filter(r => r.type === 'heart').length,
                shares: p.shares || 0,
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

        const { data, error } = await supabase.from('posts').insert([{
            author_id: req.user.id,
            content: content || '',
            file_url: file_url || null,
            message_type: message_type || 'text'
        }]).select().single();
        if (error) throw error;
        res.json({ success: true, post: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/posts/:id', auth, async (req, res) => {
    try {
        const { data: post } = await supabase.from('posts').select('author_id').eq('id', req.params.id).single();
        if (!post) return res.status(404).json({ error: 'Post not found' });
        if (post.author_id !== req.user.id && !['admin', 'super_admin'].includes(req.user.role))
            return res.status(403).json({ error: 'You can only delete your own post' });

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

        const { data: existing } = await supabase.from('post_reactions')
            .select('id,type').eq('post_id', req.params.id).eq('user_id', req.user.id).maybeSingle();

        if (existing && existing.type === type) {
            await supabase.from('post_reactions').delete().eq('id', existing.id);
        } else if (existing) {
            await supabase.from('post_reactions').update({ type }).eq('id', existing.id);
        } else {
            await supabase.from('post_reactions').insert([{ post_id: req.params.id, user_id: req.user.id, type }]);
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/posts/:id/comments', auth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('post_comments')
            .select('*, profiles(full_name, role, avatar_url)')
            .eq('post_id', req.params.id)
            .order('created_at', { ascending: true });
        if (error) throw error;
        res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/posts/:id/comments', auth, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content?.trim()) return res.status(400).json({ error: 'Empty reply' });
        const { data, error } = await supabase.from('post_comments').insert([{
            post_id: req.params.id, user_id: req.user.id, content
        }]).select('*, profiles(full_name, role, avatar_url)').single();
        if (error) throw error;
        res.json({ success: true, comment: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// MESSAGES
app.get('/api/messages/unread', auth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('direct_messages')
            .select('id, sender_id')
            .eq('receiver_id', req.user.id)
            .eq('is_read', false);
        if (error) throw error;

        const bySender = {};
        (data || []).forEach(m => { bySender[m.sender_id] = (bySender[m.sender_id] || 0) + 1; });
        res.json({ total: (data || []).length, bySender });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/messages/:otherUserId', auth, async (req, res) => {
    try {
        const other = req.params.otherUserId;
        const { data, error } = await supabase.from('direct_messages').select('*')
            .or(`and(sender_id.eq.${req.user.id},receiver_id.eq.${other}),and(sender_id.eq.${other},receiver_id.eq.${req.user.id})`)
            .order('created_at', { ascending: true })
            .limit(500);
        if (error) throw error;

        const ids = (data || []).map(m => m.id);
        let reactions = [];
        if (ids.length) {
            const { data: r } = await supabase.from('message_reactions').select('message_id,user_id,type').in('message_id', ids);
            reactions = r || [];
        }

        const out = (data || []).map(m => {
            const mr = reactions.filter(r => r.message_id === m.id);
            return {
                ...m,
                content: m.deleted ? null : m.content,
                likes: mr.filter(r => r.type === 'like').length,
                dislikes: mr.filter(r => r.type === 'dislike').length,
                my_reaction: mr.find(r => r.user_id === req.user.id)?.type || null
            };
        });

        await supabase.from('direct_messages')
            .update({ is_read: true })
            .eq('receiver_id', req.user.id).eq('sender_id', other).eq('is_read', false);

        res.json(out);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/messages', auth, async (req, res) => {
    try {
        const { receiver_id, text, message_type, file_url, reply_to } = req.body;
        if (!receiver_id) return res.status(400).json({ error: 'Receiver required' });
        if (!text?.trim() && !file_url) return res.status(400).json({ error: 'Empty message' });

        const { data, error } = await supabase.from('direct_messages').insert([{
            sender_id: req.user.id,
            receiver_id,
            content: text || '',
            message_type: message_type || 'text',
            file_url: file_url || null,
            reply_to: reply_to || null,
            is_read: false
        }]).select().single();
        if (error) throw error;
        res.json({ success: true, message: data });
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

        const { data: existing } = await supabase.from('message_reactions')
            .select('id,type').eq('message_id', req.params.id).eq('user_id', req.user.id).maybeSingle();

        if (existing && existing.type === type) {
            await supabase.from('message_reactions').delete().eq('id', existing.id);
        } else if (existing) {
            await supabase.from('message_reactions').update({ type }).eq('id', existing.id);
        } else {
            await supabase.from('message_reactions').insert([{ message_id: req.params.id, user_id: req.user.id, type }]);
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// TRANSLATION
app.get('/api/translate/languages', auth, (req, res) => {
    res.json(Object.keys(HASAB_LANGS).map(name => ({ name, code: HASAB_LANGS[name] })));
});

app.post('/api/translate', auth, async (req, res) => {
    try {
        const { text, targetLang, sourceLang } = req.body;
        if (!text || !text.trim()) return res.json({ translatedText: '' });

        const target_language = HASAB_LANGS[targetLang] || 'amh';
        const source_language = sourceLang
            ? (HASAB_LANGS[sourceLang] || 'eng')
            : (/[\u1200-\u137F]/.test(text) ? 'amh' : 'eng');

        if (source_language === target_language) return res.json({ translatedText: text });

        const response = await fetch('https://api.hasab.ai/api/translate', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${process.env.HASAB_API_KEY}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ text, source_language, target_language })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Hasab API error');

        const finalTranslation = data.translation || data.translatedText || data.text || 'Translation failed.';
        res.json({ translatedText: finalTranslation, source_language, target_language });
    } catch (error) {
        console.error('Hasab Translation Error:', error);
        res.status(500).json({ error: 'Translation failed' });
    }
});

// WORKERS
app.get('/api/branch/workers', auth, role('branch_admin', 'admin', 'super_admin'), async (req, res) => {
    try {
        let q = supabase.from('profiles')
            .select('id, full_name, staff_id, phone, role, bio, is_active, created_at, branch_id, avatar_url')
            .order('full_name');
        if (req.user.role === 'branch_admin' && req.user.branch_id) q = q.eq('branch_id', req.user.branch_id);
        const { data, error } = await q;
        if (error) throw error;
        res.json((data || []).filter(w => w.role !== 'branch_admin'));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/branch/workers', auth, role('branch_admin', 'admin', 'super_admin'), async (req, res) => {
    try {
        const { full_name, phone, role_code, bio } = req.body;
        if (!full_name || !role_code) return res.status(400).json({ error: 'Name and role are required' });

        const branchId = req.user.branch_id;
        if (!branchId) return res.status(400).json({ error: 'No branch assigned to your account' });

        const { data: roleRow } = await supabase.from('worker_roles').select('code, title').eq('code', role_code).maybeSingle();
        if (!roleRow) return res.status(400).json({ error: 'Invalid role code' });

        const staffId = await generateStaffId(branchId, role_code);
        const password = generateTempPassword(10);
        const email = `${staffId.toLowerCase()}@medconnect.com`;

        const { data: authData, error: aErr } = await supabase.auth.admin.createUser({
            email, password, email_confirm: true,
            user_metadata: { full_name, role: role_code }
        });
        if (aErr) return res.status(500).json({ error: aErr.message });

        const hash = await bcrypt.hash(password, 10);
        const { data: profile, error: pErr } = await supabase.from('profiles').insert([{
            id: authData.user.id, staff_id: staffId, full_name, phone: phone || null,
            role: role_code, branch_id: branchId, bio: bio || null,
            password_hash: hash, is_active: true
        }]).select('id, staff_id, full_name, role, phone, is_active').single();

        if (pErr) {
            await supabase.auth.admin.deleteUser(authData.user.id);
            return res.status(500).json({ error: pErr.message });
        }
        res.json({ success: true, worker: profile, credentials: { staff_id: staffId, password, full_name, role: role_code } });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/branch/workers/:id', auth, role('branch_admin', 'admin', 'super_admin'), async (req, res) => {
    try {
        if (req.user.role === 'branch_admin') {
            const { data: target } = await supabase.from('profiles').select('branch_id, role').eq('id', req.params.id).single();
            if (!target) return res.status(404).json({ error: 'Worker not found' });
            if (target.branch_id !== req.user.branch_id) return res.status(403).json({ error: 'Not in your branch' });
            if (target.role === 'branch_admin') return res.status(403).json({ error: 'Cannot edit branch admin' });
        }
        const updates = {};
        const { full_name, phone, bio, is_active } = req.body;
        if (full_name !== undefined) updates.full_name = full_name;
        if (phone !== undefined) updates.phone = phone;
        if (bio !== undefined) updates.bio = bio;
        if (is_active !== undefined) updates.is_active = is_active;
        if (!Object.keys(updates).length) return res.status(400).json({ error: 'Nothing to update' });

        const { data, error } = await supabase.from('profiles').update(updates).eq('id', req.params.id).select().single();
        if (error) throw error;
        delete data.password_hash;
        res.json({ success: true, worker: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/branch/workers/:id/reset-password', auth, role('branch_admin', 'admin', 'super_admin'), async (req, res) => {
    try {
        if (req.user.role === 'branch_admin') {
            const { data: t } = await supabase.from('profiles').select('branch_id').eq('id', req.params.id).single();
            if (t?.branch_id !== req.user.branch_id) return res.status(403).json({ error: 'Not in your branch' });
        }
        const newPassword = generateTempPassword(10);
        const hash = await bcrypt.hash(newPassword, 10);
        const { data, error } = await supabase.from('profiles').update({ password_hash: hash })
            .eq('id', req.params.id).select('staff_id').single();
        if (error) throw error;
        try { await supabase.auth.admin.updateUserById(req.params.id, { password: newPassword }); } catch (_) {}
        res.json({ success: true, staff_id: data.staff_id, password: newPassword });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/branch/workers/:id', auth, role('branch_admin', 'admin', 'super_admin'), async (req, res) => {
    try {
        const { data: target } = await supabase.from('profiles').select('branch_id, role, id').eq('id', req.params.id).single();
        if (!target) return res.status(404).json({ error: 'Worker not found' });
        if (target.role === 'branch_admin') return res.status(403).json({ error: 'Cannot delete branch admin' });
        if (req.user.role === 'branch_admin' && target.branch_id !== req.user.branch_id)
            return res.status(403).json({ error: 'Not in your branch' });

        await supabase.from('profiles').delete().eq('id', req.params.id);
        try { await supabase.auth.admin.deleteUser(req.params.id); } catch (_) {}
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// CLINICAL MODULES (Patients, Appointments, etc.)
app.get('/api/patients', auth, async (req, res) => {
    try {
        const { q, branch_id } = req.query;
        let query = supabase.from('patients').select('*, branches(name)').order('created_at', { ascending: false }).limit(300);
        if (branch_id) query = query.eq('branch_id', branch_id);
        if (q) query = query.or(`full_name.ilike.%${q}%,phone.ilike.%${q}%,mrn.ilike.%${q}%`);
        const { data, error } = await query;
        if (error) throw error;
        res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/patients', auth, async (req, res) => {
    try {
        const p = req.body;
        if (!p.full_name) return res.status(400).json({ error: 'Full name is required' });
        if (!p.mrn) p.mrn = `MRN-${Date.now().toString().slice(-8)}`;
        const { data, error } = await supabase.from('patients').insert([{
            full_name: p.full_name, mrn: p.mrn, phone: p.phone, gender: p.gender,
            dob: p.dob || null, address: p.address, blood_type: p.blood_type,
            allergies: p.allergies, emergency_contact: p.emergency_contact,
            branch_id: p.branch_id || req.user.branch_id, created_by: req.user.id
        }]).select().single();
        if (error) throw error;
        res.json({ success: true, patient: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/patients/:id', auth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('patients').update(req.body).eq('id', req.params.id).select().single();
        if (error) throw error;
        res.json({ success: true, patient: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/appointments', auth, async (req, res) => {
    try {
        let q = supabase.from('appointments')
            .select('*, patients(full_name, mrn), branches(name)')
            .order('scheduled_at', { ascending: true }).limit(300);
        if (req.user.branch_id && !['admin', 'super_admin'].includes(req.user.role))
            q = q.eq('branch_id', req.user.branch_id);
        const { data, error } = await q;
        if (error) throw error;
        res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/appointments', auth, async (req, res) => {
    try {
        const a = req.body;
        if (!a.patient_id || !a.scheduled_at) return res.status(400).json({ error: 'Patient and time required' });
        const { data, error } = await supabase.from('appointments').insert([{
            patient_id: a.patient_id, provider_id: a.provider_id || null,
            branch_id: a.branch_id || req.user.branch_id,
            scheduled_at: a.scheduled_at, reason: a.reason, notes: a.notes,
            created_by: req.user.id
        }]).select().single();
        if (error) throw error;
        res.json({ success: true, appointment: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/appointments/:id/status', auth, async (req, res) => {
    try {
        const { status } = req.body;
        const { data, error } = await supabase.from('appointments').update({ status }).eq('id', req.params.id).select().single();
        if (error) throw error;
        res.json({ success: true, appointment: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/referrals', auth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('referrals')
            .select('*, patients(full_name, mrn)').order('created_at', { ascending: false }).limit(300);
        if (error) throw error;
        res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/referrals', auth, async (req, res) => {
    try {
        const r = req.body;
        if (!r.patient_id || !r.reason) return res.status(400).json({ error: 'Patient and reason required' });
        const { data, error } = await supabase.from('referrals').insert([{
            patient_id: r.patient_id, from_provider: req.user.id,
            from_branch: req.user.branch_id, to_branch: r.to_branch || null,
            to_level: r.to_level || 'facility', to_recipient: r.to_recipient || null,
            reason: r.reason, urgency: r.urgency || 'routine', notes: r.notes
        }]).select().single();
        if (error) throw error;
        res.json({ success: true, referral: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/referrals/:id/status', auth, async (req, res) => {
    try {
        const { status } = req.body;
        const { data, error } = await supabase.from('referrals').update({ status }).eq('id', req.params.id).select().single();
        if (error) throw error;
        res.json({ success: true, referral: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/lab-orders', auth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('lab_orders')
            .select('*, patients(full_name, mrn)').order('created_at', { ascending: false }).limit(300);
        if (error) throw error;
        res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/lab-orders', auth, async (req, res) => {
    try {
        const o = req.body;
        if (!o.patient_id || !o.test_name) return res.status(400).json({ error: 'Patient and test required' });
        const { data, error } = await supabase.from('lab_orders').insert([{
            patient_id: o.patient_id, ordered_by: req.user.id,
            branch_id: o.branch_id || req.user.branch_id,
            test_name: o.test_name, priority: o.priority || 'routine', notes: o.notes
        }]).select().single();
        if (error) throw error;
        res.json({ success: true, order: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/lab-orders/:id', auth, async (req, res) => {
    try {
        const payload = { ...req.body };
        if (payload.result) { payload.result_at = new Date().toISOString(); payload.status = 'completed'; }
        const { data, error } = await supabase.from('lab_orders').update(payload).eq('id', req.params.id).select().single();
        if (error) throw error;
        res.json({ success: true, order: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/prescriptions', auth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('prescriptions')
            .select('*, patients(full_name, mrn)').order('created_at', { ascending: false }).limit(300);
        if (error) throw error;
        res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/prescriptions', auth, async (req, res) => {
    try {
        const p = req.body;
        if (!p.patient_id || !p.medication) return res.status(400).json({ error: 'Patient and medication required' });
        const { data, error } = await supabase.from('prescriptions').insert([{
            patient_id: p.patient_id, prescribed_by: req.user.id,
            branch_id: p.branch_id || req.user.branch_id,
            medication: p.medication, dosage: p.dosage, frequency: p.frequency, duration: p.duration
        }]).select().single();
        if (error) throw error;
        res.json({ success: true, prescription: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/prescriptions/:id/dispense', auth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('prescriptions').update({
            status: 'dispensed', dispensed_by: req.user.id, dispensed_at: new Date().toISOString()
        }).eq('id', req.params.id).select().single();
        if (error) throw error;
        res.json({ success: true, prescription: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/inventory', auth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('inventory').select('*').order('item_name');
        if (error) throw error;
        res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/inventory', auth, async (req, res) => {
    try {
        const i = req.body;
        if (!i.item_name) return res.status(400).json({ error: 'Item name required' });
        const { data, error } = await supabase.from('inventory').insert([{
            branch_id: i.branch_id || req.user.branch_id,
            item_name: i.item_name, category: i.category || 'supply',
            quantity: Number(i.quantity) || 0, unit: i.unit,
            reorder_level: Number(i.reorder_level) || 10,
            expiry_date: i.expiry_date || null
        }]).select().single();
        if (error) throw error;
        res.json({ success: true, item: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/inventory/:id/adjust', auth, async (req, res) => {
    try {
        const delta = Number(req.body.delta) || 0;
        const { data: cur } = await supabase.from('inventory').select('quantity').eq('id', req.params.id).single();
        const newQty = Math.max(0, (cur?.quantity || 0) + delta);
        const { data, error } = await supabase.from('inventory')
            .update({ quantity: newQty, updated_at: new Date().toISOString() })
            .eq('id', req.params.id).select().single();
        if (error) throw error;
        res.json({ success: true, item: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/worker-roles', auth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('worker_roles').select('*').order('category').order('title');
        if (error) throw error;
        res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/staff', auth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('profiles')
            .select('id, full_name, role, branch_id, staff_id, avatar_url, bio')
            .eq('is_active', true).order('full_name');
        if (error) throw error;
        res.json(data || []);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/profile', auth, async (req, res) => {
    try {
        const { full_name, phone, bio, avatar_url } = req.body;
        const updates = {};
        if (full_name) updates.full_name = full_name;
        if (phone !== undefined) updates.phone = phone;
        if (bio !== undefined) updates.bio = bio;
        if (avatar_url !== undefined) updates.avatar_url = avatar_url;
        if (!Object.keys(updates).length) return res.status(400).json({ error: 'Nothing to update' });

        const { data, error } = await supabase.from('profiles').update(updates).eq('id', req.user.id).select().single();
        if (error) throw error;
        delete data.password_hash;
        res.json({ success: true, profile: data });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/profile/avatar', auth, upload.single('avatar'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No image' });
        const ext = (req.file.originalname.split('.').pop() || 'png').toLowerCase();
        const filePath = `avatars/${req.user.id}-${Date.now()}.${ext}`;
        const { error } = await supabase.storage.from('medconnect').upload(filePath, req.file.buffer, {
            contentType: req.file.mimetype, upsert: true
        });
        if (error) throw error;
        const { data: { publicUrl } } = supabase.storage.from('medconnect').getPublicUrl(filePath);
        await supabase.from('profiles').update({ avatar_url: publicUrl }).eq('id', req.user.id);
        res.json({ success: true, avatar_url: publicUrl });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/profile/password', auth, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!newPassword || newPassword.length < 6)
            return res.status(400).json({ error: 'New password must be at least 6 characters' });

        const { data: me } = await supabase.from('profiles').select('password_hash').eq('id', req.user.id).single();
        if (!me?.password_hash) return res.status(400).json({ error: 'No password on file' });
        const ok = await bcrypt.compare(currentPassword || '', me.password_hash);
        if (!ok) return res.status(401).json({ error: 'Current password is incorrect' });

        const hash = await bcrypt.hash(newPassword, 10);
        await supabase.from('profiles').update({ password_hash: hash }).eq('id', req.user.id);
        try { await supabase.auth.admin.updateUserById(req.user.id, { password: newPassword }); } catch (_) {}
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// LIVE CONFERENCE
const LIVE = { rooms: new Map(), seq: 0 };

function liveRoom(branchId) {
    if (!LIVE.rooms.has(branchId)) {
        LIVE.rooms.set(branchId, {
            active: false,
            moderator: null,
            startedAt: null,
            participants: new Map(),
            requests: new Map(),
            signals: []
        });
    }
    return LIVE.rooms.get(branchId);
}

function pushSignal(room, from, to, type, payload) {
    LIVE.seq += 1;
    room.signals.push({ seq: LIVE.seq, from, to, type, payload, at: Date.now() });
    const cutoff = Date.now() - 90000;
    room.signals = room.signals.filter(s => s.at > cutoff).slice(-500);
}

const LIVE_GUARDS = ['admin', 'super_admin', 'branch_admin'];

app.post('/api/live/toggle', auth, role(...LIVE_GUARDS), async (req, res) => {
    try {
        const branchId = req.user.branch_id || 'global';
        const room = liveRoom(branchId);
        const on = !!req.body.on;

        if (on) {
            room.active = true;
            room.startedAt = new Date().toISOString();
            room.moderator = { id: req.user.id, name: req.user.name, role: req.user.role };
        } else {
            room.active = false;
            room.startedAt = null;
            room.moderator = null;
            room.participants.clear();
            room.requests.clear();
            room.signals = [];
        }
        res.json({ success: true, active: room.active, moderator: room.moderator });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/live/status', auth, async (req, res) => {
    try {
        const branchId = req.user.branch_id || 'global';
        const room = liveRoom(branchId);
        const myRequest = room.requests.get(req.user.id) || null;
        const me = room.participants.get(req.user.id) || null;
        res.json({
            active: room.active,
            moderator: room.moderator,
            startedAt: room.startedAt,
            participantCount: room.participants.size,
            participants: Array.from(room.participants.values()),
            myRequest,
            iAmParticipant: !!me,
            iAmModerator: room.moderator?.id === req.user.id
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/live/request', auth, async (req, res) => {
    try {
        const branchId = req.user.branch_id || 'global';
        const room = liveRoom(branchId);
        if (!room.active) return res.status(400).json({ error: 'Live conference is not active' });
        if (room.moderator?.id === req.user.id) return res.status(400).json({ error: 'You are the moderator' });

        room.requests.set(req.user.id, {
            id: req.user.id, name: req.user.name, role: req.user.role, staff_id: req.user.staff_id,
            lang: req.body.lang || 'English', requestedAt: new Date().toISOString(), status: 'pending'
        });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/live/requests', auth, role(...LIVE_GUARDS), async (req, res) => {
    try {
        const branchId = req.user.branch_id || 'global';
        const room = liveRoom(branchId);
        res.json({
            active: room.active, moderator: room.moderator,
            requests: Array.from(room.requests.values()), participants: Array.from(room.participants.values())
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/live/requests/:userId/:action', auth, role(...LIVE_GUARDS), async (req, res) => {
    try {
        const branchId = req.user.branch_id || 'global';
        const room = liveRoom(branchId);
        if (!room.active) return res.status(400).json({ error: 'Live conference is not active' });

        const { userId, action } = req.params;
        const reqObj = room.requests.get(userId);
        if (!reqObj) return res.status(404).json({ error: 'Request not found' });

        if (action === 'approve') {
            reqObj.status = 'approved';
            room.participants.set(userId, {
                id: userId, name: reqObj.name, role: reqObj.role, lang: reqObj.lang, joinedAt: new Date().toISOString()
            });
            pushSignal(room, 'system', userId, 'approved', { by: req.user.id });
            pushSignal(room, 'system', req.user.id, 'participant-joined', { userId });
        } else {
            reqObj.status = 'rejected';
            pushSignal(room, 'system', userId, 'rejected', { by: req.user.id });
            room.requests.delete(userId);
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/live/leave', auth, async (req, res) => {
    try {
        const branchId = req.user.branch_id || 'global';
        const room = liveRoom(branchId);
        room.participants.delete(req.user.id);
        room.requests.delete(req.user.id);
        pushSignal(room, req.user.id, '*', 'participant-left', { userId: req.user.id });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/live/signal', auth, async (req, res) => {
    try {
        const branchId = req.user.branch_id || 'global';
        const room = liveRoom(branchId);
        const { to, type, payload } = req.body;
        if (!to || !type) return res.status(400).json({ error: 'to and type required' });
        pushSignal(room, req.user.id, to, type, payload || {});
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/live/signal', auth, async (req, res) => {
    try {
        const branchId = req.user.branch_id || 'global';
        const room = liveRoom(branchId);
        const since = parseInt(req.query.since || '0', 10);

        const mine = room.signals.filter(s =>
            s.seq > since && (s.to === req.user.id || s.to === '*' || s.from === req.user.id)
        );
        const lastSeq = room.signals.length ? room.signals[room.signals.length - 1].seq : since;
        res.json({ signals: mine, lastSeq });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 404 Catch-all
app.use((req, res) => res.status(404).json({ error: 'API route not found.', url: req.url, method: req.method }));

// Export the app for Vercel
export default app;

// Only listen locally
if (!process.env.VERCEL) {
    const PORT = process.env.PORT || 5050;
    app.listen(PORT, () => {
        console.log(`\n========================================`);
        console.log(`🚀 MedConnect server running on http://localhost:${PORT}`);
        console.log(`========================================\n`);
    });
}