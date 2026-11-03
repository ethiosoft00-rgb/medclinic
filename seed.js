import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';

dotenv.config();

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
);

async function createAdmin() {
    const staffId = 'admin';
    const password = 'admin123';
    const email = 'admin@medconnect.com';
    
    console.log("1. Hashing password...");
    const hash = await bcrypt.hash(password, 10);

    console.log("2. Checking if user exists in database...");
    const { data: existing } = await supabase.from('profiles').select('id').eq('staff_id', staffId).maybeSingle();

    if (existing) {
        console.log("User exists. Updating password...");
        await supabase.from('profiles').update({ password_hash: hash }).eq('id', existing.id);
        console.log("✅ DONE! You can now login with:");
        console.log(`Staff ID: ${staffId}`);
        console.log(`Password: ${password}`);
        return;
    }

    console.log("3. Creating user in Supabase Auth...");
    const { data: authData, error: authError } = await supabase.auth.admin.createUser({
        email: email,
        password: password,
        email_confirm: true,
        user_metadata: { full_name: 'System Admin', role: 'super_admin' }
    });

    if (authError) {
        console.error("❌ Auth Error:", authError.message);
        return;
    }

    console.log("4. Creating profile record...");
    const { error: profileError } = await supabase.from('profiles').insert([{
        id: authData.user.id,
        staff_id: staffId,
        full_name: 'System Admin',
        role: 'super_admin',
        password_hash: hash
    }]);

    if (profileError) {
        console.error("❌ Profile Error:", profileError.message);
    } else {
        console.log("✅ DONE! You can now login with:");
        console.log(`Staff ID: ${staffId}`);
        console.log(`Password: ${password}`);
    }
}

createAdmin();