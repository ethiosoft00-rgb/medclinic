CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- CORE TABLES
CREATE TABLE facilities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  facility_id UUID REFERENCES facilities(id),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE patients (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  facility_id UUID REFERENCES facilities(id),
  full_name TEXT NOT NULL,
  sex TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE encounters (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  facility_id UUID REFERENCES facilities(id),
  patient_id UUID REFERENCES patients(id),
  status TEXT DEFAULT 'open',
  opened_at TIMESTAMPTZ DEFAULT now()
);

-- MODULE TABLES
CREATE TABLE queue_tickets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  facility_id UUID REFERENCES facilities(id),
  encounter_id UUID REFERENCES encounters(id),
  number TEXT NOT NULL,
  status TEXT DEFAULT 'waiting',
  priority TEXT DEFAULT 'routine',
  issued_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE stock_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  facility_id UUID REFERENCES facilities(id),
  name TEXT NOT NULL,
  batch TEXT,
  quantity INT DEFAULT 0,
  expiry_date DATE,
  status TEXT DEFAULT 'ok'
);

CREATE TABLE clinical_notes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  facility_id UUID REFERENCES facilities(id),
  encounter_id UUID REFERENCES encounters(id),
  subjective TEXT,
  objective TEXT,
  assessment TEXT,
  plan TEXT,
  signed_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT now()
);

-- SEED DATA (Default Admin: admin@clinic.com / Password: admin123)
INSERT INTO facilities (id, name) VALUES ('11111111-1111-1111-1111-111111111111', 'Bishoftu Health Center');
INSERT INTO users (facility_id, email, password_hash, full_name, role) 
VALUES ('11111111-1111-1111-1111-111111111111', 'admin@clinic.com', '$2a$10$Xm5M4Q1r7K8z4y9w2x3c4uY5t6R7s8A9b0C1d2E3f4G5h6I7j8K9l', 'Admin User', 'admin');
INSERT INTO stock_items (facility_id, name, batch, quantity, expiry_date, status) VALUES 
('11111111-1111-1111-1111-111111111111', 'Amoxicillin 500mg', 'AMX-2024-A', 340, '2025-12-01', 'ok'),
('11111111-1111-1111-1111-111111111111', 'Paracetamol 500mg', 'PCM-2024-B', 900, '2026-05-10', 'ok'),
('11111111-1111-1111-1111-111111111111', 'Insulin (Vial)', 'INS-2023-X', 15, '2023-11-01', 'low');