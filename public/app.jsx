const { useState, useEffect } = React;
const { BrowserRouter, Routes, Route, Link, useLocation } = ReactRouterDOM;

// --- LAYOUT ---
function Layout({ children }) {
  const location = useLocation();
  const links = [
    { path: '/', label: 'Dashboard', icon: 'fa-chart-pie' },
    { path: '/intake', label: 'MedGuide (Intake)', icon: 'fa-clipboard-user' },
    { path: '/queue', label: 'SmartQueue', icon: 'fa-users-line' },
    { path: '/stock', label: 'MedStock', icon: 'fa-pills' },
    { path: '/notes', label: 'ClinicNote AI', icon: 'fa-file-medical' },
  ];

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-header"><i className="fa-solid fa-hospital text-teal-400"></i> MedClinic</div>
        <nav>
          {links.map(l => (
            <Link key={l.path} to={l.path} className={location.pathname === l.path ? 'active' : ''}>
              <i className={`fa-solid ${l.icon}`}></i> {l.label}
            </Link>
          ))}
        </nav>
      </aside>
      <main className="main-content">
        <header className="topbar">
          <h2 style={{ color: '#64748b', fontSize: '1rem' }}>Bishoftu Health Center</h2>
          <div className="user-profile">
            <div className="user-avatar">A</div>
            <div>Admin User <br/><span style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: 'normal' }}>Administrator</span></div>
          </div>
        </header>
        <div className="page-wrapper">{children}</div>
      </main>
    </>
  );
}

function ExportToolbar({ title, icon, onExport }) {
  return (
    <div className="toolbar">
      <h2><i className={`fa-solid ${icon}`} style={{ color: 'var(--primary)' }}></i> {title}</h2>
      <div className="btn-group">
        <button className="btn btn-outline" onClick={() => window.print()}><i className="fa-solid fa-print"></i> Print</button>
        <button className="btn btn-primary" onClick={onExport}><i className="fa-solid fa-file-excel"></i> Export CSV</button>
      </div>
    </div>
  );
}

// --- PAGES ---
function Dashboard() {
  return (
    <>
      <div className="hero">
        <h2>Welcome back, Admin</h2>
        <p>Here is the current overview of Bishoftu Health Center.</p>
      </div>
      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-icon"><i className="fa-solid fa-user-injured"></i></div>
          <div className="stat-info"><h3>Total Patients Today</h3><p>124</p></div>
        </div>
        <div className="stat-card" style={{ borderLeftColor: 'var(--warning)' }}>
          <div className="stat-icon" style={{ color: 'var(--warning)', background: '#fef3c7' }}><i className="fa-solid fa-users-line"></i></div>
          <div className="stat-info"><h3>In Queue Now</h3><p>18</p></div>
        </div>
      </div>
      <div className="module-grid">
        <Link to="/intake" className="module-card">
          <div className="module-img bg-intake"></div>
          <div className="module-body">
            <div className="module-title"><i className="fa-solid fa-clipboard-user"></i> MedGuide Intake</div>
            <div className="module-desc">Register new patients and collect bilingual symptom data.</div>
          </div>
        </Link>
        <Link to="/notes" className="module-card">
          <div className="module-img bg-notes"></div>
          <div className="module-body">
            <div className="module-title"><i className="fa-solid fa-file-medical"></i> AI Clinical Notes</div>
            <div className="module-desc">Generate SOAP notes from patient data using Groq AI.</div>
          </div>
        </Link>
      </div>
    </>
  );
}

function Intake() {
  const [lang, setLang] = useState('am');
  return (
    <>
      <ExportToolbar title="MedGuide - Patient Intake" icon="fa-clipboard-user" onExport={() => alert('Exported!')} />
      <div style={{ background: 'white', padding: '2rem', borderRadius: '12px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2rem' }}>
          <h3>New Patient Form</h3>
          <select className="form-control" style={{ width: '200px' }} value={lang} onChange={e => setLang(e.target.value)}>
            <option value="am">አማርኛ (Amharic)</option>
            <option value="en">English</option>
          </select>
        </div>
        <div className="form-grid">
          <div className="form-group"><label>Full Name</label><input type="text" className="form-control" /></div>
          <div className="form-group"><label>Age</label><input type="number" className="form-control" /></div>
        </div>
        <button className="btn btn-primary" style={{ marginTop: '1rem' }}><i className="fa-solid fa-save"></i> Submit Intake</button>
      </div>
    </>
  );
}

function Queue() {
  const [queue, setQueue] = useState([]);
  
  useEffect(() => {
    fetch('/api/queue').then(res => res.json()).then(data => setQueue(data));
  }, []);

  const handleExport = () => {
    const csv = "Number,Status,Priority\n" + queue.map(q => `${q.number},${q.status},${q.priority}`).join("\n");
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'queue.csv'; a.click();
  };

  return (
    <>
      <ExportToolbar title="SmartQueue - Patient Flow" icon="fa-users-line" onExport={handleExport} />
      <table className="data-table">
        <thead><tr><th>Ticket #</th><th>Patient Name</th><th>Priority</th><th>Status</th></tr></thead>
        <tbody>
          {queue.map(q => (
            <tr key={q.id}>
              <td style={{ fontWeight: 'bold' }}>{q.number}</td>
              <td>{q.name || 'Unknown Patient'}</td>
              <td><span className={`badge badge-${q.priority === 'urgent' ? 'urgent' : 'routine'}`}>{q.priority}</span></td>
              <td><span className={`badge badge-${q.status === 'waiting' ? 'waiting' : 'routine'}`}>{q.status}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function Stock() {
  const [stock, setStock] = useState([]);
  
  useEffect(() => {
    fetch('/api/stock').then(res => res.json()).then(data => setStock(data)).catch(() => {
      setStock([{ name: 'Amoxicillin', batch: 'AMX-1', quantity: 340, expiry_date: '2025-12-01', status: 'ok' }]);
    });
  }, []);

  return (
    <>
      <ExportToolbar title="MedStock - Inventory" icon="fa-pills" onExport={() => alert('Exported!')} />
      <table className="data-table">
        <thead><tr><th>Medicine Name</th><th>Batch</th><th>Qty</th><th>Expiry</th><th>Status</th></tr></thead>
        <tbody>
          {stock.map((s, i) => (
            <tr key={i}>
              <td style={{ fontWeight: 'bold' }}>{s.name}</td>
              <td>{s.batch}</td>
              <td>{s.quantity}</td>
              <td>{s.expiry_date?.split('T')[0]}</td>
              <td><span className={`badge badge-${s.status === 'low' ? 'urgent' : 'routine'}`}>{s.status === 'low' ? 'Low Stock' : 'OK'}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function Notes() {
  const [isGenerating, setIsGenerating] = useState(false);
  const [note, setNote] = useState({ subjective: '', objective: '', assessment: '', plan: '' });

  const generateAI = async () => {
    setIsGenerating(true);
    try {
      const res = await fetch('/api/generate-note', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ symptoms: "Patient has chest pain and fever for 3 days." })
      });
      const data = await res.json();
      setNote(data);
    } catch (e) {
      setNote({ subjective: "Error connecting to AI.", objective: "", assessment: "", plan: "" });
    }
    setIsGenerating(false);
  };

  return (
    <>
      <ExportToolbar title="ClinicNote - AI SOAP Note" icon="fa-file-medical" onExport={() => window.print()} />
      <div style={{ background: 'white', padding: '2rem', borderRadius: '12px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
          <h3>Patient Encounter Note</h3>
          <button className="btn btn-primary" onClick={generateAI} disabled={isGenerating}>
            <i className="fa-solid fa-wand-magic-sparkles"></i> {isGenerating ? 'Generating with Groq...' : 'Generate with Groq AI'}
          </button>
        </div>
        <div className="form-group"><label>Subjective</label><textarea className="form-control" value={note.subjective} onChange={e => setNote({...note, subjective: e.target.value})}></textarea></div>
        <div className="form-group"><label>Objective</label><textarea className="form-control" value={note.objective} onChange={e => setNote({...note, objective: e.target.value})}></textarea></div>
        <div className="form-group"><label>Assessment</label><textarea className="form-control" value={note.assessment} onChange={e => setNote({...note, assessment: e.target.value})}></textarea></div>
        <div className="form-group"><label>Plan</label><textarea className="form-control" value={note.plan} onChange={e => setNote({...note, plan: e.target.value})}></textarea></div>
        <button className="btn btn-danger" style={{ marginTop: '1rem' }}><i className="fa-solid fa-signature"></i> Sign & Lock Note</button>
      </div>
    </>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/intake" element={<Intake />} />
          <Route path="/queue" element={<Queue />} />
          <Route path="/stock" element={<Stock />} />
          <Route path="/notes" element={<Notes />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);