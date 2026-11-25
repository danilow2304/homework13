import { createContext, useContext, useEffect, useState } from 'react';
import { Link, Navigate, Outlet, Route, Routes, useLocation, useNavigate } from 'react-router-dom';

// ---------- API helper (cookie is sent automatically; JS never touches the token) ----------
async function api(path, method = 'GET', data) {
  const res = await fetch(path, {
    method,
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: data ? JSON.stringify(data) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(json.message || 'Request failed');
    err.status = res.status;
    err.errors = json.errors || [];
    throw err;
  }
  return json;
}

// ---------- Auth context ----------
const AuthContext = createContext(null);
const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api('/api/auth/me').then(setUser).catch(() => setUser(null)).finally(() => setLoading(false));
  }, []);

  const register = async (data) => setUser(await api('/api/auth/register', 'POST', data));
  const login = async (data) => setUser(await api('/api/auth/login', 'POST', data));
  const logout = async () => { await api('/api/auth/logout', 'POST'); setUser(null); };

  return <AuthContext.Provider value={{ user, loading, register, login, logout }}>{children}</AuthContext.Provider>;
}

// ---------- Protected route (UI only; the server is the real gate) ----------
function ProtectedRoute({ role }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <p className="container">Checking session...</p>;
  if (!user) return <Navigate to="/login" replace state={{ from: location }} />;
  if (role && user.role !== role) return <p className="container error">403 - You are not authorized to view this page.</p>;
  return <Outlet />;
}

// ---------- Layout ----------
function Nav() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  return (
    <nav>
      <strong>MERN Auth</strong>
      {user && <Link to="/notes">My Notes</Link>}
      {user?.role === 'admin' && <Link to="/admin/users">Users (admin)</Link>}
      <span className="spacer" />
      {user ? (
        <>
          <span>{user.name} ({user.role})</span>
          <button className="secondary" onClick={async () => { await logout(); navigate('/login'); }}>Log out</button>
        </>
      ) : (
        <>
          <Link to="/login">Log in</Link>
          <Link to="/register">Register</Link>
        </>
      )}
    </nav>
  );
}

// ---------- Auth form (shared by Register + Login) ----------
function AuthForm({ mode }) {
  const { register, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const isRegister = mode === 'register';
  const [form, setForm] = useState({ name: '', email: '', password: '', confirm: '' });
  const [errors, setErrors] = useState({});
  const [serverError, setServerError] = useState('');

  const change = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  // Client-side validation = better UX. The server validates again.
  const check = () => {
    const e = {};
    if (isRegister && form.name.trim().length < 2) e.name = 'Name must be at least 2 characters';
    if (!/^\S+@\S+\.\S+$/.test(form.email.trim())) e.email = 'Enter a valid email';
    if (isRegister) {
      const p = form.password;
      if (p.length < 12 || !/[a-z]/.test(p) || !/[A-Z]/.test(p) || !/\d/.test(p) || !/[^A-Za-z0-9]/.test(p))
        e.password = 'Use 12+ characters with upper, lower, number and symbol';
      if (form.confirm !== p) e.confirm = 'Passwords do not match';
    } else if (!form.password) e.password = 'Password is required';
    return e;
  };

  const submit = async (ev) => {
    ev.preventDefault();
    setServerError('');
    const found = check();
    setErrors(found);
    if (Object.keys(found).length) return;
    try {
      if (isRegister) await register({ name: form.name, email: form.email, password: form.password });
      else await login({ email: form.email, password: form.password });
      navigate(location.state?.from?.pathname || '/notes', { replace: true });
    } catch (err) {
      setServerError(err.message);
      if (err.errors.length) setErrors(Object.fromEntries(err.errors.map((x) => [x.field, x.message])));
    }
  };

  const field = (name, label, type = 'text', auto) => (
    <>
      <label htmlFor={name}>{label}</label>
      <input id={name} name={name} type={type} autoComplete={auto} value={form[name]} onChange={change} />
      {errors[name] && <p className="error">{errors[name]}</p>}
    </>
  );

  return (
    <div className="container">
      <form className="card" onSubmit={submit} noValidate>
        <h1>{isRegister ? 'Create account' : 'Log in'}</h1>
        {isRegister && field('name', 'Name', 'text', 'name')}
        {field('email', 'Email', 'email', 'email')}
        {field('password', 'Password', 'password', isRegister ? 'new-password' : 'current-password')}
        {isRegister && field('confirm', 'Confirm password', 'password', 'new-password')}
        {serverError && <p className="error" role="alert">{serverError}</p>}
        <p><button>{isRegister ? 'Register' : 'Log in'}</button></p>
      </form>
    </div>
  );
}

// ---------- Protected functionality: personal notes ----------
function Notes() {
  const [notes, setNotes] = useState([]);
  const [form, setForm] = useState({ title: '', content: '' });
  const [editingId, setEditingId] = useState(null);
  const [error, setError] = useState('');

  const load = () => api('/api/notes').then(setNotes).catch((e) => setError(e.message));
  useEffect(() => { load(); }, []);

  const save = async (e) => {
    e.preventDefault();
    setError('');
    if (!form.title.trim()) return setError('Title is required');
    if (form.title.length > 100 || form.content.length > 2000) return setError('Title max 100 and content max 2000 characters');
    try {
      if (editingId) await api('/api/notes/' + editingId, 'PUT', form);
      else await api('/api/notes', 'POST', form);
      setForm({ title: '', content: '' });
      setEditingId(null);
      load();
    } catch (err) { setError(err.message); }
  };

  const remove = async (id) => {
    if (!window.confirm('Delete this note?')) return;
    try { await api('/api/notes/' + id, 'DELETE'); load(); } catch (err) { setError(err.message); }
  };

  return (
    <div className="container">
      <form className="card" onSubmit={save} noValidate>
        <h2>{editingId ? 'Edit note' : 'New note'}</h2>
        <label htmlFor="title">Title</label>
        <input id="title" value={form.title} maxLength={100} onChange={(e) => setForm({ ...form, title: e.target.value })} />
        <label htmlFor="content">Content</label>
        <textarea id="content" rows="3" value={form.content} maxLength={2000} onChange={(e) => setForm({ ...form, content: e.target.value })} />
        {error && <p className="error" role="alert">{error}</p>}
        <p className="row">
          <button>{editingId ? 'Save' : 'Add note'}</button>
          {editingId && <button type="button" className="secondary" onClick={() => { setEditingId(null); setForm({ title: '', content: '' }); }}>Cancel</button>}
        </p>
      </form>
      {notes.map((n) => (
        <div className="card" key={n._id}>
          <h3>{n.title}</h3>
          <p>{n.content}</p>
          <div className="row">
            <button onClick={() => { setEditingId(n._id); setForm({ title: n.title, content: n.content || '' }); }}>Edit</button>
            <button className="danger" onClick={() => remove(n._id)}>Delete</button>
          </div>
        </div>
      ))}
      {notes.length === 0 && <p>No notes yet.</p>}
    </div>
  );
}

// ---------- Admin-only page (authorization by role) ----------
function AdminUsers() {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState('');
  useEffect(() => { api('/api/admin/users').then(setUsers).catch((e) => setError(e.message)); }, []);
  return (
    <div className="container">
      <h2>Registered users</h2>
      {error && <p className="error">{error}</p>}
      {users.map((u) => <div className="card" key={u.id}>{u.name} &lt;{u.email}&gt; — {u.role}</div>)}
    </div>
  );
}

// ---------- Routes ----------
export default function App() {
  return (
    <>
      <Nav />
      <Routes>
        <Route path="/register" element={<AuthForm mode="register" />} />
        <Route path="/login" element={<AuthForm mode="login" />} />
        <Route element={<ProtectedRoute />}>
          <Route path="/notes" element={<Notes />} />
        </Route>
        <Route element={<ProtectedRoute role="admin" />}>
          <Route path="/admin/users" element={<AdminUsers />} />
        </Route>
        <Route path="*" element={<Navigate to="/notes" replace />} />
      </Routes>
    </>
  );
}
