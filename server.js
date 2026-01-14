// server.js
const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const JWT_SECRET = crypto.randomBytes(64).toString('hex'); // In Produktion in .env auslagern!
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// Datenbank Setup
const db = new sqlite3.Database('./storage.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type TEXT,
    parent_folder TEXT DEFAULT '/',
    share_token TEXT UNIQUE,
    is_shared BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE INDEX IF NOT EXISTS idx_share_token ON files(share_token)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_user_files ON files(user_id, parent_folder)`);
});

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Upload-Verzeichnis erstellen
fs.mkdir(UPLOAD_DIR, { recursive: true }).catch(console.error);

// Multer Storage Configuration
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const userDir = path.join(UPLOAD_DIR, req.userId.toString());
    await fs.mkdir(userDir, { recursive: true });
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 * 1024 } // 10GB Limit pro Datei (anpassbar)
});

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Nicht authentifiziert' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token ungültig' });
    req.userId = user.userId;
    next();
  });
};

// === ROUTEN ===

// Registrierung
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password || password.length < 8) {
    return res.status(400).json({ error: 'Username und Passwort (min. 8 Zeichen) erforderlich' });
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
    [username, hashedPassword], 
    function(err) {
      if (err) {
        return res.status(400).json({ error: 'Username bereits vergeben' });
      }
      res.json({ message: 'Registrierung erfolgreich', userId: this.lastID });
    }
  );
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Ungültige Anmeldedaten' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Ungültige Anmeldedaten' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  });
});

// Datei Upload
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Keine Datei hochgeladen' });
  }

  const folder = req.body.folder || '/';

  db.run(`INSERT INTO files (user_id, filename, original_name, file_path, file_size, mime_type, parent_folder)
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [req.userId, req.file.filename, req.file.originalname, req.file.path, req.file.size, req.file.mimetype, folder],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Fehler beim Speichern' });
      }
      res.json({ 
        message: 'Datei hochgeladen',
        fileId: this.lastID,
        filename: req.file.originalname
      });
    }
  );
});

// Dateien auflisten
app.get('/api/files', authenticateToken, (req, res) => {
  const folder = req.query.folder || '/';

  db.all('SELECT id, original_name, file_size, mime_type, parent_folder, is_shared, created_at FROM files WHERE user_id = ? AND parent_folder = ?',
    [req.userId, folder],
    (err, files) => {
      if (err) {
        return res.status(500).json({ error: 'Fehler beim Laden' });
      }
      res.json({ files });
    }
  );
});

// Datei herunterladen
app.get('/api/download/:fileId', authenticateToken, (req, res) => {
  db.get('SELECT * FROM files WHERE id = ? AND user_id = ?', 
    [req.params.fileId, req.userId],
    (err, file) => {
      if (err || !file) {
        return res.status(404).json({ error: 'Datei nicht gefunden' });
      }
      res.download(file.file_path, file.original_name);
    }
  );
});

// Datei löschen
app.delete('/api/files/:fileId', authenticateToken, (req, res) => {
  db.get('SELECT * FROM files WHERE id = ? AND user_id = ?',
    [req.params.fileId, req.userId],
    async (err, file) => {
      if (err || !file) {
        return res.status(404).json({ error: 'Datei nicht gefunden' });
      }

      try {
        await fs.unlink(file.file_path);
      } catch (e) {
        console.error('Fehler beim Löschen der Datei:', e);
      }

      db.run('DELETE FROM files WHERE id = ?', [req.params.fileId], (err) => {
        if (err) {
          return res.status(500).json({ error: 'Fehler beim Löschen' });
        }
        res.json({ message: 'Datei gelöscht' });
      });
    }
  );
});

// Datei teilen
app.post('/api/share/:fileId', authenticateToken, (req, res) => {
  const shareToken = crypto.randomBytes(16).toString('hex');

  db.run('UPDATE files SET share_token = ?, is_shared = 1 WHERE id = ? AND user_id = ?',
    [shareToken, req.params.fileId, req.userId],
    function(err) {
      if (err || this.changes === 0) {
        return res.status(404).json({ error: 'Datei nicht gefunden' });
      }
      res.json({ 
        shareUrl: `/share/${shareToken}`,
        shareToken 
      });
    }
  );
});

// Teilen deaktivieren
app.delete('/api/share/:fileId', authenticateToken, (req, res) => {
  db.run('UPDATE files SET share_token = NULL, is_shared = 0 WHERE id = ? AND user_id = ?',
    [req.params.fileId, req.userId],
    function(err) {
      if (err || this.changes === 0) {
        return res.status(404).json({ error: 'Datei nicht gefunden' });
      }
      res.json({ message: 'Teilen deaktiviert' });
    }
  );
});

// Öffentlicher Share-Link (ohne Auth!)
app.get('/share/:token', (req, res) => {
  db.get('SELECT * FROM files WHERE share_token = ? AND is_shared = 1',
    [req.params.token],
    (err, file) => {
      if (err || !file) {
        return res.status(404).send('Datei nicht gefunden oder nicht geteilt');
      }
      res.download(file.file_path, file.original_name);
    }
  );
});

// Speichernutzung anzeigen
app.get('/api/storage', authenticateToken, (req, res) => {
  db.get('SELECT SUM(file_size) as total FROM files WHERE user_id = ?',
    [req.userId],
    (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Fehler' });
      }
      res.json({ 
        usedBytes: result.total || 0,
        usedGB: ((result.total || 0) / (1024 * 1024 * 1024)).toFixed(2)
      });
    }
  );
});

app.listen(PORT, () => {
  console.log(`🚀 Cloud Storage läuft auf http://localhost:${PORT}`);
  console.log(`⚠️  JWT_SECRET: ${JWT_SECRET} (in Produktion in .env speichern!)`);
});

// ============================================
// public/index.html - Frontend
// ============================================
/*
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cloud Storage</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      padding: 20px;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    
    .auth-box {
      background: white;
      border-radius: 12px;
      padding: 40px;
      max-width: 400px;
      margin: 100px auto;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    }
    .auth-box h2 { margin-bottom: 30px; color: #333; text-align: center; }
    .auth-box input {
      width: 100%;
      padding: 12px;
      margin-bottom: 15px;
      border: 2px solid #ddd;
      border-radius: 8px;
      font-size: 14px;
    }
    .auth-box button {
      width: 100%;
      padding: 12px;
      background: #667eea;
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      cursor: pointer;
      font-weight: 600;
      transition: 0.3s;
    }
    .auth-box button:hover { background: #5568d3; }
    .auth-toggle {
      text-align: center;
      margin-top: 20px;
      color: #666;
      cursor: pointer;
    }
    .auth-toggle:hover { color: #667eea; }
    
    .storage-app {
      background: white;
      border-radius: 12px;
      padding: 30px;
      min-height: 80vh;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    }
    
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 30px;
      padding-bottom: 20px;
      border-bottom: 2px solid #eee;
    }
    .header h1 { color: #333; font-size: 28px; }
    .user-info { display: flex; gap: 15px; align-items: center; }
    .storage-info {
      background: #f8f9fa;
      padding: 8px 16px;
      border-radius: 20px;
      font-size: 14px;
      color: #666;
    }
    .btn-logout {
      padding: 10px 20px;
      background: #e74c3c;
      color: white;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
    }
    
    .upload-area {
      background: #f8f9fa;
      border: 2px dashed #ddd;
      border-radius: 12px;
      padding: 40px;
      text-align: center;
      margin-bottom: 30px;
      cursor: pointer;
      transition: 0.3s;
    }
    .upload-area:hover { border-color: #667eea; background: #f0f2ff; }
    .upload-area.dragover { border-color: #667eea; background: #e6e9ff; }
    
    .files-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 20px;
    }
    
    .file-card {
      background: white;
      border: 2px solid #eee;
      border-radius: 12px;
      padding: 20px;
      transition: 0.3s;
      position: relative;
    }
    .file-card:hover {
      transform: translateY(-5px);
      box-shadow: 0 10px 30px rgba(0,0,0,0.1);
    }
    .file-icon {
      font-size: 48px;
      text-align: center;
      margin-bottom: 10px;
    }
    .file-name {
      font-weight: 600;
      color: #333;
      margin-bottom: 5px;
      word-break: break-word;
      font-size: 14px;
    }
    .file-size {
      color: #999;
      font-size: 12px;
    }
    .file-actions {
      display: flex;
      gap: 5px;
      margin-top: 15px;
    }
    .btn {
      flex: 1;
      padding: 8px;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      font-size: 12px;
      font-weight: 600;
      transition: 0.2s;
    }
    .btn-download { background: #667eea; color: white; }
    .btn-download:hover { background: #5568d3; }
    .btn-share { background: #3498db; color: white; }
    .btn-share:hover { background: #2980b9; }
    .btn-delete { background: #e74c3c; color: white; }
    .btn-delete:hover { background: #c0392b; }
    
    .share-badge {
      position: absolute;
      top: 10px;
      right: 10px;
      background: #2ecc71;
      color: white;
      padding: 4px 8px;
      border-radius: 12px;
      font-size: 10px;
      font-weight: 600;
    }
    
    .modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.5);
      justify-content: center;
      align-items: center;
      z-index: 1000;
    }
    .modal.active { display: flex; }
    .modal-content {
      background: white;
      padding: 30px;
      border-radius: 12px;
      max-width: 500px;
      width: 90%;
    }
    .modal-content h3 { margin-bottom: 20px; color: #333; }
    .share-link {
      background: #f8f9fa;
      padding: 15px;
      border-radius: 8px;
      word-break: break-all;
      margin: 15px 0;
      font-family: monospace;
    }
    .modal-actions {
      display: flex;
      gap: 10px;
      margin-top: 20px;
    }
    .btn-copy {
      flex: 1;
      padding: 12px;
      background: #2ecc71;
      color: white;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
    }
    .btn-close {
      flex: 1;
      padding: 12px;
      background: #95a5a6;
      color: white;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
    }
    
    .hidden { display: none; }
    .error { color: #e74c3c; text-align: center; margin-top: 10px; }
  </style>
</head>
<body>
  <!-- Auth Screen -->
  <div id="authScreen">
    <div class="auth-box">
      <h2 id="authTitle">Login</h2>
      <input type="text" id="username" placeholder="Benutzername" autocomplete="username">
      <input type="password" id="password" placeholder="Passwort (min. 8 Zeichen)" autocomplete="current-password">
      <button id="authBtn">Anmelden</button>
      <div class="error" id="authError"></div>
      <div class="auth-toggle" id="authToggle">Noch kein Konto? Registrieren</div>
    </div>
  </div>

  <!-- Storage App -->
  <div id="storageApp" class="hidden">
    <div class="container">
      <div class="storage-app">
        <div class="header">
          <h1>☁️ Mein Cloud Storage</h1>
          <div class="user-info">
            <div class="storage-info">💾 <span id="storageUsed">0 GB</span> verwendet</div>
            <span id="currentUser"></span>
            <button class="btn-logout" onclick="logout()">Abmelden</button>
          </div>
        </div>

        <div class="upload-area" id="uploadArea">
          <div style="font-size: 48px; margin-bottom: 10px;">📤</div>
          <h3>Datei hochladen</h3>
          <p style="color: #999; margin-top: 10px;">Klicken oder Datei hierher ziehen</p>
          <input type="file" id="fileInput" style="display: none;">
        </div>

        <div class="files-grid" id="filesGrid"></div>
      </div>
    </div>
  </div>

  <!-- Share Modal -->
  <div id="shareModal" class="modal">
    <div class="modal-content">
      <h3>📤 Datei teilen</h3>
      <p>Teile diese Datei mit einem öffentlichen Link:</p>
      <div class="share-link" id="shareLink"></div>
      <div class="modal-actions">
        <button class="btn-copy" onclick="copyShareLink()">Link kopieren</button>
        <button class="btn-close" onclick="closeShareModal()">Schließen</button>
      </div>
    </div>
  </div>

  <script>
    let token = localStorage.getItem('token');
    let isLoginMode = true;
    let currentShareLink = '';

    // Init
    if (token) {
      showApp();
    }

    // Auth Toggle
    document.getElementById('authToggle').addEventListener('click', () => {
      isLoginMode = !isLoginMode;
      document.getElementById('authTitle').textContent = isLoginMode ? 'Login' : 'Registrierung';
      document.getElementById('authBtn').textContent = isLoginMode ? 'Anmelden' : 'Registrieren';
      document.getElementById('authToggle').textContent = isLoginMode 
        ? 'Noch kein Konto? Registrieren' 
        : 'Bereits registriert? Anmelden';
      document.getElementById('authError').textContent = '';
    });

    // Auth Submit
    document.getElementById('authBtn').addEventListener('click', async () => {
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const endpoint = isLoginMode ? '/api/login' : '/api/register';

      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });

        const data = await res.json();

        if (res.ok) {
          if (isLoginMode) {
            token = data.token;
            localStorage.setItem('token', token);
            localStorage.setItem('username', data.username);
            showApp();
          } else {
            document.getElementById('authError').textContent = 'Registrierung erfolgreich! Bitte anmelden.';
            document.getElementById('authError').style.color = '#2ecc71';
            setTimeout(() => {
              isLoginMode = true;
              document.getElementById('authToggle').click();
            }, 1500);
          }
        } else {
          document.getElementById('authError').textContent = data.error;
        }
      } catch (error) {
        document.getElementById('authError').textContent = 'Verbindungsfehler';
      }
    });

    // Upload Area
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');

    uploadArea.addEventListener('click', () => fileInput.click());

    uploadArea.addEventListener('dragover', (e) => {
      e.preventDefault();
      uploadArea.classList.add('dragover');
    });

    uploadArea.addEventListener('dragleave', () => {
      uploadArea.classList.remove('dragover');
    });

    uploadArea.addEventListener('drop', (e) => {
      e.preventDefault();
      uploadArea.classList.remove('dragover');
      const file = e.dataTransfer.files[0];
      if (file) uploadFile(file);
    });

    fileInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) uploadFile(file);
    });

    // Upload Function
    async function uploadFile(file) {
      const formData = new FormData();
      formData.append('file', file);

      try {
        const res = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` },
          body: formData
        });

        if (res.ok) {
          loadFiles();
          loadStorage();
        } else {
          alert('Upload fehlgeschlagen');
        }
      } catch (error) {
        alert('Upload-Fehler');
      }
      fileInput.value = '';
    }

    // Load Files
    async function loadFiles() {
      const res = await fetch('/api/files', {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      const data = await res.json();
      const grid = document.getElementById('filesGrid');
      grid.innerHTML = '';

      data.files.forEach(file => {
        const card = document.createElement('div');
        card.className = 'file-card';
        card.innerHTML = `
          ${file.is_shared ? '<div class="share-badge">Geteilt</div>' : ''}
          <div class="file-icon">${getFileIcon(file.mime_type)}</div>
          <div class="file-name">${file.original_name}</div>
          <div class="file-size">${formatBytes(file.file_size)}</div>
          <div class="file-actions">
            <button class="btn btn-download" onclick="downloadFile(${file.id}, '${file.original_name}')">⬇️</button>
            <button class="btn btn-share" onclick="shareFile(${file.id})" title="${file.is_shared ? 'Teilen beenden' : 'Teilen'}">${file.is_shared ? '🔓' : '📤'}</button>
            <button class="btn btn-delete" onclick="deleteFile(${file.id})">🗑️</button>
          </div>
        `;
        grid.appendChild(card);
      });
    }

    // Load Storage
    async function loadStorage() {
      const res = await fetch('/api/storage', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      document.getElementById('storageUsed').textContent = `${data.usedGB} GB`;
    }

    // Download
    async function downloadFile(fileId, filename) {
      window.location.href = `/api/download/${fileId}`;
    }

    // Share
    async function shareFile(fileId) {
      // Prüfe ob bereits geteilt
      const checkRes = await fetch('/api/files', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const checkData = await checkRes.json();
      const file = checkData.files.find(f => f.id === fileId);

      if (file && file.is_shared) {
        // Wenn bereits geteilt, zeige Option zum Entfernen
        if (confirm('Diese Datei ist bereits geteilt. Möchtest du das Teilen beenden?')) {
          await unshareFile(fileId);
        }
        return;
      }

      const res = await fetch(`/api/share/${fileId}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      const data = await res.json();
      currentShareLink = window.location.origin + data.shareUrl;
      document.getElementById('shareLink').textContent = currentShareLink;
      document.getElementById('shareModal').classList.add('active');
      loadFiles();
    }

    // Unshare
    async function unshareFile(fileId) {
      const res = await fetch(`/api/share/${fileId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (res.ok) {
        alert('Teilen erfolgreich beendet!');
        loadFiles();
      }
    }

    // Delete
    async function deleteFile(fileId) {
      if (!confirm('Datei wirklich löschen?')) return;

      await fetch(`/api/files/${fileId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      loadFiles();
      loadStorage();
    }

    // Copy Share Link
    function copyShareLink() {
      navigator.clipboard.writeText(currentShareLink);
      alert('Link kopiert!');
    }

    // Close Modal
    function closeShareModal() {
      document.getElementById('shareModal').classList.remove('active');
    }

    // Logout
    function logout() {
      localStorage.removeItem('token');
      localStorage.removeItem('username');
      token = null;
      document.getElementById('authScreen').classList.remove('hidden');
      document.getElementById('storageApp').classList.add('hidden');
    }

    // Show App
    function showApp() {
      document.getElementById('authScreen').classList.add('hidden');
      document.getElementById('storageApp').classList.remove('hidden');
      document.getElementById('currentUser').textContent = '👤 ' + localStorage.getItem('username');
      loadFiles();
      loadStorage();
    }

    // Helpers
    function getFileIcon(mimeType) {
      if (!mimeType) return '📄';
      if (mimeType.startsWith('image/')) return '🖼️';
      if (mimeType.startsWith('video/')) return '🎥';
      if (mimeType.startsWith('audio/')) return '🎵';
      if (mimeType.includes('pdf')) return '📕';
      if (mimeType.includes('zip') || mimeType.includes('rar')) return '📦';
      if (mimeType.includes('text')) return '📝';
      return '📄';
    }

    function formatBytes(bytes) {
      if (bytes === 0) return '0 Bytes';
      const k = 1024;
      const sizes = ['Bytes', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    }
  </script>
</body>
</html>
*/

// ============================================
// package.json
// ============================================
/*
{
  "name": "cloud-storage",
  "version": "1.0.0",
  "description": "Sicheres selbst-gehostetes Cloud Storage System",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "multer": "^1.4.5-lts.1",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "sqlite3": "^5.1.7"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
*/

// ============================================
// INSTALLATION & NUTZUNG
// ============================================
/*

📦 INSTALLATION:

1. Erstelle einen neuen Ordner:
   mkdir cloud-storage && cd cloud-storage

2. Erstelle die Dateien:
   - server.js (den obigen Code)
   - package.json (siehe oben)
   - Erstelle Ordner "public" und darin die index.html

3. Installiere Dependencies:
   npm install

4. Starte den Server:
   npm start

5. Öffne Browser:
   http://localhost:3000


🔐 SICHERHEITS-FEATURES:

✅ Passwörter werden mit bcrypt gehasht (12 Runden)
✅ JWT-Token für sichere Authentifizierung
✅ Jeder User hat isolierte Dateien
✅ Share-Links mit kryptografisch sicheren Tokens
✅ SQL-Injection-Schutz durch parametrisierte Queries
✅ Datei-Upload-Limits konfigurierbar
✅ Authentifizierungs-Middleware für geschützte Routen


📂 DATEISTRUKTUR:

cloud-storage/
├── server.js           # Backend-Server
├── package.json        # Dependencies
├── storage.db          # SQLite Datenbank (wird automatisch erstellt)
├── uploads/            # Hochgeladene Dateien (wird automatisch erstellt)
│   └── [userId]/       # Jeder User hat eigenen Ordner
└── public/
    └── index.html      # Frontend


🚀 PRODUKTIONS-TIPPS:

1. JWT_SECRET in Umgebungsvariable:
   - Erstelle .env Datei
   - Nutze dotenv package
   - Niemals JWT_SECRET committen!

2. HTTPS verwenden:
   - Mit Let's Encrypt SSL-Zertifikat
   - Nginx als Reverse Proxy

3. Datenbank:
   - Für große Installationen PostgreSQL statt SQLite
   - Regelmäßige Backups

4. Upload-Limits anpassen:
   - Siehe multer-Konfiguration (aktuell 10GB pro Datei)
   - Server-Memory beachten

5. Rate Limiting hinzufügen:
   - express-rate-limit package
   - Schutz vor Brute-Force-Attacken


🎨 FEATURES:

✅ Benutzer-Registrierung & Login
✅ Unbegrenzter Speicher (nur begrenzt durch Server-Kapazität)
✅ Drag & Drop Upload
✅ Datei-Download
✅ Datei löschen
✅ Datei teilen per Link (optional pro Datei)
✅ Share-Links können deaktiviert werden
✅ Speichernutzung anzeigen
✅ Responsive Design
✅ Persistent (SQLite Datenbank)
✅ Sichere Authentifizierung


📝 API-ENDPUNKTE:

POST   /api/register          - Neuen User registrieren
POST   /api/login             - Anmelden
POST   /api/upload            - Datei hochladen (Auth required)
GET    /api/files             - Dateien auflisten (Auth required)
GET    /api/download/:fileId  - Datei herunterladen (Auth required)
DELETE /api/files/:fileId     - Datei löschen (Auth required)
POST   /api/share/:fileId     - Datei teilen (Auth required)
DELETE /api/share/:fileId     - Teilen deaktivieren (Auth required)
GET    /api/storage           - Speichernutzung (Auth required)
GET    /share/:token          - Öffentliche Datei abrufen (NO AUTH)


🔧 ANPASSUNGEN:

- Port ändern: PORT-Variable in server.js
- Upload-Limit: multer limits in server.js
- Styling: CSS in index.html
- Ordner-Funktionen: Erweitere mit parent_folder-Logik

*/