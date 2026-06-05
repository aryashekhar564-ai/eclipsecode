const API = 'http://localhost:8000';

// ── Navigation ────────────────────────────────────────────────────────────────

function navigate(page) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    document.getElementById('page-' + page).classList.add('active');
    document.querySelector(`[data-page="${page}"]`).classList.add('active');
    window.scrollTo(0, 0);
}

document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', e => {
        e.preventDefault();
        navigate(link.dataset.page);
    });
});

// ── Hero cipher stream animation ──────────────────────────────────────────────

function randomHex(len) {
    return Array.from({length: len}, () => Math.floor(Math.random() * 16).toString(16)).join('');
}

function animateCipherStream() {
    const el = document.getElementById('cipherStream');
    if (!el) return;
    el.textContent = Array.from({length: 18}, () => randomHex(32)).join('\n');
    setInterval(() => {
        el.textContent = Array.from({length: 18}, () => randomHex(32)).join('\n');
    }, 800);
}
animateCipherStream();

// ── File Drop Zones ───────────────────────────────────────────────────────────

function setupFileDrop(dropId, inputId, infoId) {
    const drop  = document.getElementById(dropId);
    const input = document.getElementById(inputId);
    const info  = document.getElementById(infoId);
    if (!drop || !input || !info) return;

    drop.addEventListener('click', () => input.click());

    drop.addEventListener('dragover', e => {
        e.preventDefault();
        drop.classList.add('dragover');
    });
    drop.addEventListener('dragleave', () => drop.classList.remove('dragover'));
    drop.addEventListener('drop', e => {
        e.preventDefault();
        drop.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file) {
            const dt = new DataTransfer();
            dt.items.add(file);
            input.files = dt.files;
            showFileInfo(file, info);
        }
    });
    input.addEventListener('change', () => {
        if (input.files[0]) showFileInfo(input.files[0], info);
    });
}

function showFileInfo(file, infoEl) {
    infoEl.textContent = `${file.name}  (${(file.size / 1024).toFixed(1)} KB)`;
    infoEl.classList.add('visible');
}

setupFileDrop('encryptDrop', 'encryptFile', 'encryptFileInfo');
setupFileDrop('decryptDrop', 'decryptFile', 'decryptFileInfo');

// ── Encrypt cipher/mode constraints ──────────────────────────────────────────
// AES + XOR → password or keyfile only
// RSA       → keypair only
// Keypair mode is RSA-only on the server, so we never let AES/XOR pick it

document.getElementById('encryptCipher').addEventListener('change', function () {
    const modeSelect = document.getElementById('encryptMode');
    if (this.value === 'rsa') {
        modeSelect.innerHTML = `<option value="keypair">RSA Keypair (.pub)</option>`;
    } else {
        modeSelect.innerHTML = `
            <option value="password">Password</option>
            <option value="keyfile">Key File (.eckey)</option>
        `;
    }
    updateEncryptMode();
});

function updateEncryptMode() {
    const mode = document.getElementById('encryptMode').value;
    document.getElementById('encryptPasswordGroup').classList.toggle('hidden', mode !== 'password');
    document.getElementById('encryptKeyfileGroup').classList.toggle('hidden', mode !== 'keyfile');
    document.getElementById('encryptPubkeyGroup').classList.toggle('hidden', mode !== 'keypair');
}

// ── Encrypt ───────────────────────────────────────────────────────────────────

async function doEncrypt() {
    const fileInput = document.getElementById('encryptFile');
    const result    = document.getElementById('encryptResult');

    if (!fileInput.files[0]) {
        return showResult(result, 'Please select a file first.', 'error');
    }

    const file     = fileInput.files[0];
    const mode     = document.getElementById('encryptMode').value;
    const cipherId = document.getElementById('encryptCipher').value;

    // Client-side validation before hitting the server
    if (mode === 'password') {
        const pw = document.getElementById('encryptPassword').value;
        if (!pw) return showResult(result, 'Please enter a password.', 'error');
        if (pw.length < 4) return showResult(result, 'Password must be at least 4 characters.', 'error');
    }
    if (mode === 'keyfile' && !document.getElementById('encryptKeyfile').files[0]) {
        return showResult(result, 'Please select a .eckey file.', 'error');
    }
    if (mode === 'keypair' && !document.getElementById('encryptPubkey').files[0]) {
        return showResult(result, 'Please select a .pub key file.', 'error');
    }

    const fd = new FormData();
    fd.append('file',      file);
    fd.append('cipher_id', cipherId);
    fd.append('mode',      mode);

    if (mode === 'password') {
        fd.append('password', document.getElementById('encryptPassword').value);
    } else if (mode === 'keyfile') {
        fd.append('keyfile', document.getElementById('encryptKeyfile').files[0]);
    } else if (mode === 'keypair') {
        fd.append('pubkey', document.getElementById('encryptPubkey').files[0]);
    }

    showResult(result, 'Encrypting...', 'success');

    try {
        const res = await fetch(`${API}/api/encrypt`, { method: 'POST', body: fd });
        if (!res.ok) {
            const err = await res.json().catch(() => ({ detail: 'Unknown server error.' }));
            return showResult(result, `Error: ${err.detail}`, 'error');
        }
        const blob  = await res.blob();
        const fname = file.name + '.ec';
        downloadBlob(blob, fname);
        showResult(result,
            `✓ Encrypted successfully → ${fname}\n` +
            `✓ Cipher: ${cipherId.toUpperCase()} | Mode: ${mode}\n` +
            `✓ SHA-256 integrity hash stored in file header.`,
            'success'
        );
    } catch (e) {
        showResult(result, `Connection error: ${e.message}\nIs the server running?`, 'error');
    }
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

async function doDecrypt() {
    const fileInput = document.getElementById('decryptFile');
    const result    = document.getElementById('decryptResult');

    if (!fileInput.files[0]) {
        return showResult(result, 'Please select a .ec file.', 'error');
    }

    const file = fileInput.files[0];

    // Validate file extension
    if (!file.name.endsWith('.ec')) {
        return showResult(result, 'File does not appear to be a .ec file. Are you sure this was encrypted with EclipseCode?', 'error');
    }

    const fd = new FormData();
    fd.append('file', file);

    // Send all possible credentials — server picks the right one from the header
    const pw   = document.getElementById('decryptPassword').value;
    const kf   = document.getElementById('decryptKeyfile').files[0];
    const priv = document.getElementById('decryptPrivkey').files[0];

    if (pw)   fd.append('password', pw);
    if (kf)   fd.append('keyfile',  kf);
    if (priv) fd.append('privkey',  priv);

    showResult(result, 'Decrypting...', 'success');

    try {
        const res = await fetch(`${API}/api/decrypt`, { method: 'POST', body: fd });
        if (!res.ok) {
            const err = await res.json().catch(() => ({ detail: 'Unknown server error.' }));
            return showResult(result, `Error: ${err.detail}`, 'error');
        }
        const blob        = await res.blob();
        const disposition = res.headers.get('content-disposition') || '';
        const fname       = disposition.match(/filename=(.+)/)?.[1]?.replace(/"/g, '') || 'decrypted_file';
        downloadBlob(blob, fname);
        showResult(result,
            `✓ Decrypted successfully → ${fname}\n` +
            `✓ SHA-256 integrity verified — file is authentic.`,
            'success'
        );
    } catch (e) {
        showResult(result, `Connection error: ${e.message}\nIs the server running?`, 'error');
    }
}

// Show all decrypt credential inputs — server determines which is needed
// from the .ec file header, user fills whichever applies
document.getElementById('decryptFile').addEventListener('change', function () {
    if (this.files[0]) {
        document.getElementById('decryptPasswordGroup').classList.remove('hidden');
        document.getElementById('decryptKeyfileGroup').classList.remove('hidden');
        document.getElementById('decryptPrivkeyGroup').classList.remove('hidden');
    }
});

// ── Visualizer ────────────────────────────────────────────────────────────────

let selectedCipher = 'caesar';

async function initVisualizer() {
    try {
        const res  = await fetch(`${API}/api/ciphers`);
        if (!res.ok) throw new Error('Could not load ciphers from server.');
        const data = await res.json();
        const pills = document.getElementById('cipherPills');
        pills.innerHTML = '';

        Object.values(data).flat().forEach(c => {
            const pill = document.createElement('button');
            pill.className = 'cipher-pill' + (c.id === 'caesar' ? ' active' : '');
            pill.textContent = c.id.toUpperCase();
            pill.title = c.description;
            pill.onclick = () => {
                document.querySelectorAll('.cipher-pill').forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                selectedCipher = c.id;
                updateVizParams(c.id);
                // Clear previous results when switching cipher
                document.getElementById('vizSteps').innerHTML = '';
                document.getElementById('vizEncrypted').textContent = '—';
            };
            pills.appendChild(pill);
        });

        updateVizParams('caesar');
    } catch (e) {
        document.getElementById('cipherPills').innerHTML =
            `<div style="color:var(--accent3)">Could not load ciphers: ${e.message}</div>`;
    }
}

function updateVizParams(cipherId) {
    const container = document.getElementById('vizParams');
    const configs = {
        caesar:       `<div class="form-group"><label>SHIFT (1-25)</label><input type="number" id="paramShift" class="input" value="3" min="1" max="25"></div>`,
        vigenere:     `<div class="form-group"><label>KEYWORD (alphabetic)</label><input type="text" id="paramKey" class="input" value="ECLIPSE" placeholder="e.g. ECLIPSE"></div>`,
        substitution: `<div class="form-group"><label>26-CHAR SUBSTITUTION KEY</label><input type="text" id="paramKey" class="input" value="QWERTYUIOPASDFGHJKLZXCVBNM" maxlength="26" placeholder="26 unique letters"></div>`,
        xor:          `<div class="form-group"><label>KEY STRING</label><input type="text" id="paramKey" class="input" value="eclipsecode" placeholder="any string"></div>`,
        aes:          `<div class="form-group"><p style="color:var(--accent);font-size:0.8rem">A random 256-bit key is generated automatically for each trace.</p></div>`,
        rsa:          `<div class="form-group"><p style="color:var(--accent);font-size:0.8rem">A fresh RSA-2048 keypair is generated automatically for each trace. This may take a moment.</p></div>`,
    };
    container.innerHTML = configs[cipherId] || '';
}

async function doTrace() {
    const text = document.getElementById('vizText').value.trim();
    if (!text) return;

    if (text.length > 200) {
        return showStepsError('Input too long for visualizer. Please use 200 characters or fewer.');
    }

    const stepsEl = document.getElementById('vizSteps');
    const encEl   = document.getElementById('vizEncrypted');

    stepsEl.innerHTML = `<div style="color:var(--text-dim);font-size:0.8rem;padding:1rem">
        ${selectedCipher === 'rsa' ? 'Generating RSA keypair and encrypting...' : 'Computing...'}
    </div>`;
    encEl.textContent = '—';

    const fd = new FormData();
    fd.append('cipher_id', selectedCipher);
    fd.append('text',      text);
    fd.append('shift',     document.getElementById('paramShift')?.value || 3);
    fd.append('key',       document.getElementById('paramKey')?.value   || 'KEY');

    try {
        const res  = await fetch(`${API}/api/trace`, { method: 'POST', body: fd });
        const data = await res.json();

        if (!res.ok) {
            return showStepsError(data.detail || 'Trace failed.');
        }

        encEl.textContent = data.encrypted || '(binary output)';
        stepsEl.innerHTML = '';

        if (!data.steps || data.steps.length === 0) {
            stepsEl.innerHTML = `<div style="color:var(--text-dim);font-size:0.8rem;padding:1rem">
                No step trace available for this cipher.
            </div>`;
            return;
        }

        data.steps.forEach((step, i) => {
            const card = document.createElement('div');
            card.className = 'step-card';
            card.style.animationDelay = `${i * 40}ms`;
            card.innerHTML = `
                <div class="step-num">STEP ${step.step}</div>
                <div class="step-label">${escapeHtml(step.label)}</div>
                <div class="step-io">
                    <span class="step-in">${escapeHtml(String(step.input))}</span>
                    <span class="step-arrow">→</span>
                    <span class="step-out">${escapeHtml(String(step.output))}</span>
                </div>
                <div class="step-detail">${escapeHtml(step.detail)}</div>
            `;
            stepsEl.appendChild(card);
        });

    } catch (e) {
        showStepsError(`Connection error: ${e.message}`);
    }
}

function showStepsError(msg) {
    document.getElementById('vizSteps').innerHTML =
        `<div style="color:var(--accent3);font-size:0.82rem;padding:1rem">${msg}</div>`;
}

// ── Compare ───────────────────────────────────────────────────────────────────

async function doCompare() {
    const text = document.getElementById('compareText').value.trim();
    if (!text) return;

    if (text.length > 500) {
        return;
    }

    const grid = document.getElementById('compareGrid');
    grid.innerHTML = `<div style="padding:2rem;color:var(--text-dim);grid-column:1/-1">
        Encrypting with all classical ciphers...
    </div>`;

    const fd = new FormData();
    fd.append('text', text);

    try {
        const res  = await fetch(`${API}/api/compare`, { method: 'POST', body: fd });
        if (!res.ok) {
            const err = await res.json().catch(() => ({ detail: 'Unknown error.' }));
            grid.innerHTML = `<div style="color:var(--accent3);padding:2rem;grid-column:1/-1">Error: ${err.detail}</div>`;
            return;
        }
        const data = await res.json();
        grid.innerHTML = '';

        data.results.forEach((r, i) => {
            const card = document.createElement('div');
            card.className = 'compare-card';
            card.style.animationDelay = `${i * 80}ms`;
            if (r.error) {
                card.innerHTML = `
                    <div class="compare-name">${r.cipher.toUpperCase()}</div>
                    <div style="color:var(--accent3);font-size:0.8rem">${r.error}</div>
                `;
            } else {
                card.innerHTML = `
                    <div class="compare-name">${escapeHtml(r.name)}</div>
                    <div class="compare-output">${escapeHtml(r.output)}</div>
                    <div class="compare-meta">
                        <div class="compare-stat">TIME <span>${r.time_ms} ms</span></div>
                        <div class="compare-stat">LENGTH <span>${r.length} chars</span></div>
                    </div>
                `;
            }
            grid.appendChild(card);
        });
    } catch (e) {
        grid.innerHTML = `<div style="color:var(--accent3);padding:2rem;grid-column:1/-1">
            Connection error: ${e.message}
        </div>`;
    }
}

// ── Keygen ────────────────────────────────────────────────────────────────────

async function doKeygen(type) {
    const nameInput = document.getElementById(type === 'aes' ? 'keygenAesName' : 'keygenRsaName');
    const result    = document.getElementById(type === 'aes' ? 'keygenAesResult' : 'keygenRsaResult');
    const name      = nameInput.value.trim();

    if (!name) return showResult(result, 'Please enter an output filename.', 'error');

    // Prevent path traversal
    if (name.includes('/') || name.includes('\\') || name.includes('..')) {
        return showResult(result, 'Invalid filename. Do not use slashes or ..', 'error');
    }

    showResult(result,
        type === 'rsa' ? 'Generating RSA-2048 keypair... (this may take a moment)' : 'Generating AES key...',
        'success'
    );

    try {
        const fd = new FormData();
        fd.append('cipher', type);
        fd.append('out',    name);

        const res  = await fetch(`${API}/api/keygen`, { method: 'POST', body: fd });
        const data = await res.json();

        if (!res.ok) {
            return showResult(result, `Error: ${data.detail}`, 'error');
        }
        showResult(result, data.message, 'success');
    } catch (e) {
        showResult(result, `Connection error: ${e.message}`, 'error');
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function showResult(el, message, type) {
    el.textContent = message;
    el.className   = `result-box visible ${type}`;
}

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a   = document.createElement('a');
    a.href     = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ── Init ──────────────────────────────────────────────────────────────────────

// Set correct cipher/mode state on page load
document.getElementById('encryptCipher').dispatchEvent(new Event('change'));

// Load ciphers into visualizer
initVisualizer();