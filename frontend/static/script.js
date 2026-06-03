const API_BASE = "https://your-app-name.up.railway.app";
const getAuthHeader = () => {
    const token = localStorage.getItem('token');
    return token ? { 'Authorization': `Bearer ${token}` } : {};
};

let cachedFiles = [];

const formatRelativeTime = (dateString) => {
    if (!dateString) return "No uploads yet";
    const now = Date.now();
    const target = new Date(dateString).getTime();
    const diffMs = now - target;
    if (Number.isNaN(target) || diffMs < 0) return "Just now";

    const diffMinutes = Math.floor(diffMs / 60000);
    if (diffMinutes < 1) return "Just now";
    if (diffMinutes < 60) return `${diffMinutes}m ago`;

    const diffHours = Math.floor(diffMinutes / 60);
    if (diffHours < 24) return `${diffHours}h ago`;

    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
};

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
}[char]));

const getFileExtension = (filename) => {
    const parts = String(filename).split('.');
    return parts.length > 1 ? parts.pop().toUpperCase() : 'FILE';
};

const showToast = (message, type = "success") => {
    const stack = document.getElementById('toast-stack');
    if (!stack) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type === 'error' ? 'error-toast' : 'success-toast'}`;
    toast.innerText = message;
    stack.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 2600);
};

async function handleLogin(e) {
    e.preventDefault();
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;

    const response = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass })
    });

    const data = await response.json();
    if (response.ok) {
        localStorage.setItem('token', data.access_token);
        localStorage.setItem('username', data.username);
        localStorage.setItem('role', data.role);
        window.location.href = 'dashboard.html';
    } else {
        const errorDiv = document.getElementById('error-msg');
        errorDiv.innerText = data.msg || "Invalid credentials";
        errorDiv.style.display = 'block';
    }
}

async function handleRegister(e) {
    e.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    const errorDiv = document.getElementById('error-msg');
    if (errorDiv) {
        errorDiv.style.display = 'none';
        errorDiv.innerText = '';
    }

    if (password !== confirmPassword) {
        if (errorDiv) {
            errorDiv.innerText = 'Passwords do not match.';
            errorDiv.style.display = 'block';
        }
        return;
    }

    const response = await fetch('/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });

    const data = await response.json();
    if (response.ok) {
        window.location.href = 'login.html?registered=1';
    } else {
        if (errorDiv) {
            errorDiv.innerText = data.msg || 'Registration failed';
            errorDiv.style.display = 'block';
        }
    }
}

function uploadFile() {
    const fileInput = document.getElementById('fileInput');
    const status = document.getElementById('upload-status');
    const progBar = document.getElementById('progress-bar');
    const progressContainer = document.querySelector('.progress-container');
    const selectedFileLabel = document.getElementById('selected-file-label');

    if (!fileInput.files[0]) {
        showToast("Select a file first.", "error");
        return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    const xhr = new XMLHttpRequest();
    xhr.open("POST", '/files/upload', true);
    xhr.setRequestHeader("Authorization", `Bearer ${localStorage.getItem('token')}`);

    progressContainer.style.display = 'block';

    xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
            progBar.style.width = `${(e.loaded / e.total) * 100}%`;
        }
    };

    xhr.onload = () => {
        status.style.display = 'block';
        const res = JSON.parse(xhr.responseText);
        if (xhr.status === 200) {
            status.className = "alert success";
            status.innerText = "File encrypted and stored successfully.";
            showToast("Upload completed successfully.");
            fileInput.value = "";
            progBar.style.width = "0%";
            progressContainer.style.display = 'none';
            if (selectedFileLabel) {
                selectedFileLabel.innerText = "Nothing selected yet. Choose a file to begin the protected upload flow.";
            }
        } else {
            status.className = "alert error";
            status.innerText = res.msg || "Upload failed.";
            showToast(res.msg || "Upload failed.", "error");
        }
    };

    xhr.send(formData);
}

function renderFilesTable(files) {
    const tableBody = document.getElementById('file-table');
    if (!tableBody) return;

    if (!files.length) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="4">
                    <div class="empty-state">
                        <strong>No encrypted files yet</strong>
                        <p>Upload your first file to populate the secure vault.</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tableBody.innerHTML = files.map((file) => `
        <tr>
            <td>
                <div class="file-main">
                    <span class="file-type">${escapeHtml(getFileExtension(file.filename))}</span>
                    <div>
                        <strong>${escapeHtml(file.filename)}</strong>
                        <span class="muted">Protected item ready for secure retrieval</span>
                    </div>
                </div>
            </td>
            <td>${new Date(file.date).toLocaleString()}</td>
            <td><span class="badge">User ${escapeHtml(file.owner)}</span></td>
            <td><button onclick='downloadFile(${JSON.stringify(encodeURIComponent(file.filename))})'>Download</button></td>
        </tr>
    `).join('');
}

async function loadFiles() {
    const tableBody = document.getElementById('file-table');
    if (!tableBody) return;

    try {
        const res = await fetch('/files/list', {
            headers: getAuthHeader()
        });

        if (res.status === 401) return logout();

        cachedFiles = await res.json();
        const countBadge = document.getElementById('vault-count');
        if (countBadge) countBadge.innerText = cachedFiles.length;
        renderFilesTable(cachedFiles);
    } catch (err) {
        console.error("Error loading files:", err);
        showToast("Unable to load vault data.", "error");
    }
}

function filterFiles() {
    const searchInput = document.getElementById('file-search');
    if (!searchInput) return;

    const query = searchInput.value.trim().toLowerCase();
    const filteredFiles = cachedFiles.filter((file) =>
        String(file.filename).toLowerCase().includes(query)
    );

    const countBadge = document.getElementById('vault-count');
    if (countBadge) countBadge.innerText = filteredFiles.length;

    renderFilesTable(filteredFiles);
}

async function loadDashboard() {
    const totalFilesEl = document.getElementById('quick-files-count');
    if (!totalFilesEl) return;

    try {
        const res = await fetch('/files/list', {
            headers: getAuthHeader()
        });

        if (res.status === 401) return logout();

        const files = await res.json();
        const sortedFiles = [...files].sort((a, b) => new Date(b.date) - new Date(a.date));
        const last24Hours = Date.now() - (24 * 60 * 60 * 1000);
        const recentUploads = sortedFiles.filter((file) => new Date(file.date).getTime() >= last24Hours);
        const latestFile = sortedFiles[0];
        const role = localStorage.getItem('role') || 'user';

        totalFilesEl.innerText = sortedFiles.length;
        document.getElementById('recent-upload-count').innerText = recentUploads.length;
        document.getElementById('latest-activity').innerText = latestFile ? formatRelativeTime(latestFile.date) : "No uploads yet";
        document.getElementById('dashboard-total-files').innerText = sortedFiles.length;
        document.getElementById('dashboard-recent-files').innerText = recentUploads.length;
        document.getElementById('dashboard-last-upload').innerText = latestFile ? latestFile.filename : "None";
        document.getElementById('security-status').innerText = sortedFiles.length ? "Vault synced with latest encrypted records" : "Ready for the first secure upload";

        const heroRoleBadge = document.getElementById('hero-role-badge');
        if (heroRoleBadge) {
            heroRoleBadge.innerText = `${role.toUpperCase()} SESSION`;
            heroRoleBadge.classList.toggle('admin', role === 'admin');
        }

        const dashboardLogLink = document.getElementById('dashboard-log-link');
        if (dashboardLogLink && role === 'admin') {
            dashboardLogLink.style.display = 'inline-flex';
        }

        const fileList = document.getElementById('dashboard-file-list');
        if (fileList) {
            if (!sortedFiles.length) {
                fileList.innerHTML = `
                    <div class="empty-state">
                        <strong>Your vault is empty</strong>
                        <p>Upload a file to see live stats and recent activity update here.</p>
                    </div>
                `;
            } else {
                fileList.innerHTML = sortedFiles.slice(0, 4).map((file) => `
                    <div class="list-item">
                        <div class="file-main">
                            <span class="file-type">${escapeHtml(getFileExtension(file.filename))}</span>
                            <div>
                                <strong>${escapeHtml(file.filename)}</strong>
                                <span class="muted">Uploaded ${new Date(file.date).toLocaleString()}</span>
                            </div>
                        </div>
                        <span class="badge">${formatRelativeTime(file.date)}</span>
                    </div>
                `).join('');
            }
        }

        const dashboardTimeline = document.getElementById('dashboard-timeline');
        if (dashboardTimeline) {
            const timelineEntries = [
                {
                    title: role === 'admin' ? 'Administrator session active' : 'User session active',
                    detail: `Signed in as ${role} and ready for secure file operations.`
                },
                latestFile ? {
                    title: `Latest vault update: ${latestFile.filename}`,
                    detail: `Most recent upload recorded ${formatRelativeTime(latestFile.date)}.`
                } : {
                    title: 'Vault awaiting first upload',
                    detail: 'Add a protected file to begin activity tracking.'
                },
                {
                    title: `${recentUploads.length} upload(s) in the last 24 hours`,
                    detail: sortedFiles.length
                        ? 'Recent encrypted activity is reflected in your dashboard metrics.'
                        : 'No recent activity yet. Upload a file to start populating the vault.'
                }
            ];

            dashboardTimeline.innerHTML = timelineEntries.map((entry) => `
                <div class="timeline-item">
                    <span class="timeline-dot"></span>
                    <div class="timeline-card">
                        <strong>${escapeHtml(entry.title)}</strong>
                        <span class="muted">${escapeHtml(entry.detail)}</span>
                    </div>
                </div>
            `).join('');
        }
    } catch (err) {
        console.error("Error loading dashboard stats:", err);
        showToast("Unable to load dashboard stats.", "error");
    }
}

async function downloadFile(encodedFilename) {
    try {
        const response = await fetch(`/files/download/${encodedFilename}`, {
            headers: getAuthHeader()
        });

        if (response.status === 401) return logout();

        if (!response.ok) {
            const error = await response.json().catch(() => ({ msg: "Download failed." }));
            showToast(error.msg || "Download failed.", "error");
            return;
        }

        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        const decodedFilename = decodeURIComponent(encodedFilename);

        link.href = downloadUrl;
        link.download = decodedFilename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(downloadUrl);
        showToast(`Downloaded ${decodedFilename}.`);
    } catch (err) {
        console.error("Error downloading file:", err);
        showToast("Unable to download file right now.", "error");
    }
}

async function loadLogs() {
    const tableBody = document.getElementById('logs-table');
    if (!tableBody) return;

    try {
        const res = await fetch('/logs/all', {
            headers: getAuthHeader()
        });

        if (res.status === 403) {
            tableBody.innerHTML = "<tr><td colspan='4'>Access Denied: Admin Only</td></tr>";
            return;
        }

        const logs = await res.json();
        tableBody.innerHTML = logs.map((log) => `
            <tr>
                <td>${escapeHtml(log.user_id)}</td>
                <td>${escapeHtml(log.action)}</td>
                <td>${new Date(log.timestamp).toLocaleString()}</td>
                <td><span class="badge">${escapeHtml(log.status)}</span></td>
            </tr>
        `).join('');
    } catch (err) {
        console.error("Error loading logs:", err);
        showToast("Unable to load admin logs.", "error");
    }
}

function simulateAttack(type) {
    const consoleBox = document.getElementById('console');
    const logLine = (msg) => {
        const div = document.createElement('div');
        div.innerText = `> [${new Date().toLocaleTimeString()}] ${msg}`;
        consoleBox.appendChild(div);
        consoleBox.scrollTop = consoleBox.scrollHeight;
    };

    logLine(`Starting ${type} simulation...`);

    fetch('/attacks/simulate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            ...getAuthHeader()
        },
        body: JSON.stringify({ attack_type: type })
    })
    .then((res) => res.json())
    .then((data) => {
        setTimeout(() => logLine(`Result: ${data.result}`), 1000);
        setTimeout(() => logLine("System Status: Logged and blocked."), 1800);
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    const params = new URLSearchParams(window.location.search);
    const errorDiv = document.getElementById('error-msg');

    if (params.get('registered') === '1' && errorDiv) {
        errorDiv.className = 'alert success';
        errorDiv.innerText = 'Account created successfully. Please sign in.';
        errorDiv.style.display = 'block';
    }

    const isAuthPage = window.location.pathname.includes('login.html') || window.location.pathname.includes('register.html');

    if (!token && !isAuthPage) {
        window.location.href = 'login.html';
    }

    if (window.location.pathname.includes('files.html')) loadFiles();
    if (window.location.pathname.includes('dashboard.html')) loadDashboard();
    if (window.location.pathname.includes('logs.html')) loadLogs();

    const userDisplay = document.getElementById('user-welcome');
    if (userDisplay) {
        userDisplay.innerText = `Welcome back, ${localStorage.getItem('username')}`;
    }

    const logNav = document.getElementById('nav-logs');
    if (logNav && localStorage.getItem('role') !== 'admin') {
        logNav.style.display = 'none';
    }

    const fileInput = document.getElementById('fileInput');
    const selectedFileLabel = document.getElementById('selected-file-label');
    if (fileInput && selectedFileLabel) {
        fileInput.addEventListener('change', () => {
            const file = fileInput.files[0];
            selectedFileLabel.innerText = file
                ? `Selected file: ${file.name}`
                : "Nothing selected yet. Choose a file to begin the protected upload flow.";
        });
    }

    const dropzone = document.getElementById('upload-dropzone');
    if (dropzone && fileInput) {
        ['dragenter', 'dragover'].forEach((eventName) => {
            dropzone.addEventListener(eventName, (event) => {
                event.preventDefault();
                dropzone.classList.add('drag-over');
            });
        });

        ['dragleave', 'drop'].forEach((eventName) => {
            dropzone.addEventListener(eventName, (event) => {
                event.preventDefault();
                dropzone.classList.remove('drag-over');
            });
        });

        dropzone.addEventListener('drop', (event) => {
            const droppedFiles = event.dataTransfer.files;
            if (!droppedFiles.length) return;
            fileInput.files = droppedFiles;
            if (selectedFileLabel) {
                selectedFileLabel.innerText = `Selected file: ${droppedFiles[0].name}`;
            }
        });
    }
});

function logout() {
    localStorage.clear();
    window.location.href = 'login.html';
}
