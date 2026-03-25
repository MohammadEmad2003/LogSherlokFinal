/**
 * LogSherlock - Landing Page JavaScript
 * Handles file upload, session management, navigation, and authentication
 */

// API Base - use server URL, detect if running from file:// protocol
const API_BASE =
    window.location.protocol === "file:"
        ? "http://localhost:8000"
        : window.location.origin;

console.log("API Base:", API_BASE);

// ============================================================================
// Authentication Check
// ============================================================================

async function checkAuth() {
    try {
        const response = await fetch(`${API_BASE}/auth/me`, {
            credentials: 'include'
        });

        if (!response.ok) {
            window.location.href = 'auth.html';
            return false;
        }

        const user = await response.json();
        loadUserInfo(user);
        return true;
    } catch (error) {
        console.error('Auth check failed:', error);
        window.location.href = 'auth.html';
        return false;
    }
}

function loadUserInfo(user) {
    const userNameEl = document.getElementById('user-name');
    const userAvatarEl = document.getElementById('user-avatar');

    if (userNameEl) userNameEl.textContent = user.username || user.email;
    if (userAvatarEl) {
        const initial = (user.username || user.email)[0].toUpperCase();
        userAvatarEl.textContent = initial;
    }
}

// Check auth on page load
checkAuth();

// DOM Elements
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");
const filePreview = document.getElementById("file-preview");
const fileName = document.getElementById("file-name");
const fileSize = document.getElementById("file-size");
const removeFile = document.getElementById("remove-file");
const uploadForm = document.getElementById("upload-form");
const submitBtn = document.getElementById("submit-btn");
const artifactType = document.getElementById("artifact-type");
const description = document.getElementById("description");

// Modals
const sessionsModal = document.getElementById("sessions-modal");
const toolsModal = document.getElementById("tools-modal");
const profileModal = document.getElementById("profile-modal");
const navSessions = document.getElementById("nav-sessions");
const navTools = document.getElementById("nav-tools");
const closeSessionsModal = document.getElementById("close-sessions-modal");
const closeToolsModal = document.getElementById("close-tools-modal");
const closeProfileModal = document.getElementById("close-profile-modal");
const sessionsList = document.getElementById("sessions-list");
const toolsList = document.getElementById("tools-list");

// State
let selectedFile = null;

// ============================================================================
// File Upload Handling
// ============================================================================

// Drag and drop handlers
dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("drag-over");
});

dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("drag-over");
});

dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("drag-over");

    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFileSelect(files[0]);
    }
});

// File input change
fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
        handleFileSelect(e.target.files[0]);
    }
});

// Remove file button
removeFile.addEventListener("click", (e) => {
    e.stopPropagation();
    clearFileSelection();
});

function handleFileSelect(file) {
    selectedFile = file;

    // Update UI
    fileName.textContent = file.name;
    fileSize.textContent = formatFileSize(file.size);

    // Show preview, hide dropzone content
    filePreview.style.display = "block";

    // Enable submit button
    submitBtn.disabled = false;

    // Auto-detect artifact type based on extension
    const ext = file.name.split(".").pop().toLowerCase();
    const typeMap = {
        raw: "memory_dump",
        mem: "memory_dump",
        dmp: "memory_dump",
        vmem: "memory_dump",
        img: "disk_image",
        dd: "disk_image",
        e01: "disk_image",
        evtx: "evtx",
        pcap: "pcap",
        pcapng: "pcap",
        exe: "malware_sample",
        dll: "malware_sample",
    };

    if (typeMap[ext]) {
        artifactType.value = typeMap[ext];
    } else {
        artifactType.value = "auto";
    }
}

function clearFileSelection() {
    selectedFile = null;
    fileInput.value = "";
    filePreview.style.display = "none";
    submitBtn.disabled = true;
    artifactType.value = "auto";
    description.value = "";
}

function formatFileSize(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

// ============================================================================
// Form Submission
// ============================================================================

uploadForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    if (!selectedFile) {
        alert("Please select a file to upload");
        return;
    }

    // Show loading state
    const btnText = submitBtn.querySelector(".btn-text");
    const btnLoader = submitBtn.querySelector(".btn-loader");
    btnText.style.display = "none";
    btnLoader.style.display = "flex";
    submitBtn.disabled = true;

    try {
        const formData = new FormData();
        formData.append("file", selectedFile);
        formData.append("artifact_type", artifactType.value);
        formData.append("description", description.value);

        const response = await fetch(`${API_BASE}/upload_artefact`, {
            method: "POST",
            body: formData,
            credentials: "include"
        });

        if (!response.ok) {
            // Parse FastAPI's error detail from the response body
            let detail = response.statusText;
            try {
                const errBody = await response.json();
                detail = errBody.detail || detail;
            } catch (_) {}

            // Show a friendlier message for known status codes
            if (response.status === 507) {
                showUploadError("Disk Full", detail);
            } else if (response.status === 400) {
                showUploadError("Invalid File", detail);
            } else {
                showUploadError("Upload Failed", detail);
            }
            return;
        }

        const data = await response.json();

        // Redirect to dashboard with session ID
        window.location.href = `dashboard.html?session=${data.session_id}`;
    } catch (error) {
        console.error("Upload error:", error);
        showUploadError("Network Error", "Could not reach the server. Make sure it is running at " + API_BASE);

        // Reset button state
        btnText.style.display = "block";
        btnLoader.style.display = "none";
        submitBtn.disabled = false;
    }
});

function showUploadError(title, message) {
    // Reset button state first
    const btnText = submitBtn.querySelector(".btn-text");
    const btnLoader = submitBtn.querySelector(".btn-loader");
    btnText.style.display = "block";
    btnLoader.style.display = "none";
    submitBtn.disabled = false;

    // Remove any existing error banner
    const existing = document.getElementById("upload-error-banner");
    if (existing) existing.remove();

    const banner = document.createElement("div");
    banner.id = "upload-error-banner";
    banner.className = "upload-error-banner";
    banner.innerHTML = `
        <div class="upload-error-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
        </div>
        <div class="upload-error-text">
            <strong>${title}</strong>
            <span>${message}</span>
        </div>
        <button class="upload-error-close" onclick="this.parentElement.remove()">×</button>`;

    const form = document.getElementById("upload-form");
    form.insertAdjacentElement("beforebegin", banner);

    // Auto-dismiss after 10 seconds
    setTimeout(() => banner.remove(), 10000);
}

// ============================================================================
// Sessions Modal
// ============================================================================

navSessions.addEventListener("click", async (e) => {
    e.preventDefault();
    sessionsModal.classList.add("active");
    await loadSessions();
});

closeSessionsModal.addEventListener("click", () => {
    sessionsModal.classList.remove("active");
});

sessionsModal.addEventListener("click", (e) => {
    if (e.target === sessionsModal) {
        sessionsModal.classList.remove("active");
    }
});

// Chats search filter
const chatsSearchInput = document.getElementById("chats-search-input");
if (chatsSearchInput) {
    chatsSearchInput.addEventListener("input", () => {
        const q = chatsSearchInput.value.toLowerCase();
        document.querySelectorAll(".chat-item").forEach((el) => {
            const text = el.textContent.toLowerCase();
            el.style.display = text.includes(q) ? "" : "none";
        });
    });
}

function getArtifactIcon(type) {
    const icons = {
        memory_dump: "🧠",
        disk_image: "💾",
        evtx: "📋",
        pcap: "🌐",
        malware_sample: "🦠",
        binary: "⚙️",
        archive: "📦",
        unknown: "📁",
    };
    return icons[type] || "📁";
}

function getStatusLabel(status) {
    const map = {
        initialized: "New",
        running: "Active",
        completed: "Done",
        failed: "Failed",
        paused: "Paused",
        initializing: "Starting",
    };
    return map[status] || status;
}

function formatRelativeTime(iso) {
    if (!iso) return "";
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
}

async function loadSessions() {
    sessionsList.innerHTML = '<p class="no-sessions">Loading chats...</p>';

    try {
        const response = await fetch(`${API_BASE}/sessions`, {
            credentials: "include",
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const sessions = await response.json();

        if (!sessions || sessions.length === 0) {
            sessionsList.innerHTML = `
                <div class="no-chats-state">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="48" height="48">
                        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
                    </svg>
                    <p>No chats yet</p>
                    <span>Upload a forensic artifact to start your first investigation chat</span>
                </div>`;
            return;
        }

        // Sort newest first
        const sorted = [...sessions].sort((a, b) =>
            new Date(b.started_at || 0) - new Date(a.started_at || 0)
        );

        sessionsList.innerHTML = sorted
            .map((session) => {
                const icon = getArtifactIcon(session.artifact_type);
                const statusLabel = getStatusLabel(session.status);
                const timeAgo = formatRelativeTime(session.started_at);
                const preview = session.current_phase
                    ? `Phase: ${session.current_phase.replace(/_/g, " ")}`
                    : `${session.artifact_type || "artifact"}`;

                return `
                <div class="chat-item" onclick="openSession('${session.session_id}')">
                    <div class="chat-avatar">${icon}</div>
                    <div class="chat-info">
                        <div class="chat-header-row">
                            <h4 class="chat-name">${session.artifact_name || "Unnamed Artifact"}</h4>
                            <span class="chat-time">${timeAgo}</span>
                        </div>
                        <div class="chat-meta-row">
                            <span class="chat-preview">${preview}</span>
                            <span class="chat-badge ${session.status}">${statusLabel}</span>
                        </div>
                        <div class="chat-stats">
                            <span>${session.steps_count || 0} steps</span>
                            <span>·</span>
                            <span>${session.evidence_count || 0} evidence</span>
                        </div>
                    </div>
                </div>`;
            })
            .join("");
    } catch (error) {
        console.error("Failed to load chats:", error);
        sessionsList.innerHTML = `
            <div class="no-chats-state error-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="48" height="48">
                    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                <p>Could not load chats</p>
                <span>Make sure the server is running at ${API_BASE}</span>
            </div>`;
    }
}

function openSession(sessionId) {
    window.location.href = `dashboard.html?session=${sessionId}`;
}

// ============================================================================
// Profile Modal
// ============================================================================

const profileLink = document.getElementById("profile-link");

if (profileLink) {
    profileLink.addEventListener("click", async (e) => {
        e.preventDefault();
        document.getElementById("user-dropdown").classList.remove("active");
        profileModal.classList.add("active");
        await loadProfile();
    });
}

if (closeProfileModal) {
    closeProfileModal.addEventListener("click", () => {
        profileModal.classList.remove("active");
    });
}

if (profileModal) {
    profileModal.addEventListener("click", (e) => {
        if (e.target === profileModal) {
            profileModal.classList.remove("active");
        }
    });
}

async function loadProfile() {
    const profileContent = document.getElementById("profile-content");
    profileContent.innerHTML = '<div class="profile-loading">Loading profile...</div>';

    try {
        const response = await fetch(`${API_BASE}/auth/me`, {
            credentials: "include",
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const user = await response.json();
        const initial = (user.username || user.email || "U")[0].toUpperCase();
        const joinedDate = user.created_at
            ? new Date(user.created_at).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })
            : "Unknown";
        const lastLogin = user.last_login_at
            ? new Date(user.last_login_at).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })
            : "N/A";

        profileContent.innerHTML = `
            <div class="profile-avatar-section">
                <div class="profile-avatar-large">${initial}</div>
                <div class="profile-name-section">
                    <h3>${user.full_name || user.username}</h3>
                    <span class="profile-role">${user.role || "analyst"}</span>
                </div>
            </div>
            <div class="profile-details">
                <div class="profile-field">
                    <label>Username</label>
                    <span>${user.username}</span>
                </div>
                <div class="profile-field">
                    <label>Email</label>
                    <span>${user.email}</span>
                </div>
                <div class="profile-field">
                    <label>Full Name</label>
                    <span>${user.full_name || "—"}</span>
                </div>
                <div class="profile-field">
                    <label>Role</label>
                    <span class="profile-role-badge">${user.role || "analyst"}</span>
                </div>
                <div class="profile-field">
                    <label>Account Status</label>
                    <span class="profile-status ${user.is_active ? "active" : "inactive"}">${user.is_active ? "Active" : "Inactive"}</span>
                </div>
                <div class="profile-field">
                    <label>Joined</label>
                    <span>${joinedDate}</span>
                </div>
                <div class="profile-field">
                    <label>Last Login</label>
                    <span>${lastLogin}</span>
                </div>
            </div>
            <div class="profile-actions">
                <button class="btn-secondary" id="profile-logout-btn">Sign Out</button>
            </div>`;

        document.getElementById("profile-logout-btn").addEventListener("click", async () => {
            try {
                await fetch(`${API_BASE}/auth/logout`, { method: "POST", credentials: "include" });
            } catch (_) {}
            window.location.href = "auth.html";
        });
    } catch (error) {
        console.error("Failed to load profile:", error);
        profileContent.innerHTML = `
            <div class="no-chats-state error-state">
                <p>Failed to load profile</p>
                <span>Please try again or sign in again</span>
                <button class="btn-secondary" onclick="window.location.href='auth.html'">Go to Login</button>
            </div>`;
    }
}

// ============================================================================
// Tools Modal
// ============================================================================

navTools.addEventListener("click", async (e) => {
    e.preventDefault();
    toolsModal.classList.add("active");
    await loadTools();
});

closeToolsModal.addEventListener("click", () => {
    toolsModal.classList.remove("active");
});

toolsModal.addEventListener("click", (e) => {
    if (e.target === toolsModal) {
        toolsModal.classList.remove("active");
    }
});

async function loadTools() {
    toolsList.innerHTML = "<p>Loading tools...</p>";

    try {
        const response = await fetch(`${API_BASE}/tools`, {
            credentials: "include"
        });
        const data = await response.json();

        toolsList.innerHTML = data.tools
            .map(
                (tool) => `
            <div class="tool-item">
                <h4>${tool.name}</h4>
                <p>${tool.description}</p>
                <span class="category">${tool.category.replace(/_/g, " ")}</span>
            </div>
        `,
            )
            .join("");
    } catch (error) {
        console.error("Failed to load tools:", error);
        toolsList.innerHTML = `<p>Failed to load tools. Make sure the server is running at ${API_BASE}</p>`;
    }
}

// ============================================================================
// Keyboard Navigation
// ============================================================================

document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
        sessionsModal.classList.remove("active");
        toolsModal.classList.remove("active");
        if (profileModal) profileModal.classList.remove("active");
        document.getElementById("user-dropdown").classList.remove("active");
    }
});

// ============================================================================
// User Menu
// ============================================================================

const userBtn = document.getElementById("user-btn");
const userDropdown = document.getElementById("user-dropdown");
const logoutBtn = document.getElementById("logout-btn");

if (userBtn) {
    userBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        userDropdown.classList.toggle("active");
    });
}

// Close dropdown when clicking outside
document.addEventListener("click", (e) => {
    if (!userDropdown.contains(e.target) && e.target !== userBtn) {
        userDropdown.classList.remove("active");
    }
});

if (logoutBtn) {
    logoutBtn.addEventListener("click", async (e) => {
        e.preventDefault();

        try {
            await fetch(`${API_BASE}/auth/logout`, {
                method: "POST",
                credentials: "include"
            });
        } catch (error) {
            console.error("Logout error:", error);
        }

        // Redirect to auth page
        window.location.href = "auth.html";
    });
}

// Make openSession available globally
window.openSession = openSession;
