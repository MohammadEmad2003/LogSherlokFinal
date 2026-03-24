/**
 * Autonomous Forensic Orchestrator - Landing Page JavaScript
 * Handles file upload, session management, and navigation
 */

// API Base - use server URL, detect if running from file:// protocol
const API_BASE = window.location.protocol === 'file:'
    ? 'http://localhost:8000'
    : window.location.origin;

console.log('API Base:', API_BASE);

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
const navSessions = document.getElementById("nav-sessions");
const navTools = document.getElementById("nav-tools");
const closeSessionsModal = document.getElementById("close-sessions-modal");
const closeToolsModal = document.getElementById("close-tools-modal");
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
        });

        if (!response.ok) {
            throw new Error(`Upload failed: ${response.statusText}`);
        }

        const data = await response.json();

        // Redirect to dashboard with session ID
        window.location.href = `dashboard.html?session=${data.session_id}`;
    } catch (error) {
        console.error("Upload error:", error);
        alert(`Upload failed: ${error.message}`);

        // Reset button state
        btnText.style.display = "block";
        btnLoader.style.display = "none";
        submitBtn.disabled = false;
    }
});

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

async function loadSessions() {
    sessionsList.innerHTML = '<p class="no-sessions">Loading sessions...</p>';

    try {
        const response = await fetch(`${API_BASE}/sessions`);
        const sessions = await response.json();

        if (sessions.length === 0) {
            sessionsList.innerHTML =
                '<p class="no-sessions">No active sessions</p>';
            return;
        }

        sessionsList.innerHTML = sessions
            .map(
                (session) => `
            <div class="session-item" onclick="openSession('${session.session_id}')">
                <div class="session-item-info">
                    <h4>${session.artifact_name}</h4>
                    <p>${session.artifact_type} - ${session.steps_count} steps, ${session.evidence_count} evidence</p>
                </div>
                <span class="session-item-status ${session.status}">${session.status}</span>
            </div>
        `,
            )
            .join("");
    } catch (error) {
        console.error("Failed to load sessions:", error);
        sessionsList.innerHTML =
            `<p class="no-sessions">Failed to load sessions. Make sure the server is running at ${API_BASE}</p>`;
    }
}

function openSession(sessionId) {
    window.location.href = `dashboard.html?session=${sessionId}`;
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
        const response = await fetch(`${API_BASE}/tools`);
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
    }
});

// Make openSession available globally
window.openSession = openSession;
