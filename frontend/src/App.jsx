// frontend/src/App.jsx

import { useState, useRef, useEffect } from "react";

const FASTAPI_URL = "/chat";

// =========================================================
// SESSION ID — one per browser tab (sessionStorage), sent as
// X-Session-Id so the backend isolates this tab's context
// =========================================================

const SESSION_ID = (() => {
  let id = sessionStorage.getItem("devops_sentinel_sid");
  if (!id) {
    // crypto.randomUUID exists only in secure contexts (HTTPS or
    // localhost). Over plain HTTP — e.g. a bare LoadBalancer IP —
    // it is undefined and an unguarded call blanks the whole app.
    id = window.crypto?.randomUUID
      ? crypto.randomUUID()
      : `sid-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
    sessionStorage.setItem("devops_sentinel_sid", id);
  }
  return id;
})();

// Optional API key — set VITE_SENTINEL_API_KEY when the backend
// runs with SENTINEL_API_KEY; omitted entirely in open local dev.
const API_KEY = import.meta.env.VITE_SENTINEL_API_KEY;

const API_HEADERS = {
  "Content-Type": "application/json",
  "X-Session-Id": SESSION_ID,
  ...(API_KEY ? { "X-API-Key": API_KEY } : {}),
};

// =========================================================
// ASYNC INGEST POLLING
// A pasted GitHub URL returns a job_id; the repo download +
// scan runs server-side. Poll until it finishes and return
// the final result payload (response, findings, scanners).
// =========================================================

const PHASE_LABEL = {
  starting: "starting…",
  downloading: "downloading the repository…",
  scanning: "running scanners…",
  done: "done",
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function pollScanJob(jobId, onPhase) {
  // ~5 min ceiling at 2s intervals
  for (let i = 0; i < 150; i++) {
    await sleep(2000);
    const r = await fetch(`/scan-status/${jobId}`, { headers: API_HEADERS });
    if (!r.ok) throw new Error(`Scan status unavailable (${r.status})`);
    const s = await r.json();
    if (onPhase) onPhase(s.phase);
    if (s.status === "done") return s.result;
    if (s.status === "error") throw new Error(s.error || "Ingestion failed.");
  }
  throw new Error("Ingestion timed out.");
}

// =========================================================
// FAVICON + TAB TITLE
// =========================================================

function useFavicon() {
  useEffect(() => {
    document.title = "AI DevSecOps Sentinel";
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
      <defs>
        <linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" style="stop-color:#238636"/>
          <stop offset="100%" style="stop-color:#1f6feb"/>
        </linearGradient>
      </defs>
      <rect width="32" height="32" rx="7" fill="url(#g)"/>
      <text x="16" y="22" font-size="18" text-anchor="middle" font-family="system-ui" fill="white">⚙</text>
    </svg>`;
    const blob = new Blob([svg], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);
    let link = document.querySelector("link[rel~='icon']");
    if (!link) { link = document.createElement("link"); link.rel = "icon"; document.head.appendChild(link); }
    link.href = url;
    return () => URL.revokeObjectURL(url);
  }, []);
}

// =========================================================
// ICONS
// =========================================================

const SendIcon = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
  </svg>
);
const AttachIcon = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>
  </svg>
);
const CopyIcon = () => (
  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
  </svg>
);
const FileIcon = () => (
  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
  </svg>
);
const ZipIcon = () => (
  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
  </svg>
);
const ChevronIcon = ({ open }) => (
  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
    style={{ transform: open ? "rotate(90deg)" : "rotate(0deg)", transition: "transform 0.2s", flexShrink: 0 }}>
    <polyline points="9 18 15 12 9 6"/>
  </svg>
);
const BotIcon = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/>
    <path d="M12 7v4"/><line x1="8" y1="16" x2="8" y2="16" strokeWidth="3"/><line x1="16" y1="16" x2="16" y2="16" strokeWidth="3"/>
  </svg>
);
const UserIcon = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
  </svg>
);
const SpinnerIcon = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
    style={{ animation: "spin 1s linear infinite" }}>
    <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
  </svg>
);
const ShieldIcon = () => (
  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
);
const WrenchIcon = () => (
  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
  </svg>
);
const CheckIcon = () => (
  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
    <polyline points="20 6 9 17 4 12"/>
  </svg>
);
const ClearIcon = () => (
  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/>
  </svg>
);
const AlertIcon = () => (
  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
    <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
  </svg>
);
const InfoIcon = () => (
  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>
  </svg>
);
const LinkIcon = () => (
  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
  </svg>
);
const DashboardIcon = () => (
  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
    <rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>
  </svg>
);
const BrainIcon = () => (
  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M9.5 2a2.5 2.5 0 0 1 5 0v1a2.5 2.5 0 0 1-5 0V2z"/>
    <path d="M12 3C8 3 5 6 5 10c0 3 1.5 5.5 4 7v2h6v-2c2.5-1.5 4-4 4-7 0-4-3-7-7-7z"/>
  </svg>
);
const ZapIcon = () => (
  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
  </svg>
);
const EvidenceIcon = () => (
  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
    <polyline points="14 2 14 8 20 8"/>
    <line x1="16" y1="13" x2="8" y2="13"/>
    <line x1="16" y1="17" x2="8" y2="17"/>
    <polyline points="10 9 9 9 8 9"/>
  </svg>
);
const BlastIcon = () => (
  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="10"/>
    <line x1="12" y1="8" x2="12" y2="12"/>
    <line x1="12" y1="16" x2="12.01" y2="16"/>
  </svg>
);

// =========================================================
// SEVERITY + CATEGORY CONFIG
// =========================================================

const SEVERITY = {
  CRITICAL: { color: "#ff4444", bg: "rgba(255,68,68,0.1)",    border: "rgba(255,68,68,0.25)",   label: "CRITICAL" },
  HIGH:     { color: "#ff8800", bg: "rgba(255,136,0,0.1)",    border: "rgba(255,136,0,0.25)",   label: "HIGH"     },
  MEDIUM:   { color: "#d29922", bg: "rgba(210,153,34,0.1)",   border: "rgba(210,153,34,0.25)",  label: "MEDIUM"   },
  LOW:      { color: "#58a6ff", bg: "rgba(88,166,255,0.08)",  border: "rgba(88,166,255,0.2)",   label: "LOW"      },
  INFO:     { color: "#8b949e", bg: "rgba(139,148,158,0.08)", border: "rgba(139,148,158,0.2)",  label: "INFO"     },
};

const CATEGORY_COLORS = {
  SECRETS: "#ff4444", MISCONFIGURATION: "#ff8800",
  "VULNERABLE-DEPENDENCY": "#d29922", "CI-CD": "#a371f7",
  KUBERNETES: "#58a6ff", DOCKER: "#1f6feb", TERRAFORM: "#7b68ee",
  COMPLIANCE: "#e8912d", NETWORK: "#3fb950",
};

// =========================================================
// BADGES
// =========================================================

function SeverityBadge({ level }) {
  const cfg = SEVERITY[level?.toUpperCase()] || SEVERITY.INFO;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: "3px",
      background: cfg.bg, border: `1px solid ${cfg.border}`,
      borderRadius: "4px", padding: "2px 7px",
      fontSize: "10px", fontWeight: "700", color: cfg.color,
      letterSpacing: "0.5px", fontFamily: "monospace", flexShrink: 0
    }}>{cfg.label}</span>
  );
}

function CategoryBadge({ category }) {
  if (!category) return null;
  const color = CATEGORY_COLORS[category?.toUpperCase()] || "#8b949e";
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      border: `1px solid ${color}44`, borderRadius: "4px", padding: "2px 7px",
      fontSize: "10px", color, fontWeight: "600", background: `${color}11`, flexShrink: 0
    }}>{category}</span>
  );
}

function ConfidenceBadge({ level, reason }) {
  const map = { HIGH: "#2ea043", MEDIUM: "#d29922", LOW: "#8b949e" };
  const color = map[level?.toUpperCase()] || "#8b949e";
  const [hover, setHover] = useState(false);
  return (
    <div style={{ position: "relative", display: "inline-flex" }}>
      <span
        onMouseEnter={() => setHover(true)}
        onMouseLeave={() => setHover(false)}
        style={{
          display: "inline-flex", alignItems: "center", gap: "3px",
          background: `${color}11`, borderRadius: "4px", padding: "2px 6px",
          fontSize: "10px", color, fontWeight: "600", flexShrink: 0,
          cursor: reason ? "help" : "default"
        }}>
        <BrainIcon /> {level} confidence
      </span>
      {hover && reason && (
        <div style={{
          position: "absolute", top: "100%", left: 0, zIndex: 100,
          background: "#1c2128", border: "1px solid #30363d",
          borderRadius: "6px", padding: "8px 10px", marginTop: "4px",
          width: "220px", fontSize: "11px", color: "#c9d1d9", lineHeight: "1.6",
          boxShadow: "0 8px 24px rgba(0,0,0,0.5)"
        }}>
          <div style={{ color, fontWeight: "700", marginBottom: "4px", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
            Confidence Reason
          </div>
          {reason}
        </div>
      )}
    </div>
  );
}

function LocationPill({ location }) {
  if (!location) return null;
  return (
    <code style={{
      background: "#0d1117", border: "1px solid #388bfd44",
      borderRadius: "4px", padding: "2px 7px",
      fontSize: "11px", color: "#79c0ff", fontFamily: "monospace", flexShrink: 0
    }}>{location}</code>
  );
}

function FixAvailableBadge() {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: "3px",
      background: "rgba(46,160,67,0.12)", border: "1px solid rgba(46,160,67,0.3)",
      borderRadius: "4px", padding: "2px 7px",
      fontSize: "10px", color: "#2ea043", fontWeight: "700", flexShrink: 0
    }}>
      <WrenchIcon /> FIX AVAILABLE
    </span>
  );
}

// =========================================================
// HIGH PRIORITY 3 — HASH-BASED FILE DEDUPLICATION
// Computes a fast hash from file name + size + last modified.
// Prevents the same file being re-ingested across sessions.
// =========================================================

function fileHash(file) {
  // Fast fingerprint — name + size + lastModified
  // Not cryptographic, just collision-resistant enough for dedup
  const str = `${file.name}::${file.size}::${file.lastModified}`;
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // 32-bit int
  }
  return Math.abs(hash).toString(36);
}

// Persisted set of hashes for files already sent this session
const _sentFileHashes = new Set(
  JSON.parse(sessionStorage.getItem("devops_sentinel_hashes") || "[]")
);

function markFileAsSent(file) {
  _sentFileHashes.add(fileHash(file));
  try {
    sessionStorage.setItem(
      "devops_sentinel_hashes",
      JSON.stringify([..._sentFileHashes])
    );
  } catch {
    // sessionStorage quota exceeded — silently ignore
  }
}

function isFileAlreadySent(file) {
  return _sentFileHashes.has(fileHash(file));
}

function unmarkFileAsSent(file) {
  _sentFileHashes.delete(fileHash(file));
  try {
    sessionStorage.setItem(
      "devops_sentinel_hashes",
      JSON.stringify([..._sentFileHashes])
    );
  } catch {
    // sessionStorage quota exceeded — silently ignore
  }
}

// =========================================================
// FILE ENCODER
// Encodes only files that have not yet been sent to backend
// =========================================================

async function encodeFiles(files) {
  const encoded = [];
  for (const file of files) {
    try {
      // file.sent is set after first successful upload
      // Skip already-sent files to prevent duplicate ingestion
      if (file.sent) continue;

      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      let binary = "";
      for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
      encoded.push({ name: file.name, content: btoa(binary) });
    } catch (e) { console.error("Encode error:", file.name, e); }
  }
  return encoded;
}
// =========================================================
// HIGH PRIORITY 2 — SESSION PERSISTENCE
// Saves last scan result to sessionStorage so context
// survives a page refresh within the same browser tab.
// Uses sessionStorage (not localStorage) so data is
// automatically cleared when the tab closes.
// =========================================================

function useSessionPersistence(messages, uploadedFiles, history, repoCtx) {
  // Save on every change
  useEffect(() => {
    try {
      const toSave = {
        messages: messages.filter(m => !m.isLoading),
        history,
        repoCtx,
        // Save file metadata only (not content — too large)
        fileNames: uploadedFiles.map(f => ({ name: f.name, sent: true })),
        savedAt: Date.now(),
      };
      sessionStorage.setItem("devops_sentinel_session", JSON.stringify(toSave));
    } catch {
      // sessionStorage quota exceeded — silently ignore
    }
  }, [messages, uploadedFiles, history, repoCtx]);
}

// =========================================================
// HIGH PRIORITY 1 — EXPORT / DOWNLOAD REPORT
// Generates a markdown security report from the last
// structured scan result and triggers a file download.
// Works entirely client-side — no backend needed.
// =========================================================

function generateMarkdownReport(blocks, repoCtx, uploadedFiles, scannerFindings, repo, scannersRun, filesScanned) {
  const now = new Date().toISOString().split("T")[0];
  const isRepo = !!(repo || (repoCtx?.repoName || "").includes("/"));
  const projectName = repo?.name || repoCtx?.repoName || uploadedFiles[0]?.name || "Project";
  const findings = scannerFindings || [];
  const lines = [];

  // Real scanned-file count: the backend's ground-truth count first,
  // then repo file count, then unique files in findings, then uploads —
  // never the parsed-block count (which showed "1" for a repo).
  const filesFromFindings = new Set(findings.map(f => f.file).filter(Boolean)).size;
  const fileCount = filesScanned ?? repo?.files ?? (filesFromFindings || uploadedFiles?.length || 0);

  // Ground-truth severity counts from the verified scanner findings.
  const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const sevCount = Object.fromEntries(SEV.map(s => [s, 0]));
  const byTool = {};
  for (const f of findings) {
    const s = (f.severity || "INFO").toUpperCase();
    sevCount[s] = (sevCount[s] || 0) + 1;
    (byTool[f.tool] = byTool[f.tool] || []).push(f);
  }
  const total = findings.length;
  // Classify each analyst-note finding: if its file:line matches a scanner
  // finding (±1 line) it's already scanner-verified; otherwise it's an
  // AI-identified issue the deterministic tools didn't flag (logic/context
  // flaws, weak hardcoded secrets). This is robust even when scanners emit
  // many lint findings the AI consolidates — unlike a raw count subtraction.
  const _base = p => String(p || "").split(/[\\/]/).pop();
  const scannerKeys = new Set(findings.map(f => `${_base(f.file)}:${f.line || 0}`));
  let aiDetected = 0;
  for (const blk of (blocks || [])) {
    if (blk.type !== "file_analysis") continue;
    for (const f of (blk.findings || [])) {
      const m = (f.location || "").match(/([^\s`/:]+):(\d+)/);
      const key = m ? `${_base(m[1])}:${parseInt(m[2], 10)}` : null;
      if (!key || !scannerKeys.has(key)) aiDetected++;
    }
  }
  const grandTotal = total + aiDetected;
  const riskLevel = sevCount.CRITICAL > 0 ? "CRITICAL"
    : sevCount.HIGH > 0 ? "HIGH"
    : sevCount.MEDIUM > 0 ? "MEDIUM"
    : total > 0 ? "LOW" : "MINIMAL";

  lines.push(`# AI DevSecOps Sentinel — Security Report`);
  lines.push(``);
  lines.push(`| | |`);
  lines.push(`|---|---|`);
  lines.push(`| **${isRepo ? "Repository" : "Project"}** | ${projectName} |`);
  lines.push(`| **Generated** | ${now} |`);
  lines.push(`| **${isRepo ? "Files indexed & scanned" : "Files scanned"}** | ${fileCount} |`);
  lines.push(`| **Scanners run** | ${(scannersRun || Object.keys(byTool)).join(", ") || "—"} |`);
  lines.push(`| **Scanner-verified findings** | ${total} |`);
  if (aiDetected > 0) {
    lines.push(`| **AI-identified findings** | ${aiDetected} |`);
    lines.push(`| **Total distinct findings** | ${grandTotal} |`);
  }
  lines.push(`| **Overall risk** | ${riskLevel} |`);
  lines.push(``);

  // Executive summary — the part stakeholders actually read.
  lines.push(`## Executive Summary`);
  const aiClause = aiDetected > 0
    ? ` The analyst notes add **${aiDetected} AI-identified** issue${aiDetected === 1 ? "" : "s"} the deterministic scanners don't flag (e.g. logic/context flaws and weak hardcoded secrets), for **${grandTotal} distinct findings** in total.`
    : "";
  if (total === 0 && aiDetected === 0) {
    lines.push(`No findings were produced for ${projectName}. This does not guarantee the absence of risk — see the analyst notes below.`);
  } else if (total === 0) {
    lines.push(`The deterministic scanners produced **no verified findings** for **${projectName}** (${fileCount} file${fileCount === 1 ? "" : "s"}), but the analyst notes identify **${aiDetected} AI-identified** issue${aiDetected === 1 ? "" : "s"} (logic/context flaws and weak hardcoded secrets the tools don't flag). Overall risk is assessed as **${riskLevel}**.`);
  } else {
    const headline = [];
    if (sevCount.CRITICAL) headline.push(`**${sevCount.CRITICAL} critical**`);
    if (sevCount.HIGH) headline.push(`**${sevCount.HIGH} high**`);
    if (sevCount.MEDIUM) headline.push(`${sevCount.MEDIUM} medium`);
    if (sevCount.LOW) headline.push(`${sevCount.LOW} low`);
    lines.push(`Analysis of **${projectName}** (${fileCount} file${fileCount === 1 ? "" : "s"}) produced **${total} scanner-verified finding${total === 1 ? "" : "s"}** (tool-confirmed ground truth) — ${headline.join(", ")}.${aiClause} Overall risk is assessed as **${riskLevel}**.`);
  }
  lines.push(``);

  // Top 5 Actions — the prioritised, prescriptive to-do the reader acts on.
  // Distinct rules first (worst severity, then how widely they fire), each
  // as one action, capped at 4, always closed with a re-scan step so the
  // remediation loop is explicit.
  if (total > 0) {
    lines.push(`## Top 5 Actions`);
    const ruleMap = {};
    for (const f of findings) {
      const key = f.rule_id || f.title;
      if (!ruleMap[key]) ruleMap[key] = { ...f, count: 0, files: new Set() };
      ruleMap[key].count++;
      if (f.file) ruleMap[key].files.add(f.file);
    }
    const ranked = Object.values(ruleMap).sort((a, b) =>
      (sevRank[(a.severity || "INFO").toUpperCase()] - sevRank[(b.severity || "INFO").toUpperCase()]) || (b.count - a.count));
    let n = 1;
    for (const r of ranked.slice(0, 4)) {
      const scope = r.files.size > 1
        ? ` — ${r.files.size} files`
        : (r.file ? ` — \`${r.file}${r.line ? ":" + r.line : ""}\`` : "");
      lines.push(`${n}. **[${(r.severity || "INFO").toUpperCase()}]** ${r.title}${scope}`);
      n++;
    }
    lines.push(`${n}. Re-scan after applying fixes to verify remediation.`);
    lines.push(``);
  }

  // Risk summary table
  lines.push(`## Risk Summary`);
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  lines.push(`| 🔴 Critical | ${sevCount.CRITICAL} |`);
  lines.push(`| 🟠 High | ${sevCount.HIGH} |`);
  lines.push(`| 🟡 Medium | ${sevCount.MEDIUM} |`);
  lines.push(`| 🔵 Low | ${sevCount.LOW} |`);
  lines.push(`| **Total** | **${total}** |`);
  lines.push(``);

  // Full verified findings, grouped by tool then collapsed by rule so a
  // rule that fires on 18 files reads as one prioritised row (with its
  // locations) instead of 18 near-identical rows — a Staff-level report.
  const esc = (s) => String(s || "").replace(/\|/g, "\\|");
  if (total > 0) {
    lines.push(`## Verified Scanner Findings`);
    lines.push(`Deterministic tool output — every finding is reproducible, not AI-inferred. Repeated rules are collapsed with their locations.`);
    lines.push(``);
    for (const tool of Object.keys(byTool).sort()) {
      const fs = byTool[tool];
      // group by rule_id
      const byRule = {};
      for (const f of fs) (byRule[f.rule_id || f.title] = byRule[f.rule_id || f.title] || []).push(f);
      const rules = Object.values(byRule).sort((a, b) =>
        (sevRank[(a[0].severity || "INFO").toUpperCase()] - sevRank[(b[0].severity || "INFO").toUpperCase()]) || (b.length - a.length));
      lines.push(`### ${tool} — ${fs.length} finding${fs.length === 1 ? "" : "s"} across ${rules.length} rule${rules.length === 1 ? "" : "s"}`);
      lines.push(`| Severity | Rule | Count | Finding | Locations |`);
      lines.push(`|----------|------|-------|---------|-----------|`);
      for (const grp of rules) {
        const f = grp[0];
        const locs = grp.map(x => `\`${x.file}:${x.line}\``);
        const locStr = locs.slice(0, 4).join(", ") + (locs.length > 4 ? ` +${locs.length - 4} more` : "");
        const ev = f.evidence ? ` (e.g. \`${esc(f.evidence)}\`)` : "";
        lines.push(`| ${(f.severity || "INFO").toUpperCase()} | ${esc(f.rule_id)} | ${grp.length} | ${esc(f.title)}${ev} | ${locStr} |`);
      }
      lines.push(``);
    }
  }

  const fileBlocks = (blocks || []).filter(b => b.type === "file_analysis");
  if (fileBlocks.length) {
    lines.push(`## Analyst Notes — Detailed Analysis`);
    lines.push(``);
  }

  for (const block of fileBlocks) {
    lines.push(`## File: \`${block.filename}\``);
    if (block.purpose) lines.push(`**Purpose:** ${block.purpose}`);
    lines.push(``);

    if (block.positive) {
      lines.push(`### ✅ Positive Findings`);
      lines.push(block.positive);
      lines.push(``);
    }

    if (block.findings?.length > 0) {
      lines.push(`### 🔍 Security Findings (${block.findings.length})`);
      for (const f of block.findings) {
        const sev = f.level?.toUpperCase() || "INFO";
        const icon = { CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🔵" }[sev] || "ℹ️";
        lines.push(``);
        lines.push(`#### ${icon} [${sev}] ${f.title || "Finding"}`);
        if (f.location)    lines.push(`**Location:** \`${f.location}\``);
        if (f.category)    lines.push(`**Category:** ${f.category}`);
        if (f.confidence)  lines.push(`**Confidence:** ${f.confidence}`);
        if (f.risk)        lines.push(`**Risk:** ${f.risk}`);
        if (f.whyMatters)  lines.push(`**Why it matters:** ${f.whyMatters}`);
        if (f.evidence)    lines.push(`**Evidence:** ${f.evidence}`);
        if (f.blastRadius) lines.push(`**Blast Radius:** ${f.blastRadius}`);
        if (f.diffBad && f.diffFix) {
          lines.push(`**Fix:**`);
          lines.push(`\`\`\``);
          lines.push(`# BAD`);
          lines.push(f.diffBad);
          lines.push(`# FIX`);
          lines.push(f.diffFix);
          lines.push(`\`\`\``);
        }
      }
      lines.push(``);
    }

    if (block.recommendations) {
      lines.push(`### 📋 Recommendations`);
      lines.push(block.recommendations);
      lines.push(``);
    }

    lines.push(`---`);
    lines.push(``);
  }

  lines.push(`*Report generated by AI DevSecOps Sentinel*`);
  return lines.join("\n");
}

function downloadReport(blocks, repoCtx, uploadedFiles, scannerFindings, repo, scannersRun, filesScanned) {
  const md = generateMarkdownReport(blocks, repoCtx, uploadedFiles, scannerFindings, repo, scannersRun, filesScanned);
  const blob = new Blob([md], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const repoName = (repoCtx?.repoName || "report").replace(/[^a-z0-9]/gi, "-").toLowerCase();
  const date = new Date().toISOString().split("T")[0];
  a.href = url;
  a.download = `devops-sentinel-${repoName}-${date}.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function loadSessionData() {
  try {
    const raw = sessionStorage.getItem("devops_sentinel_session");
    if (!raw) return null;
    const data = JSON.parse(raw);
    // Only restore if saved within last 2 hours
    if (Date.now() - data.savedAt > 2 * 60 * 60 * 1000) {
      sessionStorage.removeItem("devops_sentinel_session");
      return null;
    }
    return data;
  } catch {
    return null;
  }
}

// =========================================================
// STACK-AWARE QUICK ACTIONS
// =========================================================

function getStackAwareQuickActions(uploadedFiles) {
  const names = uploadedFiles.map(f => f.name.toLowerCase()).join(" ");

  const hasTerraform  = names.includes(".tf");
  const hasDocker     = names.includes("dockerfile") || names.includes("docker-compose");
  const hasKubernetes = names.includes("deploy") || names.includes("service.yaml") ||
                        names.includes("ingress") || names.includes("k8s");
  const hasNode       = names.includes("package.json");
  const hasJava       = names.includes("pom.xml") || names.includes("build.gradle");
  const hasPython     = names.includes("requirements") || names.includes(".py");
  const hasGo         = names.includes("go.mod") || names.includes(".go");
  const hasCicd       = names.includes(".github") || names.includes("jenkinsfile") ||
                        names.includes("gitlab-ci") || names.includes("circleci") ||
                        names.includes(".yml") || names.includes(".yaml");
  const hasHelm       = names.includes("chart.yaml") || names.includes("values.yaml") ||
                        names.includes("helm");
  const hasZip        = names.includes(".zip");
  const hasEnv        = names.includes(".env") || names.includes("secrets");

  const actions = [
    { label: "🔒 Security Review",   msg: "Run a full security review on all uploaded files" },
    { label: "🔑 Check Secrets",     msg: "Scan all files for hardcoded secrets, tokens, and credentials" },
  ];

  if (hasDocker || hasZip)
    actions.push({ label: "🐳 Docker Audit",      msg: "Audit all Dockerfiles for security and best practice issues" });
  if (hasKubernetes || hasZip)
    actions.push({ label: "☸️ K8s Hardening",     msg: "Check all Kubernetes manifests for security context issues and misconfigurations" });
  if (hasTerraform || hasZip)
    actions.push({ label: "🏗️ Terraform Scan",    msg: "Scan Terraform files for misconfigurations, open CIDRs, and wildcard IAM" });
  if (hasHelm || hasZip)
    actions.push({ label: "⚓ Helm Audit",         msg: "Audit Helm chart values and templates for security issues" });
  if (hasCicd || hasZip)
    actions.push({ label: "🔁 CI/CD Analysis",    msg: "Analyse CI/CD pipelines for hardcoded secrets and insecure patterns" });
  if (hasNode || hasZip)
    actions.push({ label: "📦 Node.js Deps",      msg: "Check Node.js dependencies in package.json for known vulnerabilities and outdated versions" });
  if (hasJava || hasZip)
    actions.push({ label: "☕ Java Deps",          msg: "Audit Java dependencies in pom.xml or build.gradle for known vulnerabilities" });
  if (hasPython || hasZip)
    actions.push({ label: "🐍 Python Deps",       msg: "Check Python dependencies for known vulnerabilities and outdated packages" });
  if (hasGo || hasZip)
    actions.push({ label: "🦫 Go Deps",           msg: "Audit Go module dependencies for known vulnerabilities" });
  if (hasEnv || hasZip)
    actions.push({ label: "🔐 Env Secrets Scan",  msg: "Scan all .env and secrets files for plaintext credentials" });

  actions.push({ label: "🛠️ Generate All Fixes", msg: "Generate corrected versions of all files with issues found" });
  actions.push({ label: "📋 Full Report",         msg: "Generate a complete security report with all findings, evidence, compliance mapping, and remediation steps" });

  return actions;
}

// =========================================================
// MARKDOWN PARSER
// =========================================================

function renderTokens(text) {
  if (!text) return [];
  const lines = text.split("\n");
  const result = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.trim().startsWith("```")) {
      const lang = line.trim().slice(3).trim();
      const code = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith("```")) { code.push(lines[i]); i++; }
      result.push({ type: "code", lang, content: code.join("\n") });
      i++; continue;
    }
    if (line.startsWith("#### ")) { result.push({ type: "h4", content: line.slice(5) }); i++; continue; }
    if (line.startsWith("### ")) { result.push({ type: "h3", content: line.slice(4) }); i++; continue; }
    if (line.startsWith("## "))  { result.push({ type: "h2", content: line.slice(3) }); i++; continue; }
    if (line.startsWith("# "))   { result.push({ type: "h1", content: line.slice(2) }); i++; continue; }
    if (line.trim() === "---")   { result.push({ type: "hr" }); i++; continue; }
    if (line.match(/^[-*+] /)) {
      const items = [];
      while (i < lines.length && lines[i].match(/^[-*+] /)) { items.push(lines[i].slice(2)); i++; }
      result.push({ type: "ul", items }); continue;
    }
    if (line.match(/^\d+\. /)) {
      const items = [];
      while (i < lines.length && lines[i].match(/^\d+\. /)) { items.push(lines[i].replace(/^\d+\. /, "")); i++; }
      result.push({ type: "ol", items }); continue;
    }
    if (line.trim() === "") { result.push({ type: "br" }); i++; continue; }
    result.push({ type: "p", content: line }); i++;
  }
  return result;
}

function InlineText({ text }) {
  if (!text) return null;
  // Underscore emphasis (_italic_) is matched only at word boundaries so
  // snake_case identifiers (auto_create_subnetworks, var.project_id) are
  // never mangled — important for a DevOps tool, and makes the renderer
  // robust to models that emit _italic_ instead of *italic*.
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*|(?<![\w])_(?!\s)[^_]+?(?<!\s)_(?![\w]))/g);
  return (
    <>
      {parts.map((part, i) => {
        if (!part) return null;
        if (part.startsWith("`") && part.endsWith("`"))
          return <code key={i} style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "3px", padding: "1px 5px", fontFamily: "monospace", fontSize: "12px", color: "#79c0ff" }}>{part.slice(1, -1)}</code>;
        if (part.startsWith("**") && part.endsWith("**"))
          return <strong key={i} style={{ color: "#e6edf3" }}>{part.slice(2, -2)}</strong>;
        if (part.length > 2 && ((part.startsWith("*") && part.endsWith("*")) || (part.startsWith("_") && part.endsWith("_"))))
          return <em key={i} style={{ color: "#c9d1d9" }}>{part.slice(1, -1)}</em>;
        return <span key={i}>{part}</span>;
      })}
    </>
  );
}

function CodeBlock({ lang, content }) {
  const [copied, setCopied] = useState(false);
  return (
    <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "8px", margin: "7px 0", overflow: "hidden" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "5px 12px", background: "#161b22", borderBottom: "1px solid #30363d" }}>
        <span style={{ fontSize: "11px", color: "#8b949e", fontFamily: "monospace" }}>{lang || "code"}</span>
        <button onClick={() => { navigator.clipboard.writeText(content); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
          style={{ background: "transparent", border: "none", cursor: "pointer", color: copied ? "#2ea043" : "#8b949e", display: "flex", alignItems: "center", gap: "4px", fontSize: "11px", padding: "2px 6px", borderRadius: "4px" }}>
          <CopyIcon /> {copied ? "Copied!" : "Copy"}
        </button>
      </div>
      <pre style={{ margin: 0, padding: "12px 14px", overflowX: "auto", fontSize: "12.5px", lineHeight: "1.6", color: "#e6edf3", fontFamily: "'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace" }}>
        <code>{content}</code>
      </pre>
    </div>
  );
}

function MarkdownBlock({ text }) {
  const tokens = renderTokens(text);
  return (
    <div style={{ lineHeight: "1.7", fontSize: "13.5px" }}>
      {tokens.map((t, i) => {
        switch (t.type) {
          case "h1": return <h1 key={i} style={{ fontSize: "17px", fontWeight: "700", color: "#e6edf3", margin: "12px 0 5px", borderBottom: "1px solid #30363d", paddingBottom: "4px" }}><InlineText text={t.content} /></h1>;
          case "h2": return <h2 key={i} style={{ fontSize: "15px", fontWeight: "600", color: "#e6edf3", margin: "10px 0 4px" }}><InlineText text={t.content} /></h2>;
          case "h3": return <h3 key={i} style={{ fontSize: "13px", fontWeight: "600", color: "#79c0ff", margin: "8px 0 3px" }}><InlineText text={t.content} /></h3>;
          case "h4": return <h4 key={i} style={{ fontSize: "12.5px", fontWeight: "600", color: "#8b949e", margin: "7px 0 3px", textTransform: "uppercase", letterSpacing: "0.4px" }}><InlineText text={t.content} /></h4>;
          case "code": return <CodeBlock key={i} lang={t.lang} content={t.content} />;
          case "hr": return <hr key={i} style={{ border: "none", borderTop: "1px solid #30363d", margin: "9px 0" }} />;
          case "ul": return <ul key={i} style={{ margin: "4px 0", paddingLeft: "16px" }}>{t.items.map((item, j) => <li key={j} style={{ color: "#c9d1d9", marginBottom: "3px" }}><InlineText text={item} /></li>)}</ul>;
          case "ol": return <ol key={i} style={{ margin: "4px 0", paddingLeft: "16px" }}>{t.items.map((item, j) => <li key={j} style={{ color: "#c9d1d9", marginBottom: "3px" }}><InlineText text={item} /></li>)}</ol>;
          case "br": return <div key={i} style={{ height: "4px" }} />;
          case "p":  return <p key={i} style={{ margin: "3px 0", color: "#c9d1d9" }}><InlineText text={t.content} /></p>;
          default: return null;
        }
      })}
    </div>
  );
}

// =========================================================
// DIFF CODE BLOCK
// =========================================================

function DiffBlock({ bad, fix }) {
  const [copied, setCopied] = useState(false);
  return (
    <div style={{ border: "1px solid #30363d", borderRadius: "8px", overflow: "hidden", margin: "8px 0" }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr" }}>
        <div style={{ borderRight: "1px solid #30363d" }}>
          <div style={{ background: "rgba(255,68,68,0.15)", padding: "4px 12px", borderBottom: "1px solid #30363d" }}>
            <span style={{ fontSize: "10px", color: "#ff4444", fontWeight: "700" }}>✗ CURRENT (INSECURE)</span>
          </div>
          <pre style={{ margin: 0, padding: "10px 12px", background: "rgba(255,68,68,0.05)", fontSize: "12px", color: "#ff9090", fontFamily: "monospace", overflowX: "auto", lineHeight: "1.6" }}>
            <code>{bad}</code>
          </pre>
        </div>
        <div>
          <div style={{ background: "rgba(46,160,67,0.15)", padding: "4px 12px", borderBottom: "1px solid #30363d", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ fontSize: "10px", color: "#2ea043", fontWeight: "700" }}>✓ FIX (SECURE)</span>
            <button onClick={() => { navigator.clipboard.writeText(fix); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
              style={{ background: "transparent", border: "none", cursor: "pointer", color: copied ? "#2ea043" : "#8b949e", display: "flex", alignItems: "center", gap: "3px", fontSize: "10px" }}>
              <CopyIcon /> {copied ? "Copied!" : "Copy Fix"}
            </button>
          </div>
          <pre style={{ margin: 0, padding: "10px 12px", background: "rgba(46,160,67,0.05)", fontSize: "12px", color: "#90ff90", fontFamily: "monospace", overflowX: "auto", lineHeight: "1.6" }}>
            <code>{fix}</code>
          </pre>
        </div>
      </div>
    </div>
  );
}

// =========================================================
// STRUCTURED RESPONSE PARSER
// =========================================================

function _analysisBlock(filename, body) {
  return {
    type: "file_analysis", filename,
    purpose:         extractSection(body, "Purpose"),
    technologies:    extractSection(body, "Technologies Detected"),
    configurations:  extractSection(body, "Important Configurations"),
    positive:        extractSection(body, "Positive Findings"),
    findings:        extractFindings(body),
    recommendations: extractSection(body, "Recommendations Summary"),
    crossFile:       extractSection(body, "Cross-File Observations"),
  };
}

function parseStructuredResponse(text, uploadedFiles = []) {
  const hasFileAnalysis = /##\s+(?:File|Repository)\s+Analysis:/i.test(text);
  if (hasFileAnalysis) {
    const sections = text.split(/(?=##\s+(?:File|Repository)\s+Analysis:)/i);
    const blocks = [];
    for (const section of sections) {
      if (!section.trim()) continue;
      const titleMatch = section.match(/##\s+(?:File|Repository)\s+Analysis:\s*`?([^`\n]+)`?/i);
      if (!titleMatch) { blocks.push({ type: "text", content: section }); continue; }
      const body = section.slice(titleMatch[0].length);
      blocks.push(_analysisBlock(titleMatch[1].trim(), body));
    }
    // Drop empty file blocks — models sometimes emit a bare
    // "## File Analysis: <project>" header (the repo/zip name) with no body,
    // which would render as an empty "File:" section in the report/UI.
    return blocks.filter(b => b.type !== "file_analysis"
      || b.purpose || b.findings?.length || b.positive
      || b.recommendations || b.configurations || b.technologies);
  }

  // Resilience: some analyses (often shell scripts) carry the finding
  // markers or a "Security Findings" section but omit the "## File
  // Analysis:" wrapper. Synthesize one block so they still get the rich
  // dashboard/cards instead of falling back to raw markdown (which also
  // leaves #### headings unrendered).
  const hasFindings = /####\s+(?:Critical|High|Medium|Low)\b/i.test(text)
    || /#{1,4}\s+Security Findings/i.test(text);
  if (hasFindings) {
    const filename = uploadedFiles.find(f => !f.sent)?.name
      || uploadedFiles[0]?.name || "Uploaded file";
    return [_analysisBlock(filename, text)];
  }
  return null;
}

function extractSection(text, heading) {
  const regex = new RegExp(`###\\s+${heading}[^\n]*\\n([\\s\\S]*?)(?=###|$)`, "i");
  const match = text.match(regex);
  return match ? match[1].trim() : null;
}

function extractFindings(text) {
  const findings = [];
  const regex = /####\s+(Critical|High|Medium|Low|Suggestions|Low \/ Suggestions)([\s\S]*?)(?=####|###|$)/gi;
  let match;
  while ((match = regex.exec(text)) !== null) {
    const level = match[1].replace("Low / Suggestions", "Low").replace("Suggestions", "Low").trim();
    const raw = match[2].trim();
    findings.push(...splitFindingItems(raw, level));
  }
  return findings;
}

function splitFindingItems(raw, level) {
  const parts = raw.split(/(?=\*\*\[)/);
  if (parts.length <= 1) return [parseFindingItem(raw, level)];
  return parts.filter(p => p.trim()).map(p => parseFindingItem(p, level));
}

function parseFindingItem(raw, level) {
  // Accept both "**[Title]**" (prompt template) and a bare bold title line
  // "**Title**" (what models often emit) so findings aren't labelled "Finding".
  const titleMatch          = raw.match(/\*\*\[([^\]]+)\]\*\*/)
                           || raw.match(/^\s*\*\*([^*\n]{3,120}?)\*\*\s*$/m);
  const locationMatch       = raw.match(/Location:\s*`?([^\n`]+)`?/i);
  const categoryMatch       = raw.match(/\[(SECRETS|MISCONFIGURATION|VULNERABLE-DEPENDENCY|CI-CD|KUBERNETES|DOCKER|TERRAFORM|COMPLIANCE|NETWORK)\]/i);
  const confidenceMatch     = raw.match(/\[Confidence:\s*(HIGH|MEDIUM|LOW)\]/i);
  const riskMatch           = raw.match(/Risk:\s*([^\n]+)/i);
  const whyMatch            = raw.match(/Why it matters:\s*([^\n]+(?:\n(?!Fix:|Risk:|Location:|Evidence:|Blast Radius:)[^\n]+)*)/i);
  const evidenceMatch       = raw.match(/Evidence:([\s\S]*?)(?=Blast Radius:|Fix:|Risk:|Why it matters:|$)/i);
  const blastMatch          = raw.match(/Blast Radius:([\s\S]*?)(?=Fix:|Risk:|Evidence:|Why it matters:|$)/i);
  const confidenceReasonMatch = raw.match(/Confidence Reason:([\s\S]*?)(?=Fix:|Risk:|Evidence:|Blast Radius:|$)/i);
  const beforeFix           = raw.split(/^Fix:/im)[0];
  const problemCodeMatch    = beforeFix.match(/```(\w*)\n([\s\S]*?)```/);
  const problemCode         = problemCodeMatch ? { lang: problemCodeMatch[1], content: problemCodeMatch[2] } : null;
  const afterFix            = raw.split(/^Fix:/im)[1];
  const fixCodeMatch        = afterFix ? afterFix.match(/```(\w*)\n([\s\S]*?)```/) : null;
  const fixCode             = fixCodeMatch ? { lang: fixCodeMatch[1], content: fixCodeMatch[2] } : null;
  const badMatch            = raw.match(/# BAD\n([\s\S]*?)# FIX/);
  const fixDiffMatch        = raw.match(/# FIX\n([\s\S]*?)(?=```|$)/);
  const diffBad             = badMatch ? badMatch[1].trim() : null;
  const diffFix             = fixDiffMatch ? fixDiffMatch[1].replace(/```[\s\S]*/g, "").trim() : null;

  const description = raw
    .replace(/\*\*\[[^\]]+\]\*\*/g, "")
    .replace(/Location:[^\n]+/gi, "")
    .replace(/\[(?:SECRETS|MISCONFIGURATION|VULNERABLE-DEPENDENCY|CI-CD|KUBERNETES|DOCKER|TERRAFORM|COMPLIANCE|NETWORK)\]/gi, "")
    .replace(/\[Confidence:\s*(?:HIGH|MEDIUM|LOW)\]/gi, "")
    .replace(/Risk:[^\n]*/gi, "")
    .replace(/Why it matters:[\s\S]*?(?=Fix:|Evidence:|Blast Radius:|$)/gi, "")
    .replace(/Evidence:[\s\S]*?(?=Blast Radius:|Fix:|$)/gi, "")
    .replace(/Blast Radius:[\s\S]*?(?=Fix:|$)/gi, "")
    .replace(/Confidence Reason:[\s\S]*?(?=Fix:|$)/gi, "")
    .replace(/Fix:[\s\S]*?```[\s\S]*?```/gi, "")
    .replace(/```[\s\S]*?```/g, "")
    .replace(/# BAD[\s\S]*?# FIX[\s\S]*/gi, "")
    .trim();

  // Fallback title so a finding never renders as a generic "Finding":
  // prefer an explicit title, else name it from the category, else the
  // first clause of the risk sentence.
  let title = titleMatch ? titleMatch[1].trim() : "";
  if (!title) {
    const cat = (categoryMatch?.[1] || "").toUpperCase();
    if (cat === "SECRETS") title = "Hardcoded Secret";
    else if (riskMatch) title = riskMatch[1].trim().split(/(?<=\w)\./)[0].slice(0, 90);
    else if (cat) title = cat.charAt(0) + cat.slice(1).toLowerCase().replace(/-/g, " ");
  }

  return {
    level, raw,
    title:            title || null,
    location:         locationMatch ? locationMatch[1].trim() : null,
    category:         categoryMatch ? categoryMatch[1].toUpperCase() : null,
    confidence:       confidenceMatch ? confidenceMatch[1].toUpperCase() : null,
    confidenceReason: confidenceReasonMatch ? confidenceReasonMatch[1].trim() : null,
    risk:             riskMatch ? riskMatch[1].trim() : null,
    whyMatters:       whyMatch ? whyMatch[1].trim() : null,
    evidence:         evidenceMatch ? evidenceMatch[1].trim() : null,
    blastRadius:      blastMatch ? blastMatch[1].trim() : null,
    problemCode, fixCode, diffBad, diffFix, description,
  };
}

// =========================================================
// REPO CONTEXT
// =========================================================

// Severity counts from verified scanner data — preferred over counts
// parsed out of the AI's prose whenever a scan ran, so the dashboard
// reflects tool ground truth even when the AI consolidates findings.
function countScannerFindings(scannerFindings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, SECRETS: 0 };
  for (const f of scannerFindings || []) {
    const sev = f.severity?.toUpperCase();
    if (counts[sev] !== undefined) counts[sev]++;
    if (f.tool === "gitleaks") counts.SECRETS++;
  }
  return counts;
}

function deriveRepoContext(blocks, uploadedFiles, scannerFindings) {
  if (!blocks || blocks.length === 0) return null;
  const fileBlocks = blocks.filter(b => b.type === "file_analysis");
  if (fileBlocks.length === 0) return null;

  const allFindings = fileBlocks.flatMap(b => b.findings || []);
  const hasScanData = (scannerFindings || []).length > 0;
  const counts = hasScanData
    ? countScannerFindings(scannerFindings)
    : { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, SECRETS: 0 };
  const stack = new Set();

  if (!hasScanData) {
    for (const f of allFindings) {
      const lvl = f.level?.toUpperCase();
      if (counts[lvl] !== undefined) counts[lvl]++;
      if (f.category === "SECRETS") counts.SECRETS++;
    }
  }

  for (const f of fileBlocks) {
    const name = f.filename.toLowerCase();
    if (name.includes("dockerfile") || name.includes("docker")) stack.add("Docker");
    if (name.endsWith(".tf") || name.includes("terraform")) stack.add("Terraform");
    if (name.endsWith(".yaml") || name.endsWith(".yml")) {
      if (name.includes("deploy") || name.includes("service") || name.includes("ingress")) stack.add("Kubernetes");
      if (name.includes("workflow") || name.includes("github")) stack.add("GitHub Actions");
      if (name.includes("chart") || name.includes("helm") || name.includes("values")) stack.add("Helm");
    }
    if (name.includes("package.json")) stack.add("Node.js");
    if (name.includes("pom.xml") || name.includes("build.gradle")) stack.add("Java");
    if (name.includes("requirements") || name.endsWith(".py")) stack.add("Python");
    if (name.includes("postgres") || name.includes("pg")) stack.add("PostgreSQL");
    if (name.includes("redis")) stack.add("Redis");
    if (name.includes("nginx")) stack.add("Nginx");
    if (name.includes("jenkins")) stack.add("Jenkins");
  }

  const memoryCategories = [];
  if (stack.has("Docker")) memoryCategories.push("Docker configs");
  if (stack.has("Kubernetes")) memoryCategories.push("Kubernetes manifests");
  if (stack.has("Terraform")) memoryCategories.push("Terraform IaC");
  if (stack.has("GitHub Actions")) memoryCategories.push("CI/CD pipelines");
  if (stack.has("Node.js")) memoryCategories.push("Node.js dependencies");
  if (stack.has("Java")) memoryCategories.push("Java dependencies");
  if (stack.has("Python")) memoryCategories.push("Python dependencies");
  if (counts.SECRETS > 0) memoryCategories.push("Secret findings");
  if (allFindings.length > 0) memoryCategories.push("Security findings");
  if (stack.has("PostgreSQL")) memoryCategories.push("PostgreSQL configs");
  if (stack.has("Redis")) memoryCategories.push("Redis configs");

  const repoName = uploadedFiles.find(f => f.name.endsWith(".zip"))?.name.replace(".zip", "")
    || uploadedFiles[0]?.name || "Project";

  return { repoName, fileCount: fileBlocks.length, counts, stack: [...stack], memoryCategories };
}

// =========================================================
// DASHBOARD
// =========================================================

// Documentation files (.md, README, LICENSE, …) have no scannable security
// surface beyond secrets. When such a file is analysed and nothing was
// flagged, a Critical/High/Medium/Low risk dashboard is misleading — so we
// show a documentation note instead of the severity grid.
const DOC_EXTS = [
  ".md", ".markdown", ".mdx", ".mkd", ".mdown",
  ".txt", ".text", ".rst", ".adoc", ".asciidoc",
  ".wiki", ".mediawiki", ".org", ".tex", ".latex",
  ".rtf", ".textile", ".creole", ".pod",
];
// Well-known documentation filenames (matched on the base name, so variants
// like LICENSE-MIT / COPYING.LESSER / CHANGELOG-1.0 are covered).
const DOC_NAMES = [
  "readme", "license", "licence", "copying", "unlicense",
  "changelog", "changes", "history", "news", "releases",
  "contributing", "code_of_conduct", "authors", "contributors",
  "maintainers", "owners", "codeowners", "humans",
  "notice", "acknowledgments", "acknowledgements", "credits",
  "security", "support", "funding", "governance", "roadmap",
  "todo", "faq", "glossary", "install", "disclaimer",
  "copyright", "patents", "thanks",
];
// Scannable code/config extensions — a file with one of these is never a doc,
// even if its name starts with a doc word (licensecheck.py, readme_gen.js).
const CODE_EXTS = [
  ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java",
  ".rb", ".php", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp", ".cs", ".kt",
  ".scala", ".swift", ".sh", ".bash", ".zsh", ".ps1", ".tf", ".tfvars",
  ".hcl", ".yaml", ".yml", ".json", ".json5", ".toml", ".ini", ".cfg",
  ".conf", ".properties", ".env", ".xml", ".gradle", ".groovy", ".sql",
  ".lock", ".dockerfile", ".pl", ".lua", ".r", ".dart",
];
function isDocFile(name) {
  const n = (name || "").toLowerCase().split(/[\\/]/).pop();
  if (DOC_EXTS.some(e => n.endsWith(e))) return true;   // README.md, notes.rst
  if (CODE_EXTS.some(e => n.endsWith(e))) return false;  // licensecheck.py = code
  const base = n.split(".")[0];                          // COPYING.LESSER -> copying
  return DOC_NAMES.some(d => base === d || base.startsWith(d + "-") || base.startsWith(d + "_"));
}

function buildDashboard(blocks) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, SECRETS: 0, KUBERNETES: 0, TERRAFORM: 0, DOCKER: 0, "CI-CD": 0, MISCONFIGURATION: 0, "VULNERABLE-DEPENDENCY": 0, NETWORK: 0, COMPLIANCE: 0 };
  let totalFiles = 0;
  for (const block of blocks) {
    if (block.type !== "file_analysis") continue;
    totalFiles++;
    for (const f of (block.findings || [])) {
      const lvl = f.level?.toUpperCase();
      if (counts[lvl] !== undefined) counts[lvl]++;
      if (f.category && counts[f.category] !== undefined) counts[f.category]++;
    }
  }
  return { counts, totalFiles };
}

function Dashboard({ blocks, scannerFindings }) {
  const { counts: proseCounts, totalFiles } = buildDashboard(blocks);
  const hasScanData = (scannerFindings || []).length > 0;
  // Render whenever there are parsed per-file cards OR verified scanner
  // findings — so a targeted action response (plain prose, no per-file
  // blocks) still gets the same dashboard header as a full audit.
  if (totalFiles === 0 && !hasScanData) return null;

  // Severity numbers come from verified scanner data when a scan ran;
  // category chips still come from the AI's categorised findings.
  const sevCounts = hasScanData ? countScannerFindings(scannerFindings) : proseCounts;
  const counts = { ...proseCounts, ...sevCounts };
  const total = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW;
  // File count: parsed cards if present, else distinct files in the findings.
  const displayFiles = totalFiles || new Set((scannerFindings || []).map(f => f.file).filter(Boolean)).size;

  // Documentation-only analysis with nothing flagged: don't frame a doc as a
  // vulnerability target with a risk score — show a doc note, let the summary
  // card below carry the "other findings" (purpose, contents).
  const docBlocks = (blocks || []).filter(b => b.type === "file_analysis");
  const allDocs = docBlocks.length > 0 && docBlocks.every(b => isDocFile(b.filename));
  if (total === 0 && counts.SECRETS === 0 && allDocs) {
    return (
      <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "10px", padding: "12px 14px", marginBottom: "14px", display: "flex", alignItems: "center", gap: "9px" }}>
        <span style={{ fontSize: "16px" }}>📄</span>
        <span style={{ fontSize: "12px", color: "#8b949e" }}>
          <span style={{ color: "#e6edf3", fontWeight: "600" }}>Documentation</span> — no security-relevant configuration to scan. Summary below.
        </span>
      </div>
    );
  }

  const riskLevel = counts.CRITICAL > 0 ? { label: "HIGH RISK", color: "#ff4444" }
    : counts.HIGH > 0   ? { label: "ELEVATED",  color: "#ff8800" }
    : counts.MEDIUM > 5 ? { label: "MODERATE",  color: "#d29922" }
    : { label: "LOW RISK", color: "#2ea043" };

  return (
    <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "10px", padding: "14px", marginBottom: "14px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "7px" }}>
          <DashboardIcon />
          <span style={{ fontSize: "11px", fontWeight: "700", color: "#e6edf3", textTransform: "uppercase", letterSpacing: "0.8px" }}>Repository Summary</span>
        </div>
        <span style={{ background: `${riskLevel.color}18`, border: `1px solid ${riskLevel.color}44`, borderRadius: "4px", padding: "2px 9px", fontSize: "10px", fontWeight: "700", color: riskLevel.color, fontFamily: "monospace" }}>{riskLevel.label}</span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: "7px", marginBottom: "10px" }}>
        {[["CRITICAL", SEVERITY.CRITICAL], ["HIGH", SEVERITY.HIGH], ["MEDIUM", SEVERITY.MEDIUM], ["LOW", SEVERITY.LOW]].map(([key, cfg]) => (
          <div key={key} style={{ background: cfg.bg, border: `1px solid ${cfg.border}`, borderRadius: "7px", padding: "9px 10px", textAlign: "center" }}>
            <div style={{ fontSize: "20px", fontWeight: "800", color: cfg.color, lineHeight: 1 }}>{counts[key]}</div>
            <div style={{ fontSize: "9px", color: cfg.color, marginTop: "3px", fontWeight: "600", textTransform: "uppercase", letterSpacing: "0.5px" }}>{key}</div>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "5px", marginBottom: "9px" }}>
        {[
          { key: "SECRETS", label: "Secrets", icon: "🔑" },
          { key: "KUBERNETES", label: "K8s", icon: "☸️" },
          { key: "TERRAFORM", label: "Terraform", icon: "🏗️" },
          { key: "DOCKER", label: "Docker", icon: "🐳" },
          { key: "CI-CD", label: "CI/CD", icon: "🔁" },
          { key: "MISCONFIGURATION", label: "Misconfig", icon: "⚙️" },
          { key: "VULNERABLE-DEPENDENCY", label: "Vuln Deps", icon: "📦" },
          { key: "NETWORK", label: "Network", icon: "🌐" },
        ].filter(c => counts[c.key] > 0).map(({ key, label, icon }) => {
          const color = CATEGORY_COLORS[key] || "#8b949e";
          return (
            <div key={key} style={{ display: "flex", alignItems: "center", gap: "4px", background: `${color}11`, border: `1px solid ${color}33`, borderRadius: "5px", padding: "3px 8px" }}>
              <span style={{ fontSize: "10px" }}>{icon}</span>
              <span style={{ fontSize: "10px", color, fontWeight: "600" }}>{label}</span>
              <span style={{ background: `${color}22`, borderRadius: "8px", padding: "0 5px", fontSize: "9px", color, fontWeight: "700" }}>{counts[key]}</span>
            </div>
          );
        })}
      </div>
      <div style={{ display: "flex", gap: "14px", borderTop: "1px solid #30363d", paddingTop: "9px" }}>
        <span style={{ fontSize: "11px", color: "#8b949e" }}><span style={{ color: "#e6edf3", fontWeight: "600" }}>{displayFiles}</span> files</span>
        <span style={{ fontSize: "11px", color: "#8b949e" }}><span style={{ color: "#e6edf3", fontWeight: "600" }}>{total}</span> findings</span>
      </div>
    </div>
  );
}

// =========================================================
// ATTACK SURFACE PANEL
// =========================================================

function AttackSurfacePanel({ blocks }) {
  const [open, setOpen] = useState(true);
  const allFindings = blocks.flatMap(b => b.type === "file_analysis" ? (b.findings || []) : []);

  const hasExposed  = allFindings.some(f => f.category === "NETWORK" || /cidr|0\.0\.0\.0|exposed|public/i.test(f.raw || ""));
  const hasNoAuth   = allFindings.some(f => /no auth|without auth|unauthenticated|anonymous/i.test(f.raw || ""));
  const hasSecret   = allFindings.some(f => f.category === "SECRETS");
  const hasPriv     = allFindings.some(f => /privileged|runAsRoot|root user/i.test(f.raw || ""));
  const hasVuln     = allFindings.some(f => f.category === "VULNERABLE-DEPENDENCY");
  const hasNoLimits = allFindings.some(f => /resource limit|no limit|resources: \{\}/i.test(f.raw || ""));

  const chains = [];
  if (hasExposed && hasNoAuth) chains.push({ severity: "CRITICAL", title: "Unauthenticated Public Exposure", steps: ["Service exposed to 0.0.0.0/0", "No authentication configured", "Unrestricted external access"], impact: "External attackers can access internal services directly without any credentials." });
  if (hasSecret && hasExposed) chains.push({ severity: "CRITICAL", title: "Secret Leak + External Exposure", steps: ["Hardcoded credentials in repository", "Service publicly exposed", "Credential extraction + pivot"], impact: "Leaked credentials combined with public access enables direct account takeover and lateral movement." });
  if (hasPriv && hasExposed)   chains.push({ severity: "HIGH",     title: "Privileged Container + Exposure", steps: ["Container runs as root / privileged", "Service reachable externally", "Container escape → host compromise"], impact: "Privilege escalation from compromised container to the underlying host node is feasible." });
  if (hasVuln && hasExposed)   chains.push({ severity: "HIGH",     title: "Vulnerable Dependency + Network Exposure", steps: ["Outdated library with known vulnerabilities", "Application exposed on network", "Remote exploit via known CVE"], impact: "Known library vulnerabilities may be triggered remotely through exposed application endpoints." });
  if (hasNoLimits && hasExposed) chains.push({ severity: "MEDIUM", title: "No Resource Limits + External Traffic", steps: ["No CPU/memory limits defined", "Service accepts external traffic", "DoS exhausts node resources"], impact: "Resource exhaustion attack can bring down co-located services on the same Kubernetes node." });

  if (chains.length === 0) return null;

  return (
    <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "10px", marginBottom: "14px", overflow: "hidden" }}>
      <button onClick={() => setOpen(o => !o)} style={{ width: "100%", display: "flex", alignItems: "center", gap: "7px", padding: "11px 14px", background: "transparent", border: "none", cursor: "pointer", textAlign: "left", borderBottom: open ? "1px solid #30363d" : "none" }}>
        <AlertIcon />
        <span style={{ fontSize: "11px", fontWeight: "700", color: "#ff8800", textTransform: "uppercase", letterSpacing: "0.8px", flex: 1 }}>Attack Surface Analysis</span>
        <span style={{ background: "rgba(255,68,68,0.15)", border: "1px solid rgba(255,68,68,0.3)", borderRadius: "10px", padding: "1px 8px", fontSize: "10px", color: "#ff4444", fontWeight: "700" }}>{chains.length} chain{chains.length > 1 ? "s" : ""}</span>
        <ChevronIcon open={open} />
      </button>
      {open && (
        <div style={{ padding: "10px 14px", display: "flex", flexDirection: "column", gap: "9px" }}>
          {chains.map((chain, i) => {
            const cfg = SEVERITY[chain.severity] || SEVERITY.MEDIUM;
            return (
              <div key={i} style={{ background: cfg.bg, border: `1px solid ${cfg.border}`, borderRadius: "8px", padding: "10px 12px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "7px", marginBottom: "9px" }}>
                  <SeverityBadge level={chain.severity} />
                  <span style={{ fontSize: "12px", fontWeight: "600", color: "#e6edf3" }}>{chain.title}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "4px", flexWrap: "wrap", marginBottom: "9px" }}>
                  {chain.steps.map((step, j) => (
                    <div key={j} style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                      <span style={{ background: "#0d1117", border: `1px solid ${cfg.border}`, borderRadius: "4px", padding: "2px 8px", fontSize: "11px", color: "#c9d1d9" }}>{step}</span>
                      {j < chain.steps.length - 1 && <span style={{ color: cfg.color, fontSize: "13px", fontWeight: "700" }}>→</span>}
                    </div>
                  ))}
                </div>
                <div style={{ display: "flex", alignItems: "flex-start", gap: "6px", background: "#0d1117", borderRadius: "5px", padding: "7px 9px" }}>
                  <AlertIcon />
                  <span style={{ fontSize: "11px", color: "#c9d1d9", lineHeight: "1.5" }}>
                    <strong style={{ color: "#e6edf3" }}>Impact: </strong>{chain.impact}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// =========================================================
// FOLLOW-UP SUGGESTIONS
// =========================================================

function FollowUpSuggestions({ blocks, onSend }) {
  const allFindings = blocks.flatMap(b => b.type === "file_analysis" ? (b.findings || []) : []);
  const hasSecrets  = allFindings.some(f => f.category === "SECRETS");
  const hasDocker   = allFindings.some(f => f.category === "DOCKER");
  const hasK8s      = allFindings.some(f => f.category === "KUBERNETES");
  const hasTF       = allFindings.some(f => f.category === "TERRAFORM");
  const hasCicd     = allFindings.some(f => f.category === "CI-CD");
  const hasVulnDep  = allFindings.some(f => f.category === "VULNERABLE-DEPENDENCY");
  const hasCritical = allFindings.some(f => f.level?.toUpperCase() === "CRITICAL");
  const hasNetwork  = allFindings.some(f => f.category === "NETWORK");

  const suggestions = [];
  if (hasCritical) suggestions.push({ label: "🔴 Show all critical findings",   msg: "List all critical findings with exact locations and fixes" });
  if (hasSecrets)  suggestions.push({ label: "🔑 Show all secrets detected",    msg: "Show all hardcoded secrets found with exact file locations and evidence" });
  if (hasDocker)   suggestions.push({ label: "🐳 Generate fixed Dockerfile",    msg: "Generate a fully corrected and hardened Dockerfile based on the findings" });
  if (hasK8s)      suggestions.push({ label: "☸️ K8s hardening checklist",     msg: "Create a Kubernetes hardening checklist based on findings in these files" });
  if (hasTF)       suggestions.push({ label: "🏗️ Fix Terraform issues",        msg: "Generate fixed Terraform configuration for all identified issues" });
  if (hasCicd)     suggestions.push({ label: "🔁 Secure the CI/CD pipeline",   msg: "Generate a hardened CI/CD pipeline configuration based on these findings" });
  if (hasVulnDep)  suggestions.push({ label: "📦 Show vulnerable dependencies", msg: "List all vulnerable dependencies with exact versions and recommended upgrades" });
  if (hasNetwork)  suggestions.push({ label: "🌐 Fix network exposure",         msg: "Show all network exposure issues and generate fixed configurations" });
  suggestions.push({ label: "📋 Generate full security report", msg: "Generate a complete security report with all findings, evidence, compliance mapping, and remediation steps" });
  suggestions.push({ label: "💡 Explain the top vulnerability", msg: "Explain the most critical vulnerability found and how an attacker would exploit it" });

  if (suggestions.length === 0) return null;

  return (
    <div style={{ background: "rgba(31,111,235,0.06)", border: "1px solid rgba(31,111,235,0.2)", borderRadius: "8px", padding: "10px 12px", marginTop: "12px" }}>
      <div style={{ fontSize: "10px", color: "#58a6ff", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "9px", display: "flex", alignItems: "center", gap: "5px" }}>
        <ZapIcon /> Suggested Follow-ups
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
        {suggestions.map((s, i) => (
          <button key={i} onClick={() => onSend(s.msg)} style={{
            background: "#161b22", border: "1px solid #30363d",
            borderRadius: "6px", padding: "5px 11px",
            fontSize: "11px", color: "#c9d1d9", cursor: "pointer", transition: "all 0.15s"
          }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = "#1f6feb"; e.currentTarget.style.color = "#79c0ff"; e.currentTarget.style.background = "rgba(31,111,235,0.1)"; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = "#30363d"; e.currentTarget.style.color = "#c9d1d9"; e.currentTarget.style.background = "#161b22"; }}>
            {s.label}
          </button>
        ))}
      </div>
    </div>
  );
}

// =========================================================
// DOWNLOAD REPORT BUTTON
// Shown inside ChatMessage when file analysis is present.
// Additive — does not change any existing component.
// =========================================================

function DownloadReportButton({ blocks, repoCtx, uploadedFiles, scannerFindings, repo, scannersRun, filesScanned }) {
  const [downloaded, setDownloaded] = useState(false);

  const handleDownload = () => {
    downloadReport(blocks, repoCtx, uploadedFiles, scannerFindings, repo, scannersRun, filesScanned);
    setDownloaded(true);
    setTimeout(() => setDownloaded(false), 3000);
  };

  return (
    <button
      onClick={handleDownload}
      style={{
        display: "inline-flex", alignItems: "center", gap: "6px",
        background: downloaded ? "rgba(46,160,67,0.15)" : "rgba(31,111,235,0.1)",
        border: `1px solid ${downloaded ? "rgba(46,160,67,0.4)" : "rgba(31,111,235,0.3)"}`,
        borderRadius: "6px", padding: "6px 13px",
        fontSize: "11px", fontWeight: "600",
        color: downloaded ? "#2ea043" : "#58a6ff",
        cursor: "pointer", transition: "all 0.2s",
        marginTop: "10px",
      }}
      onMouseEnter={e => {
        if (!downloaded) {
          e.currentTarget.style.background = "rgba(31,111,235,0.2)";
          e.currentTarget.style.borderColor = "rgba(31,111,235,0.5)";
        }
      }}
      onMouseLeave={e => {
        if (!downloaded) {
          e.currentTarget.style.background = "rgba(31,111,235,0.1)";
          e.currentTarget.style.borderColor = "rgba(31,111,235,0.3)";
        }
      }}
    >
      {downloaded ? (
        <>✓ Downloaded</>
      ) : (
        <>
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          Download Report (.md)
        </>
      )}
    </button>
  );
}

// =========================================================
// FINDING CARD
// =========================================================

function FindingCard({ finding }) {
  const { level, title, location, category, confidence, confidenceReason, problemCode, fixCode, diffBad, diffFix, risk, whyMatters, evidence, blastRadius, description } = finding;
  const autoOpen = ["CRITICAL", "HIGH"].includes(level?.toUpperCase());
  const [open, setOpen] = useState(autoOpen);
  const [fixOpen, setFixOpen] = useState(false);
  const sev = SEVERITY[level?.toUpperCase().replace("SUGGESTIONS", "LOW")] || SEVERITY.INFO;
  const hasFix = !!(fixCode || diffFix);

  return (
    <div style={{ background: sev.bg, border: `1px solid ${sev.border}`, borderRadius: "8px", marginBottom: "7px", overflow: "hidden" }}>
      <button onClick={() => setOpen(o => !o)} style={{ width: "100%", display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap", padding: "8px 12px", background: "transparent", border: "none", cursor: "pointer", textAlign: "left" }}>
        <SeverityBadge level={level} />
        {category && <CategoryBadge category={category} />}
        {confidence && <ConfidenceBadge level={confidence} reason={confidenceReason} />}
        {location && <LocationPill location={location} />}
        {hasFix && <FixAvailableBadge />}
        {title && <span style={{ fontSize: "12px", fontWeight: "600", color: "#e6edf3", flex: 1, minWidth: "100px" }}>{title}</span>}
        <ChevronIcon open={open} />
      </button>
      {open && (
        <div style={{ padding: "0 12px 12px", borderTop: `1px solid ${sev.border}` }}>
          {description && description.length > 5 && (
            <div style={{ paddingTop: "9px" }}><MarkdownBlock text={description} /></div>
          )}
          {problemCode && (
            <div style={{ marginTop: "9px" }}>
              <div style={{ fontSize: "9px", color: "#8b949e", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "3px" }}>Affected Code</div>
              <CodeBlock lang={problemCode.lang || "yaml"} content={problemCode.content} />
            </div>
          )}
          {diffBad && diffFix && (
            <div style={{ marginTop: "9px" }}>
              <div style={{ fontSize: "9px", color: "#8b949e", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "3px" }}>Fix Comparison</div>
              <DiffBlock bad={diffBad} fix={diffFix} />
            </div>
          )}
          {risk && (
            <div style={{ display: "flex", gap: "6px", alignItems: "flex-start", background: "#0d1117", borderRadius: "5px", padding: "7px 9px", marginTop: "7px" }}>
              <ShieldIcon />
              <div>
                <span style={{ fontSize: "9px", color: "#8b949e", textTransform: "uppercase", letterSpacing: "0.8px", display: "block", marginBottom: "2px" }}>Risk</span>
                <span style={{ fontSize: "12px", color: "#c9d1d9" }}>{risk}</span>
              </div>
            </div>
          )}
          {whyMatters && (
            <div style={{ display: "flex", gap: "6px", alignItems: "flex-start", background: "rgba(88,166,255,0.06)", border: "1px solid rgba(88,166,255,0.15)", borderRadius: "5px", padding: "7px 9px", marginTop: "7px" }}>
              <InfoIcon />
              <div>
                <span style={{ fontSize: "9px", color: "#58a6ff", textTransform: "uppercase", letterSpacing: "0.8px", display: "block", marginBottom: "2px" }}>Why it matters</span>
                <span style={{ fontSize: "12px", color: "#c9d1d9" }}>{whyMatters}</span>
              </div>
            </div>
          )}
          {evidence && (
            <div style={{ background: "rgba(210,153,34,0.06)", border: "1px solid rgba(210,153,34,0.2)", borderRadius: "5px", padding: "7px 9px", marginTop: "7px" }}>
              <div style={{ fontSize: "9px", color: "#d29922", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "5px", display: "flex", alignItems: "center", gap: "4px" }}>
                <EvidenceIcon /> Evidence
              </div>
              <MarkdownBlock text={evidence} />
            </div>
          )}
          {blastRadius && (
            <div style={{ background: "rgba(255,68,68,0.06)", border: "1px solid rgba(255,68,68,0.2)", borderRadius: "5px", padding: "7px 9px", marginTop: "7px" }}>
              <div style={{ fontSize: "9px", color: "#ff4444", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "5px", display: "flex", alignItems: "center", gap: "4px" }}>
                <BlastIcon /> Blast Radius
              </div>
              <MarkdownBlock text={blastRadius} />
            </div>
          )}
          {fixCode && !diffFix && (
            <div style={{ marginTop: "9px" }}>
              <button onClick={() => setFixOpen(o => !o)} style={{ display: "flex", alignItems: "center", gap: "5px", background: "rgba(35,134,54,0.1)", border: "1px solid rgba(35,134,54,0.3)", borderRadius: "6px", padding: "5px 11px", cursor: "pointer", color: "#2ea043", fontSize: "11px", fontWeight: "600" }}>
                <WrenchIcon /> {fixOpen ? "Hide Fix" : "Show Fix"} <ChevronIcon open={fixOpen} />
              </button>
              {fixOpen && <CodeBlock lang={fixCode.lang || "yaml"} content={fixCode.content} />}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// =========================================================
// FILE ANALYSIS CARD
// =========================================================

function FileAnalysisCard({ block }) {
  const [open, setOpen] = useState(true);
  const critCount  = (block.findings || []).filter(f => f.level?.toUpperCase() === "CRITICAL").length;
  const highCount  = (block.findings || []).filter(f => f.level?.toUpperCase() === "HIGH").length;
  const totalCount = (block.findings || []).length;
  const ext = block.filename.split(".").pop()?.toLowerCase();
  const fileColor = { tf: "#7b68ee", yaml: "#58a6ff", yml: "#58a6ff", json: "#d29922", py: "#3fb950", sh: "#8b949e", xml: "#e8912d", md: "#8b949e", zip: "#ff8800", env: "#ff4444", js: "#f7df1e", ts: "#3178c6", go: "#00add8" }[ext] || "#8b949e";

  return (
    <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "10px", marginBottom: "10px", overflow: "hidden" }}>
      <button onClick={() => setOpen(o => !o)} style={{ width: "100%", display: "flex", alignItems: "center", gap: "7px", padding: "10px 14px", background: "transparent", border: "none", cursor: "pointer", textAlign: "left", borderBottom: open ? "1px solid #30363d" : "none" }}>
        <span style={{ background: `${fileColor}1a`, border: `1px solid ${fileColor}44`, borderRadius: "4px", padding: "2px 6px", fontSize: "10px", color: fileColor, fontFamily: "monospace", fontWeight: "700", flexShrink: 0 }}>{ext?.toUpperCase() || "FILE"}</span>
        <span style={{ color: "#e6edf3", fontSize: "13px", fontWeight: "600", flex: 1 }}>{block.filename}</span>
        <div style={{ display: "flex", gap: "5px", alignItems: "center" }}>
          {critCount > 0 && <span style={{ background: "rgba(255,68,68,0.15)", border: "1px solid rgba(255,68,68,0.3)", borderRadius: "10px", padding: "1px 7px", fontSize: "10px", color: "#ff4444", fontWeight: "700" }}>{critCount} critical</span>}
          {highCount > 0 && <span style={{ background: "rgba(255,136,0,0.12)", border: "1px solid rgba(255,136,0,0.3)", borderRadius: "10px", padding: "1px 7px", fontSize: "10px", color: "#ff8800", fontWeight: "700" }}>{highCount} high</span>}
          {totalCount > 0 && critCount === 0 && highCount === 0 && <span style={{ background: "rgba(210,153,34,0.1)", border: "1px solid rgba(210,153,34,0.3)", borderRadius: "10px", padding: "1px 7px", fontSize: "10px", color: "#d29922", fontWeight: "600" }}>{totalCount} findings</span>}
          {totalCount === 0 && <span style={{ background: "rgba(46,160,67,0.1)", border: "1px solid rgba(46,160,67,0.25)", borderRadius: "10px", padding: "1px 7px", fontSize: "10px", color: "#2ea043", fontWeight: "600" }}>✓ clean</span>}
        </div>
        <ChevronIcon open={open} />
      </button>
      {open && (
        <div style={{ padding: "12px 14px" }}>
          {block.purpose && (
            <div style={{ background: "#0d1117", borderRadius: "6px", padding: "8px 12px", marginBottom: "10px", borderLeft: "3px solid #1f6feb" }}>
              <div style={{ fontSize: "9px", color: "#8b949e", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "3px" }}>Purpose</div>
              <div style={{ fontSize: "13px", color: "#c9d1d9" }}>{block.purpose}</div>
            </div>
          )}
          {(block.technologies || block.configurations) && (
            <div style={{ display: "grid", gridTemplateColumns: block.technologies && block.configurations ? "1fr 1fr" : "1fr", gap: "9px", marginBottom: "10px" }}>
              {block.technologies && (
                <div style={{ background: "#0d1117", borderRadius: "6px", padding: "8px 12px" }}>
                  <div style={{ fontSize: "9px", color: "#8b949e", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "5px" }}>Technologies</div>
                  <MarkdownBlock text={block.technologies} />
                </div>
              )}
              {block.configurations && (
                <div style={{ background: "#0d1117", borderRadius: "6px", padding: "8px 12px" }}>
                  <div style={{ fontSize: "9px", color: "#8b949e", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "5px" }}>Key Configurations</div>
                  <MarkdownBlock text={block.configurations} />
                </div>
              )}
            </div>
          )}
          {block.positive && (
            <div style={{ background: "rgba(46,160,67,0.06)", border: "1px solid rgba(46,160,67,0.2)", borderRadius: "6px", padding: "8px 12px", marginBottom: "10px" }}>
              <div style={{ fontSize: "9px", color: "#2ea043", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "5px", display: "flex", alignItems: "center", gap: "4px" }}>
                <CheckIcon /> Positive Findings
              </div>
              <MarkdownBlock text={block.positive} />
            </div>
          )}
          {block.findings?.length > 0 && (
            <div style={{ marginBottom: "10px" }}>
              <div style={{ fontSize: "9px", color: "#8b949e", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "7px", display: "flex", alignItems: "center", gap: "4px" }}>
                <ShieldIcon /> Security Findings ({block.findings.length})
              </div>
              {block.findings.map((f, i) => <FindingCard key={i} finding={f} />)}
            </div>
          )}
          {block.recommendations && (
            <div style={{ background: "#0d1117", borderRadius: "6px", padding: "8px 12px", marginBottom: "10px" }}>
              <div style={{ fontSize: "9px", color: "#8b949e", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "5px" }}>Recommendations</div>
              <MarkdownBlock text={block.recommendations} />
            </div>
          )}
          {block.crossFile && (
            <div style={{ background: "rgba(88,166,255,0.05)", border: "1px solid rgba(88,166,255,0.2)", borderRadius: "6px", padding: "8px 12px" }}>
              <div style={{ fontSize: "9px", color: "#58a6ff", textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: "5px", display: "flex", alignItems: "center", gap: "4px" }}>
                <LinkIcon /> Cross-File Observations
              </div>
              <MarkdownBlock text={block.crossFile} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// =========================================================
// SCANNER FINDINGS PANEL
// Verified ground truth from deterministic scanners
// (gitleaks, checkov) — structured data from the backend,
// rendered independently of the AI's prose.
// =========================================================

const SEVERITY_COLORS = {
  CRITICAL: "#ff4444",
  HIGH: "#ff8800",
  MEDIUM: "#d29922",
  LOW: "#58a6ff",
  INFO: "#8b949e",
};

function ScannerFindingsPanel({ findings, scannersRun }) {
  const [open, setOpen] = useState(false);
  const [tool, setTool] = useState(null); // null = All (consolidated)
  if (!findings?.length) return null;

  const counts = {};
  for (const f of findings) {
    const sev = f.severity?.toUpperCase() || "INFO";
    counts[sev] = (counts[sev] || 0) + 1;
  }

  // Per-tool finding counts, in the order tools ran (fallback: discovered)
  const toolCounts = {};
  for (const f of findings) toolCounts[f.tool] = (toolCounts[f.tool] || 0) + 1;
  const toolsWithFindings = (scannersRun || []).filter(t => toolCounts[t]);
  for (const t of Object.keys(toolCounts)) {
    if (!toolsWithFindings.includes(t)) toolsWithFindings.push(t);
  }

  const shown = tool ? findings.filter(f => f.tool === tool) : findings;

  const chip = (label, count, active, onClick) => (
    <button key={label} onClick={(e) => { e.stopPropagation(); setOpen(true); onClick(); }}
      style={{ background: active ? "#1f6feb22" : "#0d1117",
        border: `1px solid ${active ? "#1f6feb" : "#30363d"}`, borderRadius: "5px",
        padding: "2px 8px", fontSize: "10px", cursor: "pointer",
        color: active ? "#79c0ff" : "#8b949e", fontFamily: "monospace" }}>
      {label}{count != null ? ` ${count}` : ""}
    </button>
  );

  return (
    <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "10px", marginBottom: "12px", overflow: "hidden" }}>
      <button onClick={() => setOpen(o => !o)} style={{ width: "100%", display: "flex", alignItems: "center", gap: "7px", padding: "10px 14px", background: "transparent", border: "none", cursor: "pointer", textAlign: "left", borderBottom: open ? "1px solid #30363d" : "none" }}>
        <span style={{ color: "#2ea043", display: "flex", alignItems: "center" }}><ShieldIcon /></span>
        <span style={{ color: "#e6edf3", fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.6px" }}>
          Verified Scanner Findings ({findings.length})
        </span>
        <span style={{ flex: 1 }} />
        {Object.entries(SEVERITY_COLORS).map(([sev, color]) =>
          counts[sev] ? (
            <span key={sev} style={{ background: `${color}1f`, border: `1px solid ${color}55`, borderRadius: "10px", padding: "1px 7px", fontSize: "10px", color, fontWeight: "700" }}>
              {counts[sev]} {sev.toLowerCase()}
            </span>
          ) : null
        )}
        <ChevronIcon open={open} />
      </button>
      {open && (
        <>
          <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", padding: "9px 12px", borderBottom: "1px solid #30363d" }}>
            {chip("All", findings.length, tool === null, () => setTool(null))}
            {toolsWithFindings.map(t => chip(t, toolCounts[t], tool === t, () => setTool(t)))}
          </div>
          <div style={{ padding: "8px 10px", maxHeight: "320px", overflowY: "auto" }}>
          {shown.map((f, i) => {
            const color = SEVERITY_COLORS[f.severity?.toUpperCase()] || SEVERITY_COLORS.INFO;
            return (
              <div key={i} style={{ display: "flex", gap: "8px", alignItems: "baseline", padding: "6px 6px", borderBottom: i < shown.length - 1 ? "1px solid #21262d" : "none", flexWrap: "wrap" }}>
                <span style={{ background: `${color}1f`, border: `1px solid ${color}55`, borderRadius: "4px", padding: "1px 6px", fontSize: "9px", color, fontWeight: "700", flexShrink: 0 }}>{f.severity}</span>
                <span style={{ fontSize: "10px", color: "#8b949e", fontFamily: "monospace", flexShrink: 0 }}>{f.tool}/{f.rule_id}</span>
                <span style={{ fontSize: "11px", color: "#79c0ff", fontFamily: "monospace", flexShrink: 0 }}>{f.file}:{f.line}</span>
                <span style={{ fontSize: "12px", color: "#c9d1d9", flex: 1, minWidth: "180px" }}>
                  {f.title}
                  {f.evidence && <span style={{ color: "#d29922", fontFamily: "monospace", fontSize: "11px" }}> — {f.evidence}</span>}
                </span>
              </div>
            );
          })}
          </div>
        </>
      )}
    </div>
  );
}

// =========================================================
// REPO FOLLOW-UPS
// One-click next steps shown on repo-ingestion summaries
// =========================================================

const REPO_FOLLOW_UPS = [
  { icon: "🛡️", label: "Full security audit", msg: "Run a full security audit on the repository" },
  { icon: "🔴", label: "Critical findings", msg: "Show all critical findings with fixes" },
  { icon: "🔑", label: "Hardcoded secrets", msg: "Are there hardcoded secrets in this repo?" },
  { icon: "🗺️", label: "Walk me through it", msg: "Walk me through this repo" },
];

function RepoFollowUps({ onSend }) {
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "12px" }}>
      {REPO_FOLLOW_UPS.map((a, i) => (
        <button key={i} onClick={() => onSend(a.msg)} style={{
          display: "flex", alignItems: "center", gap: "5px",
          background: "#161b22", border: "1px solid #30363d",
          borderRadius: "6px", padding: "6px 11px", cursor: "pointer",
          color: "#c9d1d9", fontSize: "12px", transition: "all 0.2s",
        }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = "#2ea043"; e.currentTarget.style.color = "#2ea043"; }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = "#30363d"; e.currentTarget.style.color = "#c9d1d9"; }}>
          <span>{a.icon}</span> {a.label}
        </button>
      ))}
    </div>
  );
}

// =========================================================
// CHAT MESSAGE
// =========================================================

function ChatMessage({ role, content, isLoading, onSend, uploadedFiles, isLatestAssistant, scannerFindings, scannersRun, repo, filesScanned }) {
  const isUser = role === "user";

  // Parse structured file analysis for EVERY assistant message that has
  // it — each analysis keeps its rich dashboard/cards in the scrollback.
  // (Previously gated on isLatestAssistant, which collapsed earlier
  // analyses into raw markdown the moment the user sent another prompt.)
  const parsed = !isUser && !isLoading
    ? parseStructuredResponse(content, uploadedFiles || [])
    : null;

  const hasFileBlocks = parsed?.some(b => b.type === "file_analysis");
  const repoCtx = hasFileBlocks
    ? deriveRepoContext(parsed, uploadedFiles || [], scannerFindings)
    : null;

  // ... rest of ChatMessage unchanged ...
  return (
    <div style={{ display: "flex", gap: "10px", padding: "14px 16px", alignItems: "flex-start", background: isUser ? "transparent" : "rgba(22,27,34,0.35)", borderBottom: "1px solid #21262d" }}>
      <div style={{ width: "27px", height: "27px", borderRadius: "7px", flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center", background: isUser ? "#1f6feb" : "#238636", color: "#fff" }}>
        {isUser ? <UserIcon /> : <BotIcon />}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: "10px", fontWeight: "700", letterSpacing: "0.6px", color: isUser ? "#79c0ff" : "#2ea043", marginBottom: "7px", textTransform: "uppercase" }}>
          {isUser ? "You" : "AI DevSecOps Sentinel"}
        </div>
        {isLoading ? (
          <div style={{ display: "flex", alignItems: "center", gap: "7px", color: "#8b949e", fontSize: "13px" }}>
            <SpinnerIcon />
            <span>Analysing...</span>
            <div style={{ display: "flex", gap: "3px" }}>
              {[0, 1, 2].map(i => <div key={i} style={{ width: "4px", height: "4px", borderRadius: "50%", background: "#484f58", animation: `bounce 1.2s ${i * 0.2}s infinite` }} />)}
            </div>
          </div>
        ) : hasFileBlocks ? (
          <div>
            {scannerFindings?.length > 0 && (
              <ScannerFindingsPanel findings={scannerFindings} scannersRun={scannersRun} />
            )}
            {repoCtx?.memoryCategories?.length > 0 && (
              <div style={{ background: "rgba(46,160,67,0.05)", border: "1px solid rgba(46,160,67,0.15)", borderRadius: "7px", padding: "8px 12px", marginBottom: "12px", display: "flex", flexWrap: "wrap", alignItems: "center", gap: "6px" }}>
                <span style={{ fontSize: "9px", color: "#2ea043", textTransform: "uppercase", letterSpacing: "0.8px", fontWeight: "700", marginRight: "4px" }}>✓ Context retained:</span>
                {repoCtx.memoryCategories.map((cat, i) => (
                  <span key={i} style={{ background: "rgba(46,160,67,0.1)", border: "1px solid rgba(46,160,67,0.2)", borderRadius: "4px", padding: "2px 8px", fontSize: "10px", color: "#2ea043" }}>{cat}</span>
                ))}
              </div>
            )}
            <Dashboard blocks={parsed} scannerFindings={scannerFindings} />
            <AttackSurfacePanel blocks={parsed} />
            {parsed.map((block, i) =>
              block.type === "file_analysis"
                ? <FileAnalysisCard key={i} block={block} />
                : <MarkdownBlock key={i} text={block.content} />
            )}
            {onSend && <FollowUpSuggestions blocks={parsed} onSend={onSend} />}
            {onSend && <DownloadReportButton blocks={parsed} repoCtx={repoCtx} uploadedFiles={uploadedFiles || []} scannerFindings={scannerFindings} repo={repo} scannersRun={scannersRun} filesScanned={filesScanned} />}
          </div>
        ) : (
          <div>
            {/* Targeted action responses (quick actions, follow-ups,
                sidebar links) carry verified findings but often no per-file
                blocks — render the same dashboard + findings header so the
                UI is uniform across every response, not a plain wall. */}
            {scannerFindings?.length > 0 && (
              <>
                <ScannerFindingsPanel findings={scannerFindings} scannersRun={scannersRun} />
                <Dashboard blocks={parsed || []} scannerFindings={scannerFindings} />
              </>
            )}
            <MarkdownBlock text={content} />
            {isLatestAssistant && repo && onSend && <RepoFollowUps onSend={onSend} />}
            {onSend && scannerFindings?.length > 0 && (
              <DownloadReportButton blocks={[]} repoCtx={null} uploadedFiles={uploadedFiles || []} scannerFindings={scannerFindings} repo={repo} scannersRun={scannersRun} filesScanned={filesScanned} />
            )}
          </div>
        )}
      </div>
    </div>
  );
}
// =========================================================
// REPO CONTEXT HEADER
// =========================================================

function RepoContextHeader({ repoCtx, fileCount }) {
  if (!repoCtx && fileCount === 0) return null;
  if (!repoCtx) {
    return (
      <span style={{ background: "#1c2128", border: "1px solid #30363d", borderRadius: "10px", padding: "2px 9px", fontSize: "11px", color: "#2ea043" }}>
        {fileCount} file{fileCount > 1 ? "s" : ""} in context
      </span>
    );
  }
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
      <span style={{ background: "#1c2128", border: "1px solid #30363d", borderRadius: "5px", padding: "3px 9px", fontSize: "11px", color: "#e6edf3", fontWeight: "600", display: "flex", alignItems: "center", gap: "5px" }}>
        <ZipIcon /> {repoCtx.repoName}
      </span>
      <span style={{ background: "#1c2128", border: "1px solid #30363d", borderRadius: "5px", padding: "3px 9px", fontSize: "11px", color: "#8b949e" }}>{repoCtx.fileCount} files</span>
      {repoCtx.counts.CRITICAL > 0 && (
        <span style={{ background: "rgba(255,68,68,0.12)", border: "1px solid rgba(255,68,68,0.3)", borderRadius: "5px", padding: "3px 9px", fontSize: "11px", color: "#ff4444", fontWeight: "700" }}>
          {repoCtx.counts.CRITICAL} critical
        </span>
      )}
      {repoCtx.counts.HIGH > 0 && (
        <span style={{ background: "rgba(255,136,0,0.1)", border: "1px solid rgba(255,136,0,0.3)", borderRadius: "5px", padding: "3px 9px", fontSize: "11px", color: "#ff8800", fontWeight: "700" }}>
          {repoCtx.counts.HIGH} high
        </span>
      )}
      {repoCtx.counts.SECRETS > 0 && (
        <span style={{ background: "rgba(255,68,68,0.1)", border: "1px solid rgba(255,68,68,0.25)", borderRadius: "5px", padding: "3px 9px", fontSize: "11px", color: "#ff4444" }}>
          🔑 {repoCtx.counts.SECRETS} secrets
        </span>
      )}
      {repoCtx.stack.slice(0, 3).map(s => (
        <span key={s} style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "5px", padding: "3px 8px", fontSize: "10px", color: "#8b949e" }}>{s}</span>
      ))}
    </div>
  );
}

// =========================================================
// QUICK ACTION CHIPS — stack-aware
// =========================================================

function QuickActionChips({ onSend, uploadedFiles }) {
  const actions = getStackAwareQuickActions(uploadedFiles || []);
  return (
    <div style={{ padding: "10px 16px", borderBottom: "1px solid #21262d", background: "rgba(22,27,34,0.3)" }}>
      <div style={{ fontSize: "9px", color: "#484f58", textTransform: "uppercase", letterSpacing: "1px", marginBottom: "7px" }}>Quick Actions</div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
        {actions.map((a, i) => (
          <button key={i} onClick={() => onSend(a.msg)} style={{
            background: "#161b22", border: "1px solid #30363d",
            borderRadius: "6px", padding: "5px 10px",
            fontSize: "11px", color: "#8b949e", cursor: "pointer", transition: "all 0.15s"
          }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = "#238636"; e.currentTarget.style.color = "#2ea043"; e.currentTarget.style.background = "rgba(35,134,54,0.08)"; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = "#30363d"; e.currentTarget.style.color = "#8b949e"; e.currentTarget.style.background = "#161b22"; }}>
            {a.label}
          </button>
        ))}
      </div>
    </div>
  );
}

// =========================================================
// FILE BADGE
// =========================================================

function FileBadge({ file, onRemove }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "5px", background: "#1c2128", border: "1px solid #30363d", borderRadius: "5px", padding: "3px 8px", fontSize: "11px", color: "#8b949e", maxWidth: "175px" }}>
      {file.name.endsWith(".zip") ? <ZipIcon /> : <FileIcon />}
      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{file.name}</span>
      <button onClick={() => onRemove(file.name)} style={{ background: "transparent", border: "none", cursor: "pointer", color: "#484f58", padding: "0", fontSize: "14px", lineHeight: 1, display: "flex", alignItems: "center" }}>×</button>
    </div>
  );
}

// =========================================================
// SIDEBAR
// =========================================================

const FILE_PROMPTS = [
  "Analyse all files — full security report",
  "Are there hardcoded secrets?",
  "What ports are exposed?",
  "Find all misconfigurations with fixes",
  "Walk me through this repo",
  "Is the CI/CD pipeline secure?",
  "Docker best practices violations?",
  "Kubernetes security context issues?",
  "Check Terraform CIDR blocks",
  "Are images pinned to a digest?",
];
const GENERAL_PROMPTS = [
  "What is DevSecOps?",
  "CI vs CD — what's the difference?",
  "GitOps and ArgoCD explained",
  "Secure Dockerfile best practices",
  "What is shift-left security?",
  "Explain Kubernetes RBAC",
  "How does Terraform manage state?",
  "Prometheus vs Datadog",
  "Zero trust networking explained",
];

function Sidebar({ onPromptClick, uploadedFiles, onFilesAdded, onFileRemove }) {
  const fileInputRef = useRef(null);
  const [tab, setTab] = useState("files");

  return (
    <div style={{ width: "245px", flexShrink: 0, background: "#0d1117", borderRight: "1px solid #21262d", display: "flex", flexDirection: "column", height: "100vh", overflow: "hidden" }}>
      <div style={{ padding: "15px 13px 12px", borderBottom: "1px solid #21262d" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "9px" }}>
          <div style={{ width: "32px", height: "32px", background: "linear-gradient(135deg, #238636 0%, #1f6feb 100%)", borderRadius: "8px", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "15px" }}>⚙️</div>
          <div>
            <div style={{ fontSize: "13px", fontWeight: "700", color: "#e6edf3", letterSpacing: "-0.3px" }}>AI DevSecOps Sentinel</div>
            <div style={{ fontSize: "10px", color: "#2ea043", display: "flex", alignItems: "center", gap: "4px" }}>
              <span style={{ width: "5px", height: "5px", background: "#2ea043", borderRadius: "50%", display: "inline-block", animation: "pulse 2s infinite" }} />
              Online
            </div>
          </div>
        </div>
      </div>

      <div style={{ padding: "10px 12px", borderBottom: "1px solid #21262d" }}>
        <div style={{ fontSize: "9px", fontWeight: "600", color: "#484f58", textTransform: "uppercase", letterSpacing: "1px", marginBottom: "7px" }}>Upload Files</div>
        <button onClick={() => fileInputRef.current?.click()} style={{ width: "100%", padding: "8px", background: "transparent", border: "1px dashed #30363d", borderRadius: "6px", color: "#8b949e", fontSize: "12px", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: "6px", transition: "all 0.2s" }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = "#238636"; e.currentTarget.style.color = "#2ea043"; }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = "#30363d"; e.currentTarget.style.color = "#8b949e"; }}>
          <AttachIcon /> Click or drop files
        </button>
        <input ref={fileInputRef} type="file" multiple style={{ display: "none" }}
          accept=".zip,.py,.pyi,.js,.jsx,.mjs,.cjs,.ts,.tsx,.vue,.svelte,.java,.kt,.kts,.scala,.groovy,.clj,.go,.rs,.rb,.php,.c,.h,.cpp,.cc,.cxx,.hpp,.cs,.swift,.m,.dart,.ex,.exs,.pl,.lua,.r,.sh,.bash,.zsh,.ps1,.yaml,.yml,.tf,.tfvars,.hcl,.json,.json5,.xml,.toml,.ini,.conf,.cfg,.properties,.env,.sql,.gradle,.mod,.sum,.lock,.md,.markdown,.rst,.adoc,.txt"
          onChange={e => { onFilesAdded(Array.from(e.target.files)); e.target.value = ""; }} />
        {uploadedFiles.length > 0 && (
          <div style={{ marginTop: "7px", display: "flex", flexDirection: "column", gap: "4px", maxHeight: "130px", overflowY: "auto" }}>
            {uploadedFiles.map(f => <FileBadge key={f.name} file={f} onRemove={onFileRemove} />)}
          </div>
        )}
        <div style={{ marginTop: "5px", fontSize: "9px", color: "#484f58", lineHeight: "1.5" }}>
          Code (.py, .go, .js/.ts, .java, .rb, .php, .rs, .c/.cpp, …) · IaC (.tf, Dockerfile, .yaml) · CI (Jenkinsfile, workflows) · .zip · repo URL
        </div>
      </div>

      <div style={{ display: "flex", borderBottom: "1px solid #21262d" }}>
        {[["files", "📁 File"], ["general", "🧠 General"]].map(([key, label]) => (
          <button key={key} onClick={() => setTab(key)} style={{ flex: 1, padding: "8px 0", background: "transparent", border: "none", borderBottom: tab === key ? "2px solid #238636" : "2px solid transparent", color: tab === key ? "#2ea043" : "#8b949e", fontSize: "10px", fontWeight: "600", cursor: "pointer", textTransform: "uppercase", letterSpacing: "0.5px", transition: "all 0.2s" }}>{label}</button>
        ))}
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: "7px 9px" }}>
        <div style={{ fontSize: "9px", color: "#484f58", textTransform: "uppercase", letterSpacing: "1px", margin: "5px 4px 7px" }}>{tab === "files" ? "File Analysis" : "Knowledge"}</div>
        {(tab === "files" ? FILE_PROMPTS : GENERAL_PROMPTS).map((p, i) => (
          <button key={i} onClick={() => onPromptClick(p)} style={{ width: "100%", textAlign: "left", background: "transparent", border: "1px solid transparent", borderRadius: "5px", padding: "6px 8px", color: "#8b949e", fontSize: "11px", cursor: "pointer", marginBottom: "2px", lineHeight: "1.4", transition: "all 0.15s" }}
            onMouseEnter={e => { e.currentTarget.style.background = "#161b22"; e.currentTarget.style.borderColor = "#30363d"; e.currentTarget.style.color = "#c9d1d9"; }}
            onMouseLeave={e => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.borderColor = "transparent"; e.currentTarget.style.color = "#8b949e"; }}>
            {p}
          </button>
        ))}
      </div>
    </div>
  );
}

// =========================================================
// MAIN APP
// =========================================================

// =========================================================
// MAIN APP
// =========================================================

export default function App() {
  useFavicon();

  // ── Step 5: Load saved session on first render ─────────
  const _savedSession = loadSessionData();

  const WELCOME_MESSAGE = {
    role: "assistant",
    content: `## Welcome to AI DevSecOps Sentinel

I'm your senior DevOps & DevSecOps AI engineer. Here is what I can do:

**With uploaded files:**
- Full security audit with severity dashboard, expandable per-file cards
- Secret detection — AWS keys, tokens, passwords, private keys
- Evidence-backed findings with exact line numbers and code snippets
- Side-by-side diff blocks showing current (insecure) vs fix (secure)
- Blast radius analysis — what systems are affected by each finding
- Attack surface reasoning — multi-finding chain analysis
- Compliance mapping — CWE, OWASP, NIST, CIS, MITRE per finding
- Follow-up action suggestions after every scan

**General knowledge:**
- CI/CD, Kubernetes, Docker, Terraform, Helm, ArgoCD, GitOps
- DevSecOps, shift-left, zero trust, supply chain security

**Three ways in:**
- **Upload files** — code (any language), IaC, Dockerfiles, CI configs, or a \`.zip\` — via the sidebar
- **Paste a public GitHub repo URL** in the chat box — I'll download, scan, and report on the whole repo
- **Just ask** — DevOps / DevSecOps questions, no files needed`
  };

  const [messages, setMessages] = useState(
    _savedSession?.messages?.length > 0
      ? _savedSession.messages
      : [WELCOME_MESSAGE]
  );

  const [input, setInput]             = useState("");
  const [isLoading, setIsLoading]     = useState(false);

  // Restore file names from session — marked sent:true so they
  // won't be re-uploaded (backend still has them if server
  // hasn't restarted). Actual File objects can't be serialized
  // so content is not restored — only names for UI display.
  const [uploadedFiles, setUploadedFiles] = useState(() => {
    if (_savedSession?.fileNames?.length > 0) {
      return _savedSession.fileNames.map(f =>
        Object.assign(new File([], f.name), { sent: true })
      );
    }
    return [];
  });

  const [history, setHistory]             = useState(_savedSession?.history || []);
  const [repoCtx, setRepoCtx]             = useState(_savedSession?.repoCtx || null);
  // Derived, not state — always mirrors the uploaded file list
  const showQuickActions = uploadedFiles.length > 0;

  const messagesEndRef = useRef(null);
  const textareaRef    = useRef(null);

  // ── Step 6: Wire up session persistence hook ───────────
  useSessionPersistence(messages, uploadedFiles, history, repoCtx);

  // ── Reconcile restored session with backend state ──────
  // The session restore only keeps file NAMES (not contents),
  // marked as already sent. If the backend restarted, its
  // in-memory context is empty and those files can never be
  // re-sent — drop them so the UI doesn't claim context the
  // backend no longer has.
  useEffect(() => {
    fetch("/health", { headers: { "X-Session-Id": SESSION_ID } })
      .then(r => r.json())
      .then(h => {
        if (h.files_in_memory === 0) {
          setUploadedFiles(prev => prev.filter(f => !f.sent));
          setRepoCtx(null);
          _sentFileHashes.clear();
          sessionStorage.removeItem("devops_sentinel_hashes");
        }
      })
      .catch(() => {}); // backend down — the send path reports that itself
  }, []);

  useEffect(() => { messagesEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 160) + "px";
    }
  }, [input]);

  // =========================================================
  // FILE MANAGEMENT
  // =========================================================

  const handleFilesAdded = (newFiles) => {
    setUploadedFiles(prev => {
      const existingNames = new Set(prev.map(f => f.name));
      const toAdd = newFiles
        .filter(f => !existingNames.has(f.name))
        .map(f => Object.assign(f, { sent: isFileAlreadySent(f) }));
      return [...prev, ...toAdd];
    });
  };

  // =========================================================
  // SEND MESSAGE
  // =========================================================

  const handleSend = async (override) => {
    const text = (override || input).trim();
    if (!text || isLoading) return;
    setInput("");
    setMessages(prev => [...prev,
      { role: "user", content: text },
      { role: "assistant", content: "", isLoading: true }
    ]);
    setIsLoading(true);

    const filesToSend = uploadedFiles.filter(f => !f.sent);

    try {
      const encodedFiles = await encodeFiles(filesToSend);
      const res = await fetch(FASTAPI_URL, {
        method: "POST",
        headers: API_HEADERS,
        body: JSON.stringify({ message: text, history, files: encodedFiles })
      });
      if (!res.ok) throw new Error(`Backend error ${res.status}`);
      let data = await res.json();

      // Async repo ingest: the first response is just a job_id. Show
      // live progress in the pending bubble, then poll for the result.
      if (data.job_id && data.status === "running") {
        const showPhase = (phase) => setMessages(prev => {
          const u = [...prev];
          u[u.length - 1] = {
            role: "assistant",
            content: `${data.response}\n\n_${PHASE_LABEL[phase] || "working…"}_`,
            isLoading: true,
          };
          return u;
        });
        showPhase("starting");
        data = await pollScanJob(data.job_id, showPhase);
      }

      const answer = data.response || "No response received.";
      setHistory(prev => [...prev, [text, answer]]);

      // GitHub repo ingested server-side — surface it in the sidebar
      // as an already-sent entry so the ✕ removal endpoint works on it
      if (data.repo?.zip_name) {
        setUploadedFiles(prev =>
          prev.some(f => f.name === data.repo.zip_name)
            ? prev
            : [...prev, { name: data.repo.zip_name, sent: true, isRepo: true }]
        );
      }

      if (filesToSend.length > 0) {
        filesToSend.forEach(markFileAsSent);
        setUploadedFiles(prev =>
          prev.map(f => filesToSend.some(s => s.name === f.name)
            ? Object.assign(f, { sent: true })
            : f
          )
        );
      }

      const parsed = parseStructuredResponse(answer, uploadedFiles);
      if (parsed) {
        const ctx = deriveRepoContext(parsed, uploadedFiles, data.findings || []);
        if (ctx) setRepoCtx(ctx);
      }

      setMessages(prev => {
        const u = [...prev];
        u[u.length - 1] = {
          role: "assistant",
          content: answer,
          scannerFindings: data.findings || [],
          scannersRun: data.scanners?.run || [],
          repo: data.repo || null,
          filesScanned: data.files_scanned ?? data.repo?.files ?? null,
        };
        return u;
      });
    } catch (err) {
      const msg = err.message.includes("Failed to fetch")
        ? "⚠️ **Cannot connect to backend.**\n\n```bash\nuvicorn backend.main:app --reload --port 8000\n```"
        : `❌ **Error:** ${err.message}`;
      setMessages(prev => {
        const u = [...prev];
        u[u.length - 1] = { role: "assistant", content: msg };
        return u;
      });
    } finally { setIsLoading(false); }
  };

  const handleClear = () => {
    setMessages([WELCOME_MESSAGE]);
    setHistory([]);
    setUploadedFiles([]);
    setRepoCtx(null);
    sessionStorage.removeItem("devops_sentinel_session");
    sessionStorage.removeItem("devops_sentinel_hashes");
    _sentFileHashes.clear();
  };

  return (
    <>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0d1117; color: #e6edf3; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; overflow: hidden; }
        @keyframes spin   { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes pulse  { 0%,100% { opacity:1; } 50% { opacity:0.3; } }
        @keyframes bounce { 0%,80%,100% { transform:scale(0); } 40% { transform:scale(1); } }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }
        textarea { font-family: inherit; }
      `}</style>

      <div style={{ display: "flex", height: "100vh", overflow: "hidden" }}
        onDragOver={e => e.preventDefault()}
        onDrop={e => { e.preventDefault(); handleFilesAdded(Array.from(e.dataTransfer.files)); }}>

        <Sidebar
          onPromptClick={handleSend}
          uploadedFiles={uploadedFiles}
          onFilesAdded={handleFilesAdded}
          onFileRemove={name => {
            const file = uploadedFiles.find(f => f.name === name);
            if (file) unmarkFileAsSent(file);
            setUploadedFiles(prev => prev.filter(f => f.name !== name));
            // Sync the backend: drop from memory/workspace/RAG + rescan
            fetch("/remove-file", {
              method: "POST",
              headers: API_HEADERS,
              body: JSON.stringify({ name }),
            }).catch(() => {});
          }}
        />

        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>

          {/* Top bar */}
          <div style={{ padding: "8px 16px", borderBottom: "1px solid #21262d", display: "flex", alignItems: "center", justifyContent: "space-between", minHeight: "44px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", flex: 1, flexWrap: "wrap" }}>
              <span style={{ fontSize: "13px", fontWeight: "600", color: "#e6edf3", marginRight: "4px" }}>Chat</span>
              <RepoContextHeader repoCtx={repoCtx} fileCount={uploadedFiles.length} />
            </div>
            <button onClick={handleClear}
              style={{ background: "transparent", border: "1px solid #30363d", borderRadius: "5px", color: "#8b949e", fontSize: "12px", padding: "4px 10px", cursor: "pointer", display: "flex", alignItems: "center", gap: "5px", transition: "all 0.2s", flexShrink: 0 }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = "#da3633"; e.currentTarget.style.color = "#da3633"; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = "#30363d"; e.currentTarget.style.color = "#8b949e"; }}>
              <ClearIcon /> Clear
            </button>
          </div>

          {/* Stack-aware quick action chips */}
          {showQuickActions && (
            <QuickActionChips onSend={handleSend} uploadedFiles={uploadedFiles} />
          )}

          {/* Messages */}
          <div style={{ flex: 1, overflowY: "auto" }}>
            {messages.map((msg, i) => {
              const isLatestAssistant =
                msg.role === "assistant" &&
                !msg.isLoading &&
                !messages.slice(i + 1).some(m => m.role === "assistant" && !m.isLoading);

              return (
                <ChatMessage
                  key={i}
                  role={msg.role}
                  content={msg.content}
                  isLoading={msg.isLoading}
                  onSend={handleSend}
                  uploadedFiles={uploadedFiles}
                  isLatestAssistant={isLatestAssistant}
                  scannerFindings={msg.scannerFindings}
                  scannersRun={msg.scannersRun}
                  repo={msg.repo}
                  filesScanned={msg.filesScanned}
                />
              );
            })}
            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <div style={{ padding: "12px 16px", borderTop: "1px solid #21262d" }}>
            <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "9px", overflow: "hidden" }}>
              <textarea
                ref={textareaRef}
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); } }}
                placeholder="Ask anything — upload files or paste a GitHub repo URL for a full security audit..."
                disabled={isLoading}
                rows={1}
                style={{ width: "100%", background: "transparent", border: "none", outline: "none", color: "#e6edf3", fontSize: "14px", lineHeight: "1.6", padding: "12px 14px", resize: "none", display: "block" }}
              />
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 10px", borderTop: "1px solid #21262d" }}>
                <span style={{ fontSize: "10px", color: "#484f58" }}>Enter to send · Shift+Enter newline · Drag & drop files anywhere</span>
                <button onClick={() => handleSend()} disabled={isLoading || !input.trim()}
                  style={{ background: isLoading || !input.trim() ? "#1c2128" : "#238636", border: "none", borderRadius: "6px", color: isLoading || !input.trim() ? "#484f58" : "#fff", fontSize: "12px", fontWeight: "600", padding: "5px 13px", cursor: isLoading || !input.trim() ? "not-allowed" : "pointer", display: "flex", alignItems: "center", gap: "5px", transition: "all 0.2s" }}>
                  {isLoading ? <SpinnerIcon /> : <SendIcon />}
                  {isLoading ? "Analysing..." : "Send"}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}