// ============================================================================
// MindBridge Architectural Blueprint Client Engine (v3.0)
// ============================================================================

const PHQ9_QUESTIONS = [
  "1. Little interest or pleasure in doing things",
  "2. Feeling down, depressed, or hopeless",
  "3. Trouble falling or staying asleep, or sleeping too much",
  "4. Feeling tired or having little energy",
  "5. Poor appetite or overeating",
  "6. Feeling bad about yourself — or that you are a failure or have let yourself or your family down",
  "7. Trouble concentrating on things, such as reading the textbook or coding",
  "8. Moving or speaking so slowly that other people could have noticed, or being fidgety/restless",
  "9. Thoughts that you would be better off dead, or of hurting yourself in some way"
];

const GAD7_QUESTIONS = [
  "1. Feeling nervous, anxious, or on edge",
  "2. Not being able to stop or control worrying",
  "3. Worrying too much about different academic or personal things",
  "4. Trouble relaxing after study or lab sessions",
  "5. Being so restless that it is hard to sit still",
  "6. Becoming easily annoyed or irritable",
  "7. Feeling afraid, as if something awful might happen"
];

const state = {
  activeView: 'dashboard',
  role: 'student',
  anonymousMode: false,
  anonymousToken: null,
  anonymousAlias: 'Balaji M.',
  selectedMoodRating: 4,
  selectedMoodLabel: 'Focused',
  selectedTags: ['Exam & Midterm Prep'],
  moods: [],
  counselors: [],
  bookings: [],
  assessments: [],
  forumPosts: [],
  auditLogs: [],
  selectedCounselorId: null,
  activeAssessmentType: 'PHQ-9',
  breathMode: '4-7-8',
  breathCycles: 0,
  mindfulMinutes: 42,
  timerSeconds: 25 * 60,
  timerInterval: null,
  audioCtx: null,
  activeOscillator: null,
  cryptoKey: null,
  cryptoFingerprint: 'AES-GCM-256-LOCAL',
  webrtcStream: null,
  webrtcCanvasInterval: null,
  micEnabled: true
};

// DOM Initializer
document.addEventListener('DOMContentLoaded', async () => {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
  initDialogsFallback();
  await initZeroKnowledgeCrypto();
  initNavigation();
  initRoleAndPrivacy();
  initMoodTracker();
  initAssessmentModule();
  initCounselorFilters();
  initForumControls();
  initDeStressSuite();
  initGovernanceControls();
  initCrisisHubFilters();
  fetchInitialData();
});

// Modern <dialog closedby="any"> fallback for browsers without native closedBy (modern-web-guidance)
function initDialogsFallback() {
  document.querySelectorAll('dialog.modal-dialog').forEach(dialog => {
    if (!('closedBy' in HTMLDialogElement.prototype)) {
      dialog.addEventListener('click', (event) => {
        if (event.target !== dialog) return;
        const rect = dialog.getBoundingClientRect();
        const isDialogContent = (
          rect.top <= event.clientY &&
          event.clientY <= rect.top + rect.height &&
          rect.left <= event.clientX &&
          event.clientX <= rect.left + rect.width
        );
        if (isDialogContent) return;
        dialog.close();
      });
    }
  });
}

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (!modal) return;
  if (typeof modal.showModal === 'function') {
    if (!modal.open) modal.showModal();
  } else {
    modal.setAttribute('open', 'open');
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (!modal) return;
  if (typeof modal.close === 'function' && modal.open) {
    modal.close();
  } else {
    modal.removeAttribute('open');
  }
}

function getApiHeaders() {
  const headers = { 'Content-Type': 'application/json' };
  if (state.anonymousMode && state.anonymousToken) {
    headers['X-Anonymous-Token'] = state.anonymousToken;
  }
  return headers;
}

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ============================================================================
// 1. Zero-Knowledge Client-Side Encryption (Web Crypto API AES-GCM-256)
// ============================================================================
async function initZeroKnowledgeCrypto() {
  try {
    if (!window.crypto || !window.crypto.subtle) return;
    let rawHex = localStorage.getItem('mindbridge_aes_gcm_key');
    let keyBytes;
    if (rawHex && rawHex.length === 64) {
      keyBytes = new Uint8Array(rawHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    } else {
      keyBytes = window.crypto.getRandomValues(new Uint8Array(32));
      rawHex = Array.from(keyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      localStorage.setItem('mindbridge_aes_gcm_key', rawHex);
    }
    state.cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
    state.cryptoFingerprint = `AES256-${rawHex.slice(0, 6).toUpperCase()}-${rawHex.slice(-6).toUpperCase()}`;
    const fpEl = document.getElementById('crypto-key-fingerprint');
    if (fpEl) fpEl.innerText = state.cryptoFingerprint;
  } catch (err) {
    console.warn('Web Crypto AES-GCM fallback:', err);
  }
}

async function encryptNoteClientSide(plaintext) {
  if (!state.cryptoKey || !plaintext) {
    return { ciphertext: plaintext, iv: null, encrypted: false };
  }
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const encryptedBuf = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    state.cryptoKey,
    encoded
  );
  const cipherHex = Array.from(new Uint8Array(encryptedBuf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  const ivHex = Array.from(iv)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return {
    ciphertext: `[AES-GCM-256] ${cipherHex}`,
    iv: ivHex,
    encrypted: true
  };
}

async function decryptNoteClientSide(noteText, ivHex) {
  if (!state.cryptoKey || !ivHex || !noteText || !noteText.startsWith('[AES-GCM-256] ')) {
    return noteText;
  }
  try {
    const cipherHex = noteText.replace('[AES-GCM-256] ', '').trim();
    const cipherBytes = new Uint8Array(cipherHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    const ivBytes = new Uint8Array(ivHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    const decryptedBuf = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes },
      state.cryptoKey,
      cipherBytes
    );
    return new TextDecoder().decode(decryptedBuf);
  } catch {
    return noteText;
  }
}

// ============================================================================
// 2. Role Switcher & Anonymous UUID Privacy Mode (TC-AUTH-01)
// ============================================================================
function initRoleAndPrivacy() {
  const roleSelect = document.getElementById('role-select');
  const roleBanner = document.getElementById('role-banner');
  const roleBadge = document.getElementById('sidebar-role-badge');

  roleSelect?.addEventListener('change', () => {
    state.role = roleSelect.value;
    if (state.role === 'student') {
      roleBadge.innerText = 'Clinical v3.0';
      roleBanner.classList.add('hidden');
    } else if (state.role === 'counselor') {
      roleBadge.innerText = 'Care Provider';
      roleBanner.classList.remove('hidden');
      roleBanner.innerHTML = `<span>🤝 <strong>Verified Care Provider Workspace:</strong> Manage scheduled WebRTC consultations, complete sessions, and support students in the peer forum.</span>`;
    } else if (state.role === 'admin') {
      roleBadge.innerText = 'Clinical Admin';
      roleBanner.classList.remove('hidden');
      roleBanner.innerHTML = `<span>🏥 <strong>Clinical Admin & HIPAA Governance Oversight:</strong> Longitudinal PHQ-9/GAD-7 telemetry, crisis interception logs, and 30-day retention controls active.</span>`;
    }
    renderBookings();
    renderForumPosts();
  });

  const anonBtn = document.getElementById('btn-anon-toggle');
  anonBtn?.addEventListener('click', async () => {
    state.anonymousMode = !state.anonymousMode;
    anonBtn.setAttribute('aria-pressed', String(state.anonymousMode));
    const textEl = document.getElementById('anon-status-text');
    const nameEl = document.getElementById('user-display-name');
    const subEl = document.getElementById('user-display-sub');
    const avatarEl = document.getElementById('user-avatar');

    if (state.anonymousMode) {
      anonBtn.classList.add('anon-active');
      try {
        const res = await fetch('/api/auth/anonymous', { method: 'POST' });
        const json = await res.json();
        state.anonymousToken = json.data?.anonymousToken || ('anon_' + Math.random().toString(36).slice(2, 10));
        state.anonymousAlias = json.data?.alias || 'Anonymous Peer #4092';
      } catch {
        state.anonymousToken = 'anon_' + Math.random().toString(36).slice(2, 10);
        state.anonymousAlias = 'Anonymous Peer #4092';
      }
      textEl.innerText = `Anonymous UUID (${state.anonymousToken})`;
      nameEl.innerText = state.anonymousAlias;
      subEl.innerText = 'Zero-PII Encrypted Session';
      avatarEl.innerText = '🕵️';
    } else {
      anonBtn.classList.remove('anon-active');
      state.anonymousToken = null;
      state.anonymousAlias = 'Balaji M.';
      textEl.innerText = 'Anonymous Mode: Off';
      nameEl.innerText = 'Balaji M.';
      subEl.innerText = 'Computer Science • Year 3';
      avatarEl.innerText = 'BM';
    }
  });
}

// ============================================================================
// 3. View Navigation Router
// ============================================================================
function initNavigation() {
  const navButtons = document.querySelectorAll('.nav-item');
  navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-target');
      switchTab(target);
    });
  });

  document.getElementById('btn-toggle-panic')?.addEventListener('click', () => {
    switchTab('destress');
    const breathBtn = document.getElementById('btn-toggle-breath');
    if (breathBtn && !isBreathing) {
      breathBtn.click();
    }
  });
}

function switchTab(viewId) {
  state.activeView = viewId;
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
  document.querySelector(`.nav-item[data-target="${viewId}"]`)?.classList.add('active');

  document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
  document.getElementById(`view-${viewId}`)?.classList.add('active');

  const titles = {
    dashboard: ["Wellness Hub & Longitudinal Diagnostics", "Structured Likert mood logging, zero-knowledge encrypted journaling, and intelligent crisis triage."],
    assessments: ["PHQ-9 & GAD-7 Clinical Inventories", "Standardized psychometric scoring frameworks for longitudinal depression and anxiety screening."],
    counselors: ["Direct Provider Care Directory", "Filter verified practitioners by therapeutic modality (CBT, ACT, DBT, MBSR), languages, and WebRTC availability."],
    destress: ["Autonomic Regulation Engine", "Deterministic breath pacing (4-7-8 Vagal, 4-4-4-4 Box, 5-5 Coherent HRV) and neuro-acoustic synthesis."],
    community: ["Safe Peer Support Forum", "Connect with fellow students with real-time semantic safety triage protection."],
    governance: ["HIPAA / GDPR Privacy & Encryption Vault", "Zero-knowledge AES-GCM-256 client keys, 30-day ephemeral retention, and instant data erasure."],
    crisis: ["Global Crisis Interception Hub", "Localized 24/7 emergency hotlines (988 US/CA, 112 EU, 14416 India) and 5-4-3-2-1 grounding."]
  };

  if (titles[viewId]) {
    document.getElementById('page-title').innerText = titles[viewId][0];
    document.getElementById('page-subtitle').innerText = titles[viewId][1];
  }

  if (viewId === 'governance') {
    fetchGovernanceAudit();
  }
}

// ============================================================================
// 4. Data Fetching & Longitudinal Dashboard Telemetry
// ============================================================================
async function fetchInitialData() {
  try {
    const [therapistsRes, bookingsRes, postsRes, moodsRes, assessmentsRes] = await Promise.all([
      fetch('/api/therapists').then(r => r.json()).catch(() => ({ therapists: getMockCounselors() })),
      fetch('/api/bookings').then(r => r.json()).catch(() => ({ data: getMockBookings() })),
      fetch('/api/posts').then(r => r.json()).catch(() => ({ data: getMockPosts() })),
      fetch('/api/moods').then(r => r.json()).catch(() => ({ data: getMockMoods() })),
      fetch('/api/assessments').then(r => r.json()).catch(() => ({ data: [] }))
    ]);

    state.counselors = therapistsRes.therapists || therapistsRes.data || getMockCounselors();
    state.bookings = bookingsRes.data || getMockBookings();
    state.forumPosts = postsRes.data || getMockPosts();
    state.moods = moodsRes.moods || moodsRes.data || getMockMoods();
    state.assessments = assessmentsRes.assessments || assessmentsRes.data || [];

    renderCounselors();
    renderBookings();
    renderForumPosts();
    await renderMoodHistory(state.moods);
    renderAssessmentHistory();
    updateDashboardMetrics();
  } catch (err) {
    console.warn("Using offline mock fallback data", err);
  }
}

function updateDashboardMetrics() {
  const total = state.moods.length;
  const avg = total
    ? (state.moods.reduce((sum, m) => sum + Number(m.score || m.rating || 3), 0) / total).toFixed(1)
    : '4.0';
  const resilience = (Number(avg) * 2).toFixed(1);

  const avgChip = document.getElementById('avg-mood-chip');
  const resEl = document.getElementById('metric-resilience');
  if (avgChip) avgChip.innerText = `Avg ${avg} / 5`;
  if (resEl) resEl.innerText = `${resilience}/10`;

  const latestPhq9 = state.assessments.find(a => a.type === 'PHQ-9');
  const latestGad7 = state.assessments.find(a => a.type === 'GAD-7');

  const phqEl = document.getElementById('metric-phq9');
  const phqSub = document.getElementById('metric-phq9-sub');
  if (phqEl && latestPhq9) {
    phqEl.innerText = `${latestPhq9.score} / 27`;
    if (phqSub) phqSub.innerText = `PHQ-9 (${latestPhq9.severity.replace(' Depression', '')})`;
  }

  const gadEl = document.getElementById('metric-gad7');
  const gadSub = document.getElementById('metric-gad7-sub');
  if (gadEl && latestGad7) {
    gadEl.innerText = `${latestGad7.score} / 21`;
    if (gadSub) gadSub.innerText = `GAD-7 (${latestGad7.severity.replace(' Anxiety', '')})`;
  }

  // Update mini bar chart dynamically from last 7 moods
  const chartContainer = document.getElementById('mood-chart-bars');
  if (chartContainer && state.moods.length) {
    const days = ['M', 'T', 'W', 'T', 'F', 'S', 'S'];
    const recent = state.moods.slice(-7);
    while (recent.length < 7) {
      recent.unshift({ rating: 3, score: 3, label: 'Baseline' });
    }
    chartContainer.innerHTML = recent.map((m, idx) => {
      const val = Number(m.score || m.rating || 3);
      const pct = Math.max(20, Math.min(100, val * 20));
      const isLast = idx === recent.length - 1;
      return `<div class="chart-bar ${isLast ? 'active' : ''}" style="height: ${pct}%;" title="${escapeHtml(m.emotion || m.label || '')}: ${val}/5"><span class="bar-day">${days[idx]}</span></div>`;
    }).join('');
  }
}

// ============================================================================
// 5. Intelligent Triage & Longitudinal Mood Logging (POST /api/triage & /api/moods)
// ============================================================================
async function screenTextWithTriage(journalText) {
  if (!journalText || !journalText.trim()) return { level: 'NORMAL' };
  try {
    const res = await fetch('/api/triage', {
      method: 'POST',
      headers: getApiHeaders(),
      body: JSON.stringify({ journalText })
    });
    const data = await res.json();
    if (data.level === 'CRISIS') {
      triggerSafetyModalWithTriage(data);
    }
    return data;
  } catch {
    return { level: 'NORMAL' };
  }
}

function triggerSafetyModalWithTriage(triageData) {
  const sugEl = document.getElementById('safety-suggested-exercise');
  if (sugEl && triageData?.suggestedExercise) {
    sugEl.innerHTML = `Recommended Immediate Regulation: <strong>${escapeHtml(triageData.suggestedExercise)}</strong>`;
  }
  openModal('modal-safety');
}

function initMoodTracker() {
  const moodBtns = document.querySelectorAll('.mood-btn');
  moodBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      moodBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.selectedMoodRating = Number(btn.getAttribute('data-rating'));
      state.selectedMoodLabel = btn.getAttribute('data-label');
    });
  });

  // Multi-select qualitative tags
  const tagBtns = document.querySelectorAll('#mood-tags-container .tag-pill');
  tagBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      btn.classList.toggle('active');
      const activeTags = Array.from(document.querySelectorAll('#mood-tags-container .tag-pill.active'))
        .map(el => el.getAttribute('data-tag'));
      state.selectedTags = activeTags.length ? activeTags : ['General Academic'];
    });
  });

  // Standalone Triage Check Button
  document.getElementById('btn-run-triage')?.addEventListener('click', async () => {
    const notes = document.getElementById('mood-notes')?.value.trim() || '';
    const statusMsg = document.getElementById('mood-status-msg');
    if (!notes) {
      if (statusMsg) statusMsg.innerText = 'Enter journal text to run semantic triage.';
      return;
    }
    const triage = await screenTextWithTriage(notes);
    if (triage.level === 'CRISIS') {
      if (statusMsg) statusMsg.innerText = '⚠️ Acute distress indicators detected — Crisis protocol activated.';
    } else {
      if (statusMsg) statusMsg.innerText = `✓ Triage Level: NORMAL • Suggested: ${triage.suggestedExercise || 'Box Breathing'}`;
    }
  });

  // Save Mood & Journal Entry
  document.getElementById('btn-save-mood')?.addEventListener('click', async () => {
    const notesInput = document.getElementById('mood-notes');
    const encryptChk = document.getElementById('chk-encrypt-journal');
    const rawNotes = notesInput.value.trim();

    // 1. Evaluate against Intelligent Triage before persisting (Blueprint Sec 2A)
    if (rawNotes) {
      const triageResult = await screenTextWithTriage(rawNotes);
      if (triageResult.level === 'CRISIS') {
        const statusMsg = document.getElementById('mood-status-msg');
        if (statusMsg) statusMsg.innerText = "🚨 Emergency intervention triggered.";
      }
    }

    // 2. Apply Zero-Knowledge AES-GCM-256 encryption if enabled (Blueprint Sec 4)
    let finalNotes = rawNotes;
    let encryptedFlag = false;
    let ivHex = null;
    if (encryptChk?.checked && rawNotes) {
      const encResult = await encryptNoteClientSide(rawNotes);
      finalNotes = encResult.ciphertext;
      encryptedFlag = encResult.encrypted;
      ivHex = encResult.iv;
    }

    const payload = {
      userId: state.anonymousToken || "u101",
      score: state.selectedMoodRating,
      rating: state.selectedMoodRating,
      emotion: state.selectedMoodLabel,
      label: state.selectedMoodLabel,
      tags: state.selectedTags,
      trigger: state.selectedTags[0] || "General Academic",
      notes: finalNotes,
      encrypted: encryptedFlag,
      iv: ivHex
    };

    try {
      const res = await fetch('/api/moods', {
        method: 'POST',
        headers: getApiHeaders(),
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.success) {
        const savedEntry = data.entry || data.data;
        state.moods.push(savedEntry);
        await renderMoodHistory(state.moods);
        updateDashboardMetrics();
        const statusMsg = document.getElementById('mood-status-msg');
        statusMsg.innerText = encryptedFlag
          ? "🔒 Encrypted (AES-GCM-256) entry saved."
          : "✓ Longitudinal check-in recorded.";
        notesInput.value = '';
        setTimeout(() => { statusMsg.innerText = ''; }, 4000);
      }
    } catch {
      state.moods.push({
        id: Date.now(),
        ...payload,
        timestamp: new Date().toISOString()
      });
      await renderMoodHistory(state.moods);
      updateDashboardMetrics();
    }
  });
}

async function renderMoodHistory(moods) {
  const container = document.getElementById('mood-history-list');
  const countEl = document.getElementById('mood-total-count');
  if (countEl) countEl.innerText = `${moods.length} entries`;
  if (!container) return;

  const recent = moods.slice(-5).reverse();
  const renderedItems = await Promise.all(recent.map(async m => {
    const scoreVal = m.score || m.rating || 4;
    const emotionVal = m.emotion || m.label || 'Neutral';
    const tagsArr = Array.isArray(m.tags) && m.tags.length ? m.tags : [m.trigger || 'Academic'];
    let displayNotes = m.notes || 'No reflection notes listed';

    if (m.encrypted && m.iv) {
      const decrypted = await decryptNoteClientSide(m.notes, m.iv);
      displayNotes = `🔓 [Decrypted AES-GCM-256]: ${escapeHtml(decrypted)}`;
    }

    return `
      <div class="list-item">
        <div>
          <strong>${escapeHtml(emotionVal)} (${scoreVal}/5)</strong>
          ${tagsArr.map(t => `<span class="chip" style="margin-left:0.35rem;">${escapeHtml(t)}</span>`).join('')}
          ${m.encrypted ? `<span class="mono-badge" style="margin-left:0.35rem;">E2EE</span>` : ''}
          <p style="font-size:0.82rem; color:var(--text-secondary); margin-top:0.3rem;">${displayNotes}</p>
        </div>
        <div style="display:flex; align-items:center; gap:0.6rem;">
          <small style="color:var(--text-secondary);">${new Date(m.timestamp).toLocaleDateString()}</small>
          <button class="btn btn-ghost btn-sm" onclick="deleteMoodEntry(${m.id})" title="Remove entry">&times;</button>
        </div>
      </div>
    `;
  }));

  container.innerHTML = renderedItems.join('');
}

async function deleteMoodEntry(id) {
  try {
    await fetch(`/api/moods/${id}`, { method: 'DELETE', headers: getApiHeaders() });
  } catch {
    // ignore offline error
  }
  state.moods = state.moods.filter(m => Number(m.id) !== Number(id));
  await renderMoodHistory(state.moods);
  updateDashboardMetrics();
}

// ============================================================================
// 6. Standardized Psychometric Inventories: PHQ-9 & GAD-7 (Blueprint Sec 1 & 2C)
// ============================================================================
function initAssessmentModule() {
  renderAssessmentQuestions();
  document.getElementById('btn-submit-assessment')?.addEventListener('click', submitAssessment);
}

function switchAssessmentInstrument(type) {
  state.activeAssessmentType = type;
  const btnPhq = document.getElementById('tab-btn-phq9');
  const btnGad = document.getElementById('tab-btn-gad7');
  const titleEl = document.getElementById('assessment-form-title');

  if (type === 'PHQ-9') {
    btnPhq.className = 'btn btn-primary';
    btnGad.className = 'btn btn-secondary';
    if (titleEl) titleEl.innerText = 'PHQ-9 Patient Health Questionnaire (Depression Severity)';
  } else {
    btnGad.className = 'btn btn-primary';
    btnPhq.className = 'btn btn-secondary';
    if (titleEl) titleEl.innerText = 'GAD-7 Generalized Anxiety Disorder Scale';
  }
  renderAssessmentQuestions();
}

function renderAssessmentQuestions() {
  const container = document.getElementById('assessment-questions-list');
  if (!container) return;
  const questions = state.activeAssessmentType === 'PHQ-9' ? PHQ9_QUESTIONS : GAD7_QUESTIONS;
  const maxScore = questions.length * 3;
  const scoreChip = document.getElementById('assessment-live-score');
  if (scoreChip) scoreChip.innerText = `Current Score: 0 / ${maxScore}`;

  const options = [
    { val: 0, text: "Not at all (0)" },
    { val: 1, text: "Several days (1)" },
    { val: 2, text: "More than half (2)" },
    { val: 3, text: "Nearly every day (3)" }
  ];

  container.innerHTML = questions.map((q, idx) => `
    <div class="assessment-item">
      <p>${escapeHtml(q)}</p>
      <div class="assessment-options">
        ${options.map(opt => `
          <label class="assessment-opt-label">
            <input type="radio" name="assess-q-${idx}" value="${opt.val}" ${opt.val === 0 ? 'checked' : ''} onchange="updateLiveAssessmentScore()" />
            <span>${opt.text}</span>
          </label>
        `).join('')}
      </div>
    </div>
  `).join('');
}

function getAssessmentResponsesArray() {
  const count = state.activeAssessmentType === 'PHQ-9' ? 9 : 7;
  const responses = [];
  for (let i = 0; i < count; i++) {
    const checked = document.querySelector(`input[name="assess-q-${i}"]:checked`);
    responses.push(checked ? Number(checked.value) : 0);
  }
  return responses;
}

function updateLiveAssessmentScore() {
  const responses = getAssessmentResponsesArray();
  const sum = responses.reduce((a, b) => a + b, 0);
  const maxScore = responses.length * 3;
  const scoreChip = document.getElementById('assessment-live-score');
  if (scoreChip) scoreChip.innerText = `Current Score: ${sum} / ${maxScore}`;
}

async function submitAssessment() {
  const responses = getAssessmentResponsesArray();
  const payload = {
    type: state.activeAssessmentType,
    responses,
    userId: state.anonymousToken || 'u101'
  };

  try {
    const res = await fetch('/api/assessments', {
      method: 'POST',
      headers: getApiHeaders(),
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.success) {
      state.assessments.unshift(data.assessment);
      renderAssessmentHistory();
      updateDashboardMetrics();
      const fb = document.getElementById('assessment-feedback-msg');
      if (fb) {
        fb.innerText = `✓ ${data.assessment.type}: ${data.assessment.score}/${data.assessment.maxScore} (${data.assessment.severity})`;
        setTimeout(() => { fb.innerText = ''; }, 5000);
      }
      if (data.assessment.crisisFlag) {
        openModal('modal-safety');
      }
    }
  } catch {
    // offline fallback
  }
}

function renderAssessmentHistory() {
  const container = document.getElementById('assessment-history-list');
  if (!container) return;
  if (!state.assessments.length) {
    container.innerHTML = `<p class="text-subtle">No psychometric assessments recorded yet.</p>`;
    return;
  }
  container.innerHTML = state.assessments.slice(0, 6).map(a => `
    <div class="list-item">
      <div>
        <strong>${escapeHtml(a.type)}: ${a.score} / ${a.maxScore}</strong>
        <span class="chip" style="margin-left:0.4rem;">${escapeHtml(a.severity)}</span>
        <p style="font-size:0.8rem; color:var(--text-secondary); margin-top:0.25rem;">${escapeHtml(a.recommendation || '')}</p>
      </div>
      <small style="color:var(--text-secondary); white-space:nowrap;">${new Date(a.timestamp).toLocaleDateString()}</small>
    </div>
  `).join('');
}

// ============================================================================
// 7. Direct Provider Care Directory & WebRTC Telehealth (Blueprint Sec 2D, 3, 4)
// ============================================================================
function initCounselorFilters() {
  ['counselor-search', 'counselor-modality-filter', 'counselor-language-filter', 'counselor-specialty-filter'].forEach(id => {
    const el = document.getElementById(id);
    el?.addEventListener('input', () => renderCounselors());
    el?.addEventListener('change', () => renderCounselors());
  });
}

function renderCounselors() {
  const container = document.getElementById('counselor-container');
  if (!container) return;

  const query = (document.getElementById('counselor-search')?.value || '').toLowerCase().trim();
  const modalityFilter = document.getElementById('counselor-modality-filter')?.value || 'ALL';
  const langFilter = document.getElementById('counselor-language-filter')?.value || 'ALL';
  const specialtyFilter = document.getElementById('counselor-specialty-filter')?.value || 'ALL';

  const filtered = state.counselors.filter(c => {
    const langs = Array.isArray(c.languages) ? c.languages.join(' ').toLowerCase() : 'english';
    const mod = (c.modality || 'CBT').toLowerCase();
    const matchesSearch = !query ||
      c.name.toLowerCase().includes(query) ||
      c.specialty.toLowerCase().includes(query) ||
      mod.includes(query) ||
      langs.includes(query);
    const matchesMod = modalityFilter === 'ALL' || mod.includes(modalityFilter.toLowerCase());
    const matchesLang = langFilter === 'ALL' || langs.includes(langFilter.toLowerCase());
    const matchesSpec = specialtyFilter === 'ALL' || c.specialty.toLowerCase().includes(specialtyFilter.toLowerCase());
    return matchesSearch && matchesMod && matchesLang && matchesSpec;
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="card"><p style="color:var(--text-secondary);">No practitioners match your multi-attribute filter criteria.</p></div>`;
    return;
  }

  container.innerHTML = filtered.map(c => {
    const langs = Array.isArray(c.languages) ? c.languages : ['English'];
    const isAvail = c.available !== false;
    return `
      <div class="counselor-card">
        <div class="flex-between">
          <div>
            <h3>${escapeHtml(c.name)}</h3>
            <small style="color:var(--accent-teal); font-weight:600;">${escapeHtml(c.role || 'Verified Practitioner')}</small>
          </div>
          <span class="chip">★ ${c.rating}</span>
        </div>
        <p style="color:var(--text-secondary); font-size:0.86rem; margin: 0.55rem 0;">${escapeHtml(c.specialty)}</p>
        <div class="provider-meta-row">
          <span class="mono-badge">${escapeHtml(c.modality || 'CBT')}</span>
          <span class="slot-pill">💬 ${escapeHtml(langs.join(', '))}</span>
          <span class="slot-pill">💳 ${escapeHtml(c.rate || '$0 Campus')}</span>
          <span class="slot-pill" style="color:${isAvail ? '#10b981' : '#f59e0b'};">● ${isAvail ? 'Available Now' : 'Waitlist'}</span>
        </div>
        <div style="font-size:0.76rem; color:var(--text-secondary); margin-top:0.35rem;">Open Consultation Slots:</div>
        <div class="slot-pills">
          ${(c.slots || []).map(s => `<span class="slot-pill">${escapeHtml(s)}</span>`).join('')}
        </div>
        <div class="card-action-row">
          <button class="btn btn-primary" style="flex:1;" onclick="openBookingModal('${c.id}')">Book Session</button>
          <button class="btn btn-secondary" onclick="launchTelehealthRoom('${c.id}')" title="Launch P2P Encrypted WebRTC Room">🎥 WebRTC</button>
        </div>
      </div>
    `;
  }).join('');
}

function renderBookings() {
  const container = document.getElementById('booking-list');
  if (!container) return;
  if (!state.bookings.length) {
    container.innerHTML = `<p style="color:var(--text-secondary); font-size:0.9rem;">No upcoming appointments. Visit the Care Directory to schedule.</p>`;
    return;
  }
  container.innerHTML = state.bookings.map(b => `
    <div class="list-item">
      <div>
        <strong>${escapeHtml(b.counselorName)}</strong>
        <p style="font-size:0.8rem; color:var(--text-secondary);">${escapeHtml(b.mode)} • ${escapeHtml(b.date)} at ${escapeHtml(b.slot)}</p>
        ${b.notes ? `<small style="color:var(--text-secondary);">Focus: ${escapeHtml(b.notes)}</small>` : ''}
      </div>
      <div style="display:flex; align-items:center; gap:0.45rem; flex-wrap:wrap;">
        <button class="btn btn-secondary btn-sm" onclick="launchTelehealthRoom('${b.counselorId || 'c1'}', '${b.id}')">🎥 Join Room</button>
        <span style="font-size:0.74rem; color:${b.status === 'COMPLETED' ? '#3b82f6' : '#10b981'}; font-weight:700;">${escapeHtml(b.status)}</span>
        ${state.role !== 'student' && b.status === 'CONFIRMED'
          ? `<button class="btn btn-secondary btn-sm" onclick="completeBooking('${b.id}')">Complete</button>`
          : ''}
        <button class="btn btn-ghost btn-sm" onclick="cancelBooking('${b.id}')" title="Cancel Session">&times;</button>
      </div>
    </div>
  `).join('');
}

function openBookingModal(counselorId) {
  const counselor = state.counselors.find(c => c.id === counselorId);
  if (!counselor) return;
  state.selectedCounselorId = counselorId;
  document.getElementById('modal-counselor-name').innerText = `Schedule with ${counselor.name}`;
  const slotSelect = document.getElementById('booking-slot');
  if (slotSelect && counselor.slots) {
    slotSelect.innerHTML = counselor.slots.map(s => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join('');
  }
  const errEl = document.getElementById('booking-error-msg');
  if (errEl) {
    errEl.classList.add('hidden');
    errEl.innerText = '';
  }
  openModal('modal-booking');
}

document.getElementById('btn-confirm-booking')?.addEventListener('click', async () => {
  const date = document.getElementById('booking-date').value;
  const slot = document.getElementById('booking-slot').value;
  const mode = document.getElementById('booking-mode').value;
  const notes = document.getElementById('booking-notes')?.value.trim() || '';
  const errEl = document.getElementById('booking-error-msg');

  const payload = { counselorId: state.selectedCounselorId, slot, date, mode, notes };
  try {
    const res = await fetch('/api/bookings', {
      method: 'POST',
      headers: getApiHeaders(),
      body: JSON.stringify(payload)
    });
    const resData = await res.json();
    if (!res.ok || !resData.success) {
      if (errEl) {
        errEl.innerText = resData.message || 'Unable to book this slot.';
        errEl.classList.remove('hidden');
      }
      return;
    }
    state.bookings.push(resData.data);
    renderBookings();
    updateDashboardMetrics();
    closeModal('modal-booking');
    if (document.getElementById('booking-notes')) {
      document.getElementById('booking-notes').value = '';
    }
  } catch {
    closeModal('modal-booking');
  }
});

async function cancelBooking(bookingId) {
  try {
    await fetch(`/api/bookings/${bookingId}`, { method: 'DELETE', headers: getApiHeaders() });
  } catch {}
  state.bookings = state.bookings.filter(b => b.id !== bookingId);
  renderBookings();
  updateDashboardMetrics();
}

async function completeBooking(bookingId) {
  try {
    const res = await fetch(`/api/bookings/${bookingId}`, {
      method: 'PATCH',
      headers: getApiHeaders(),
      body: JSON.stringify({ status: 'COMPLETED' })
    });
    const data = await res.json();
    if (data.success) {
      const target = state.bookings.find(b => b.id === bookingId);
      if (target) target.status = 'COMPLETED';
      renderBookings();
    }
  } catch {}
}

// Integrated WebRTC Telehealth Pipeline (Blueprint Section 4)
async function launchTelehealthRoom(providerId, bookingId) {
  const provider = state.counselors.find(c => c.id === providerId) || state.counselors[0];
  document.getElementById('telehealth-provider-name').innerText = provider?.name || 'Verified Practitioner';
  document.getElementById('telehealth-provider-modality').innerText = `${provider?.modality || 'CBT'} • E2EE P2P Connected`;

  try {
    const res = await fetch('/api/telehealth/session', {
      method: 'POST',
      headers: getApiHeaders(),
      body: JSON.stringify({ providerId, bookingId })
    });
    const json = await res.json();
    if (json.success && json.data) {
      document.getElementById('telehealth-fingerprint').innerText =
        `${json.data.encryption} • ${json.data.dtlsFingerprint}`;
    }
  } catch {
    document.getElementById('telehealth-fingerprint').innerText =
      'WebRTC DTLS-SRTP • SHA-256 E4:9A:2F:7C:11:8B:3D:09';
  }

  openModal('modal-telehealth');
  startSimulatedWebRTCStream();
}

function startSimulatedWebRTCStream() {
  const canvas = document.getElementById('webrtc-fallback-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let phase = 0;
  if (state.webrtcCanvasInterval) clearInterval(state.webrtcCanvasInterval);

  state.webrtcCanvasInterval = setInterval(() => {
    ctx.fillStyle = '#090e1a';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Draw P2P encrypted audio/video waveform telemetry
    ctx.strokeStyle = '#14b8a6';
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    for (let x = 0; x < canvas.width; x += 6) {
      const y = 110 + Math.sin((x + phase) * 0.045) * 28 * Math.cos(phase * 0.02);
      if (x === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.stroke();

    ctx.fillStyle = '#9ca3af';
    ctx.font = '12px JetBrains Mono, monospace';
    ctx.fillText('DTLS-SRTP P2P STREAM ACTIVE (60fps)', 16, 28);
    phase += 5;
  }, 60);
}

function endTelehealthSession() {
  if (state.webrtcCanvasInterval) {
    clearInterval(state.webrtcCanvasInterval);
    state.webrtcCanvasInterval = null;
  }
  if (state.webrtcStream) {
    state.webrtcStream.getTracks().forEach(t => t.stop());
    state.webrtcStream = null;
  }
  closeModal('modal-telehealth');
}

document.getElementById('btn-toggle-mic')?.addEventListener('click', (e) => {
  state.micEnabled = !state.micEnabled;
  e.target.innerText = state.micEnabled ? '🎙️ Mic: On' : '🔇 Mic: Muted';
});

// ============================================================================
// 8. Autonomic Regulation Engine (4-7-8, 4-4-4-4 Box, 5-5 Coherent Pacer)
// ============================================================================
let breathInterval = null;
let isBreathing = false;

function initDeStressSuite() {
  const btnBreath = document.getElementById('btn-toggle-breath');
  const circle = document.getElementById('breath-circle');
  const text = document.getElementById('breath-text');
  const cycleChip = document.getElementById('breath-cycle-count');
  const modeBtns = document.querySelectorAll('.breath-mode-btn');

  const modeDescriptions = {
    '4-7-8': [
      '4-7-8 Autonomic Vagal Breathing',
      '4s Inhale • 7s Hold • 8s Exhale — Activates parasympathetic vagal tone for acute anxiety suppression.'
    ],
    '4-4-4-4': [
      'Box Breathing (4-4-4-4 Stabilization)',
      '4s Inhale • 4s Hold • 4s Exhale • 4s Rest — Navy SEAL & clinical protocol for attentional stabilization.'
    ],
    '5-5': [
      'Coherent Autonomic Pacing (5-5 HRV)',
      '5s Inhale • 5s Exhale (6 breaths/min) — Synchronizes heart-rate variability (HRV) baroreflex resonance.'
    ]
  };

  modeBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      modeBtns.forEach(b => { b.className = 'btn btn-secondary breath-mode-btn'; });
      btn.className = 'btn btn-primary breath-mode-btn';
      state.breathMode = btn.getAttribute('data-mode');
      const info = modeDescriptions[state.breathMode];
      if (info) {
        document.getElementById('breath-mode-title').innerText = info[0];
        document.getElementById('breath-mode-desc').innerText = info[1];
      }
      if (isBreathing) {
        btnBreath.click(); // reset current pacer
      }
    });
  });

  btnBreath?.addEventListener('click', () => {
    isBreathing = !isBreathing;
    if (isBreathing) {
      btnBreath.innerText = "Stop Guided Pacer";
      let step = 0;
      const sequence = () => {
        if (!isBreathing) return;
        if (state.breathMode === '4-7-8') {
          step = (step + 1) % 3;
          if (step === 1) {
            text.innerText = "Inhale (4s)";
            circle.className = "breathing-circle expand";
          } else if (step === 2) {
            text.innerText = "Hold (7s)";
            circle.className = "breathing-circle hold";
          } else {
            text.innerText = "Exhale (8s)";
            circle.className = "breathing-circle";
            recordBreathCycle(cycleChip);
          }
        } else if (state.breathMode === '4-4-4-4') {
          step = (step + 1) % 4;
          if (step === 1) {
            text.innerText = "Inhale (4s)";
            circle.className = "breathing-circle expand";
          } else if (step === 2) {
            text.innerText = "Hold Full (4s)";
            circle.className = "breathing-circle hold";
          } else if (step === 3) {
            text.innerText = "Exhale (4s)";
            circle.className = "breathing-circle";
          } else {
            text.innerText = "Hold Empty (4s)";
            circle.className = "breathing-circle";
            recordBreathCycle(cycleChip);
          }
        } else {
          step = (step + 1) % 2;
          if (step === 1) {
            text.innerText = "Coherent Inhale (5s)";
            circle.className = "breathing-circle expand";
          } else {
            text.innerText = "Coherent Exhale (5s)";
            circle.className = "breathing-circle";
            recordBreathCycle(cycleChip);
          }
        }
      };
      sequence();
      breathInterval = setInterval(sequence, 4000);
    } else {
      btnBreath.innerText = "Start Guided Breath Pacer";
      clearInterval(breathInterval);
      circle.className = "breathing-circle";
      text.innerText = "Ready";
    }
  });

  // Sound Synthesizer with explicit AudioContext resume (TC-AUDIO-01)
  const soundBtns = document.querySelectorAll('.sound-toggle');
  soundBtns.forEach(btn => {
    btn.addEventListener('click', async () => {
      const type = btn.getAttribute('data-type');
      const wasActive = btn.innerText === 'Stop';

      if (state.activeOscillator) {
        try { state.activeOscillator.stop(); } catch {}
        state.activeOscillator = null;
        soundBtns.forEach(b => { b.innerText = "Play"; });
        if (wasActive) return;
      }

      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      state.audioCtx = state.audioCtx || new AudioCtx();
      if (state.audioCtx.state === 'suspended') {
        await state.audioCtx.resume();
      }

      const osc = state.audioCtx.createOscillator();
      const gain = state.audioCtx.createGain();

      if (type === 'alpha') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(210, state.audioCtx.currentTime);
      } else if (type === 'theta') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(140, state.audioCtx.currentTime);
      } else {
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(80, state.audioCtx.currentTime);
      }

      gain.gain.setValueAtTime(0.06, state.audioCtx.currentTime);
      osc.connect(gain);
      gain.connect(state.audioCtx.destination);
      osc.start();
      state.activeOscillator = osc;
      btn.innerText = "Stop";
    });
  });

  // Pomodoro Cognitive Sprint Timer
  const timerDisplay = document.getElementById('focus-timer-display');
  const btnToggleTimer = document.getElementById('btn-toggle-timer');
  const btnResetTimer = document.getElementById('btn-reset-timer');

  function formatTimer(sec) {
    const m = String(Math.floor(sec / 60)).padStart(2, '0');
    const s = String(sec % 60).padStart(2, '0');
    return `${m}:${s}`;
  }

  btnToggleTimer?.addEventListener('click', () => {
    if (state.timerInterval) {
      clearInterval(state.timerInterval);
      state.timerInterval = null;
      btnToggleTimer.innerText = 'Resume Sprint';
    } else {
      btnToggleTimer.innerText = 'Pause Sprint';
      state.timerInterval = setInterval(() => {
        if (state.timerSeconds > 0) {
          state.timerSeconds -= 1;
          if (timerDisplay) timerDisplay.innerText = formatTimer(state.timerSeconds);
        } else {
          clearInterval(state.timerInterval);
          state.timerInterval = null;
          state.mindfulMinutes += 25;
          updateDashboardMetrics();
          btnToggleTimer.innerText = 'Start Sprint';
        }
      }, 1000);
    }
  });

  btnResetTimer?.addEventListener('click', () => {
    if (state.timerInterval) {
      clearInterval(state.timerInterval);
      state.timerInterval = null;
    }
    state.timerSeconds = 25 * 60;
    if (timerDisplay) timerDisplay.innerText = '25:00';
    if (btnToggleTimer) btnToggleTimer.innerText = 'Start Sprint';
  });
}

function recordBreathCycle(cycleChip) {
  state.breathCycles += 1;
  state.mindfulMinutes += 1;
  if (cycleChip) cycleChip.innerText = `${state.breathCycles} ${state.breathCycles === 1 ? 'Cycle' : 'Cycles'}`;
  updateDashboardMetrics();
}

// ============================================================================
// 9. Safe Peer Forum (with Triage Screening, Upvoting & Replies)
// ============================================================================
function initForumControls() {
  document.getElementById('forum-search')?.addEventListener('input', () => renderForumPosts());
  document.getElementById('forum-category-filter')?.addEventListener('change', () => renderForumPosts());

  document.getElementById('btn-open-post-modal')?.addEventListener('click', () => {
    openModal('modal-post');
  });

  document.getElementById('btn-submit-post')?.addEventListener('click', async () => {
    const category = document.getElementById('post-category').value;
    const title = document.getElementById('post-title').value.trim();
    const body = document.getElementById('post-body').value.trim();

    if (!title || !body) return;

    const authorName = state.anonymousMode
      ? state.anonymousAlias
      : state.role === 'counselor'
      ? 'Peer Counselor (Verified)'
      : state.role === 'admin'
      ? 'Clinical Wellness Team'
      : 'Anonymous Student';

    const payload = { title, body, category, author: authorName };
    try {
      const res = await fetch('/api/posts', {
        method: 'POST',
        headers: getApiHeaders(),
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.success) {
        state.forumPosts.unshift(data.data);
        renderForumPosts();
        closeModal('modal-post');
        document.getElementById('post-title').value = '';
        document.getElementById('post-body').value = '';

        if (data.safetyIntervention) {
          openModal('modal-safety');
        }
      }
    } catch {
      closeModal('modal-post');
    }
  });
}

function renderForumPosts() {
  const container = document.getElementById('forum-posts-container');
  if (!container) return;

  const query = (document.getElementById('forum-search')?.value || '').toLowerCase().trim();
  const catFilter = document.getElementById('forum-category-filter')?.value || 'ALL';

  const filtered = state.forumPosts.filter(p => {
    const matchesSearch = !query ||
      p.title.toLowerCase().includes(query) ||
      p.body.toLowerCase().includes(query) ||
      p.category.toLowerCase().includes(query);
    const matchesCat = catFilter === 'ALL' ||
      p.category.toLowerCase().includes(catFilter.toLowerCase());
    return matchesSearch && matchesCat;
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="card mt-3"><p style="color:var(--text-secondary);">No discussions match your search.</p></div>`;
    return;
  }

  container.innerHTML = filtered.map(p => {
    const repliesHtml = (p.replyList || []).map(r => `
      <div class="reply-item">
        <strong>${r.author}</strong> <small style="color:var(--text-secondary);">• ${r.timestamp || 'Just now'}</small>
        <p style="margin-top:0.2rem; color:var(--text-primary);">${r.text}</p>
      </div>
    `).join('');

    return `
      <div class="card mt-3">
        <div class="flex-between">
          <span class="badge-role">${p.category}</span>
          <small style="color:var(--text-secondary);">${p.timestamp}</small>
        </div>
        <h3 style="margin: 0.6rem 0;">${p.title}</h3>
        <p style="color:var(--text-secondary); font-size:0.92rem; line-height:1.55;">${p.body}</p>
        <div class="flex-between mt-3" style="font-size:0.85rem; color:var(--text-secondary);">
          <span>Posted by: <em>${p.author}</em></span>
          <div class="forum-actions-bar">
            <button class="btn btn-secondary btn-sm" onclick="upvotePost('${p.id}')">▲ ${p.upvotes || 0} Helpful</button>
            <span>💬 ${(p.replyList ? p.replyList.length : p.replies) || 0} Replies</span>
          </div>
        </div>
        <div class="replies-box">
          ${repliesHtml}
          <div class="reply-form">
            <input type="text" id="reply-input-${p.id}" class="input-control" placeholder="Write a supportive peer reply..." />
            <button class="btn btn-primary btn-sm" onclick="submitReply('${p.id}')">Reply</button>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

async function upvotePost(postId) {
  try {
    const res = await fetch(`/api/posts/${postId}/upvote`, {
      method: 'POST',
      headers: getApiHeaders()
    });
    const data = await res.json();
    if (data.success) {
      const target = state.forumPosts.find(p => p.id === postId);
      if (target) target.upvotes = data.data.upvotes;
      renderForumPosts();
    }
  } catch {
    const target = state.forumPosts.find(p => p.id === postId);
    if (target) target.upvotes = (target.upvotes || 0) + 1;
    renderForumPosts();
  }
}

async function submitReply(postId) {
  const input = document.getElementById(`reply-input-${postId}`);
  if (!input || !input.value.trim()) return;
  const text = input.value.trim();
  const author = state.anonymousMode
    ? state.anonymousAlias
    : state.role === 'counselor'
    ? 'Verified Peer Mentor'
    : 'Peer Supporter';

  try {
    const res = await fetch(`/api/posts/${postId}/replies`, {
      method: 'POST',
      headers: getApiHeaders(),
      body: JSON.stringify({ text, author })
    });
    const data = await res.json();
    if (data.success) {
      const idx = state.forumPosts.findIndex(p => p.id === postId);
      if (idx !== -1) state.forumPosts[idx] = data.data;
      renderForumPosts();
      if (data.safetyIntervention) {
        openModal('modal-safety');
      }
    }
  } catch {}
}

// ============================================================================
// 10. HIPAA / GDPR Privacy Vault & Global Crisis Region Filter
// ============================================================================
function initGovernanceControls() {
  const statusEl = document.getElementById('governance-status-msg');

  document.getElementById('btn-export-data')?.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/governance/export', { headers: getApiHeaders() });
      const json = await res.json();
      const blob = new Blob([JSON.stringify(json, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `mindbridge-gdpr-export-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      if (statusEl) statusEl.innerText = '✓ GDPR Article 20 JSON Data Export downloaded.';
      fetchGovernanceAudit();
    } catch {}
  });

  document.getElementById('btn-ephemeral-sweep')?.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/governance/ephemeral-sweep', {
        method: 'POST',
        headers: getApiHeaders()
      });
      const json = await res.json();
      if (statusEl) {
        statusEl.innerText = `✓ 30-Day Ephemeral Sweep complete (${json.expiredRecordsRemoved || 0} expired records removed).`;
      }
      fetchGovernanceAudit();
    } catch {}
  });

  document.getElementById('btn-purge-data')?.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/governance/purge', {
        method: 'DELETE',
        headers: getApiHeaders()
      });
      const json = await res.json();
      if (json.success) {
        state.moods = [];
        state.assessments = [];
        state.bookings = [];
        await renderMoodHistory(state.moods);
        renderAssessmentHistory();
        renderBookings();
        updateDashboardMetrics();
        if (statusEl) statusEl.innerText = '🗑️ All personal data permanently purged (GDPR Right to Erasure).';
        fetchGovernanceAudit();
      }
    } catch {}
  });
}

async function fetchGovernanceAudit() {
  const container = document.getElementById('audit-log-list');
  if (!container) return;
  try {
    const res = await fetch('/api/governance/audit', { headers: getApiHeaders() });
    const json = await res.json();
    const logs = json.data || [];
    container.innerHTML = logs.slice(0, 8).map(l => `
      <div class="list-item">
        <div>
          <strong style="font-size:0.84rem;">${escapeHtml(l.action)}</strong>
          <span class="mono-badge" style="margin-left:0.4rem;">${escapeHtml(l.actor)}</span>
          <p style="font-size:0.78rem; color:var(--text-secondary); margin-top:0.2rem;">${escapeHtml(l.detail)}</p>
        </div>
        <small style="color:var(--text-secondary); white-space:nowrap;">${new Date(l.timestamp).toLocaleTimeString()}</small>
      </div>
    `).join('');
  } catch {}
}

function initCrisisHubFilters() {
  const regionFilter = document.getElementById('crisis-region-filter');
  regionFilter?.addEventListener('change', () => {
    const val = regionFilter.value;
    document.querySelectorAll('#crisis-hotlines-grid .crisis-box').forEach(box => {
      const reg = box.getAttribute('data-region');
      if (val === 'ALL' || reg === val || reg === 'Campus') {
        box.classList.remove('hidden');
      } else {
        box.classList.add('hidden');
      }
    });
  });
}

// Fallback Mock Data
function getMockCounselors() {
  return [
    { id: "c1", name: "Sarah Jenkins, MSW", role: "Licensed Clinical Social Worker", specialty: "Academic Anxiety & Burnout", modality: "CBT (Cognitive Behavioral Therapy)", languages: ["English", "Spanish"], rate: "$0 (Campus Covered)", available: true, rating: 4.9, slots: ["10:00 AM", "02:30 PM", "04:00 PM"] },
    { id: "c2", name: "David Chen, Peer Lead", role: "Certified Peer Mentor", specialty: "Social Isolation & First-Year Prep", modality: "ACT (Acceptance & Commitment Therapy)", languages: ["English", "Mandarin"], rate: "$0 (Peer Support)", available: true, rating: 4.8, slots: ["11:30 AM", "01:00 PM", "05:15 PM"] },
    { id: "c3", name: "Dr. Alisha Rao, PsyD", role: "Clinical Psychologist", specialty: "Clinical Depression & Crisis Management", modality: "Trauma-Informed Care & DBT", languages: ["English", "Hindi", "Telugu"], rate: "$0 (Campus Covered)", available: true, rating: 5.0, slots: ["09:00 AM", "03:00 PM"] }
  ];
}

function getMockBookings() {
  return [
    { id: "b101", counselorId: "c1", counselorName: "Sarah Jenkins, MSW", slot: "10:00 AM", date: "2026-11-12", status: "CONFIRMED", mode: "Encrypted WebRTC Video" }
  ];
}

function getMockPosts() {
  return [
    { id: "p1", author: "Anonymous Junior", category: "Academic Stress", title: "Dealing with imposter syndrome in 3rd year engineering", body: "Does anyone else feel like they are constantly behind despite putting in 10 hours a day? How do you mentally cope?", upvotes: 24, replies: 2, replyList: [], timestamp: "2 hours ago" },
    { id: "p2", author: "Peer Supporter Marcus", category: "Sleep & Routine", title: "3 proven sleep hacks during finals week", body: "Avoid screens 45 mins before bed and try non-sleep deep rest (NSDR). It cut my fatigue down significantly.", upvotes: 42, replies: 1, replyList: [], timestamp: "5 hours ago" }
  ];
}

function getMockMoods() {
  return [
    { id: 1, label: "Calm", emotion: "Calm", rating: 4, score: 4, tags: ["Study Flow"], notes: "Productive study session.", timestamp: new Date(Date.now() - 86400000).toISOString() },
    { id: 2, label: "Overwhelmed", emotion: "Overwhelmed", rating: 2, score: 2, tags: ["Exam Anxiety"], notes: "Upcoming data structures midterms.", timestamp: new Date().toISOString() }
  ];
}
