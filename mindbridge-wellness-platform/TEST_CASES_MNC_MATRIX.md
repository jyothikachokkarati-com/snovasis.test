# Enterprise QA & MNC Interview Test Case Matrix

This document defines exhaustive functional, non-functional, security, and edge-case testing coverage designed to meet MNC Tier-1 hiring benchmarks.

| Test Case ID | Test Category | Description | Input / Precondition | Expected Result | Priority |
|---|---|---|---|---|---|
| **TC-AUTH-01** | Privacy & Security | Anonymous Mode Tokenization | User toggles "Anonymous Mode" | UUID replaces student identity; no PII exposed in network headers | Critical |
| **TC-MOOD-01** | Functional | Mood Score Bound Check | Rating = 0 or 6 | System rejects with HTTP 400 Bad Request | High |
| **TC-MOOD-02** | Functional | Stress Notes XSS Sanitization | `<script>alert('xss')</script>` in trigger notes | Input is sanitized or HTML-encoded; no script execution | Critical |
| **TC-MOOD-03** | Boundary | Maximum Character Limit | Note exceeding 2000 characters | System truncates or warns user gracefully | Medium |
| **TC-BOOK-01** | Concurrency | Double Booking Race Condition | Two concurrent requests for slot "10:00 AM" | Exactly 1 booking succeeds (201); 2nd receives 409 Conflict | Critical |
| **TC-BOOK-02** | Functional | Counselor Availability Filter | Filter counselors by "Academic Burnout" | List dynamically filters without reloading DOM | Medium |
| **TC-AUDIO-01**| UX / Performance | Web Audio Context Suspended State | Autoplay policy triggered on modern browsers | App waits for explicit user gesture before resuming AudioContext | High |
| **TC-FORUM-01**| Safety & Moderation | Trigger Word Screening | Post containing harmful self-harm keywords | Urgent safety intervention overlay triggers immediately with crisis hotlines | Critical |
| **TC-FORUM-02**| Performance | Pagination / Infinite Scroll | Forum loaded with 10,000+ posts | Virtual list or pagination keeps DOM node count < 100 | High |
| **TC-CRISIS-01**| Reliability / SLA | Crisis Hotlines Availability | User clicks "Crisis Support" | Hotline cards render with instantaneous tel: links; zero network lag | Critical |
| **TC-RESP-01** | Accessibility & UI | Mobile Viewport Breakdown | Device width: 360px (Android), 390px (iOS) | Sidebar collapses into bottom navigation; touch targets >= 44x44px | High |
| **TC-NET-01**  | Offline Resilience | Service Worker / Network Drop | Network switches to Offline | Cached static shell loads; mood submissions saved to IndexedDB queue | High |
