const request = require('supertest');
const app = require('../server/index');

describe('MindBridge Enterprise & Architectural Blueprint API Test Suite', () => {
  // Test Case 1: Healthcheck
  test('TC01: GET /api/health returns 200, UP status, and clinical standards', async () => {
    const res = await request(app).get('/api/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe('UP');
    expect(res.body.standards).toEqual(expect.arrayContaining(['HIPAA', 'GDPR', 'PHQ-9', 'GAD-7', 'AES-GCM-256', 'WebRTC']));
    expect(res.body).toHaveProperty('timestamp');
  });

  // Test Case 2: Mood Retrieval
  test('TC02: GET /api/moods returns mood historical records', async () => {
    const res = await request(app).get('/api/moods');
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
  });

  // Test Case 3: Mood Ingestion (Blueprint & Legacy Contract)
  test('TC03: POST /api/moods accepts Blueprint schema (userId, score, emotion, tags, notes) and returns entry', async () => {
    const payload = {
      userId: "u101",
      score: 5,
      emotion: "Thriving",
      tags: ["Exam Prep", "Mindfulness"],
      notes: "Aced the engineering exam!"
    };
    const res = await request(app).post('/api/moods').send(payload);
    expect(res.statusCode).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.entry.score).toBe(5);
    expect(res.body.entry.emotion).toBe("Thriving");
    expect(res.body.entry.tags).toEqual(["Exam Prep", "Mindfulness"]);
    expect(res.body.data.rating).toBe(5);
  });

  // Test Case 4: Mood Ingestion Boundary Validation (TC-MOOD-01)
  test('TC04: POST /api/moods rejects ratings/scores outside 1-5 range', async () => {
    const payload = { score: 10, emotion: "Superhuman" };
    const res = await request(app).post('/api/moods').send(payload);
    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
  });

  // Test Case 5: Direct Provider Care Directory (/api/therapists & /api/counselors)
  test('TC05: GET /api/therapists returns structured providers with modality, languages, rate, and availability', async () => {
    const res = await request(app).get('/api/therapists?modality=CBT');
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.body.therapists)).toBe(true);
    expect(res.body.therapists.length).toBeGreaterThan(0);
    expect(res.body.therapists[0]).toHaveProperty('modality');
    expect(res.body.therapists[0]).toHaveProperty('languages');
    expect(res.body.therapists[0]).toHaveProperty('rate');
    expect(res.body.therapists[0]).toHaveProperty('available');
  });

  // Test Case 6: Peer Appointment Booking (Success)
  test('TC06: POST /api/bookings successfully books session with valid inputs', async () => {
    const payload = { counselorId: "c1", slot: "10:00 AM", date: "2026-11-15", mode: "Encrypted WebRTC Video" };
    const res = await request(app).post('/api/bookings').send(payload);
    expect(res.statusCode).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data.status).toBe("CONFIRMED");
    expect(res.body.data.counselorName).toBe("Sarah Jenkins, MSW");
    expect(res.body.data).toHaveProperty('webrtcRoomId');
  });

  // Test Case 7: Double Booking Race / Conflict Prevention (TC-BOOK-01)
  test('TC07: POST /api/bookings returns 409 Conflict for duplicate counselor slot', async () => {
    const payload = { counselorId: "c1", slot: "10:00 AM", date: "2026-11-15", mode: "Encrypted WebRTC Video" };
    const res = await request(app).post('/api/bookings').send(payload);
    expect(res.statusCode).toBe(409);
    expect(res.body.success).toBe(false);
  });

  // Test Case 8: Peer Booking Invalid Counselor ID
  test('TC08: POST /api/bookings returns 404 for non-existent counselor', async () => {
    const payload = { counselorId: "c_unknown_999", slot: "10:00 AM", date: "2026-11-15" };
    const res = await request(app).post('/api/bookings').send(payload);
    expect(res.statusCode).toBe(404);
    expect(res.body.success).toBe(false);
  });

  // Test Case 9: Forum Discussion Creation & XSS Sanitization (TC-MOOD-02)
  test('TC09: POST /api/posts allows creation of anonymous support post and sanitizes XSS', async () => {
    const payload = {
      title: "How to handle final year project stress?",
      body: "Struggling with backend deadlocks <script>alert('xss')</script>",
      category: "Academic Stress"
    };
    const res = await request(app).post('/api/posts').send(payload);
    expect(res.statusCode).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data.body).toContain('&lt;script&gt;');
  });

  // Test Case 10: Intelligent Triage & Crisis Safety Protocol (Blueprint Section 2A & 3)
  test('TC10: POST /api/triage evaluates journalText and returns CRISIS level with global hotlines (988, 112, 14416)', async () => {
    const crisisRes = await request(app)
      .post('/api/triage')
      .send({ journalText: "I feel completely hopeless and want to end my life tonight" });
    expect(crisisRes.statusCode).toBe(200);
    expect(crisisRes.body.level).toBe('CRISIS');
    expect(Array.isArray(crisisRes.body.hotlines)).toBe(true);
    const contacts = crisisRes.body.hotlines.map(h => h.contact);
    expect(contacts).toEqual(expect.arrayContaining(['988', '112', '14416']));
    expect(crisisRes.body).toHaveProperty('suggestedExercise');

    const normalRes = await request(app)
      .post('/api/triage')
      .send({ journalText: "Finished my algorithms homework and going for a walk." });
    expect(normalRes.statusCode).toBe(200);
    expect(normalRes.body.level).toBe('NORMAL');
  });

  // Test Case 11: Standardized Psychometric Scoring (PHQ-9 & GAD-7)
  test('TC11: POST /api/assessments computes PHQ-9 and GAD-7 scores and clinical severity bands', async () => {
    const phqPayload = {
      type: 'PHQ-9',
      responses: [1, 2, 1, 2, 1, 1, 2, 1, 0] // sum = 11 -> Moderate Depression
    };
    const phqRes = await request(app).post('/api/assessments').send(phqPayload);
    expect(phqRes.statusCode).toBe(201);
    expect(phqRes.body.assessment.score).toBe(11);
    expect(phqRes.body.assessment.severity).toBe('Moderate Depression');

    const gadPayload = {
      type: 'GAD-7',
      responses: [2, 2, 3, 2, 2, 2, 2] // sum = 15 -> Severe Anxiety
    };
    const gadRes = await request(app).post('/api/assessments').send(gadPayload);
    expect(gadRes.statusCode).toBe(201);
    expect(gadRes.body.assessment.score).toBe(15);
    expect(gadRes.body.assessment.severity).toBe('Severe Anxiety');
  });

  // Test Case 12: WebRTC Telehealth Room & HIPAA/GDPR Governance Endpoints
  test('TC12: POST /api/telehealth/session and GET /api/governance/export operate per Blueprint Section 4', async () => {
    const rtcRes = await request(app).post('/api/telehealth/session').send({ providerId: 'c1' });
    expect(rtcRes.statusCode).toBe(201);
    expect(rtcRes.body.data.encryption).toMatch(/DTLS-SRTP/);

    const expRes = await request(app).get('/api/governance/export');
    expect(expRes.statusCode).toBe(200);
    expect(expRes.body.success).toBe(true);
    expect(expRes.body.data).toHaveProperty('moods');
    expect(expRes.body.data).toHaveProperty('assessments');
  });

  // Test Case 13: Client SPA Fallback Routing
  test('TC13: GET unmapped URL falls back to SPA index.html', async () => {
    const res = await request(app).get('/random-student-route');
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toMatch(/html/);
  });
});
