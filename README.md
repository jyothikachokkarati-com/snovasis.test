# MindBridge — Student Wellness Platform

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/jyothikachokkarati-com/snovasis.test)

MindBridge is an enterprise-grade digital mental health platform adhering to international clinical standards (PHQ-9, GAD-7, CBT/ACT modality filtering, autonomic breath pacing, WebRTC DTLS-SRTP telehealth, and AES-GCM-256 client-side zero-knowledge encryption).

---

## 🚀 One-Click Cloud Deployment (Render)

Click the badge above or visit:
👉 **[https://render.com/deploy?repo=https://github.com/jyothikachokkarati-com/snovasis.test](https://render.com/deploy?repo=https://github.com/jyothikachokkarati-com/snovasis.test)**

Render will automatically parse `render.yaml`, provision the Node.js web service, install dependencies, run health checks against `/api/health`, and publish your live URL.

---

## 🛠️ Local Development & Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/jyothikachokkarati-com/snovasis.test.git
cd snovasis.test

# 2. Install dependencies
npm --prefix mindbridge-wellness-platform install

# 3. Start full-stack application (Ports 5000 & 3000)
node mindbridge-wellness-platform/server/index.js
```

Open: `http://localhost:5000` or `http://localhost:3000`

---

## 🧪 Automated Test Suite (13/13 Passing)

```bash
npm --prefix mindbridge-wellness-platform test
```
