# MindBridge - Student Wellness & Peer Support Platform

MindBridge is an enterprise-grade full-stack web application prototype built to connect students with verified peer counselors, licensed mental health professionals, emotional diagnostic tracking, audio de-stress routines, and structured academic stress-relief tools.

---

## 🚀 Quick Start / How to Run in Antigravity or Local Dev

### Option 1: Static / Full Frontend Prototype
Double-click `public/index.html` or serve with any static web server:
```bash
# Using Python
python3 -m http.server 3000 --directory public
```
Visit: `http://localhost:3000`

### Option 2: Full-Stack Node.js / Express Server
1. Navigate to the project root:
   ```bash
   npm install
   ```
2. Start the development server:
   ```bash
   npm run dev
   ```
3. Open `http://localhost:5000` in your browser.

---

## 🛠️ Architecture Overview

- **Frontend**: Clean Vanilla JavaScript (ES6+), Modern Glassmorphic CSS Design System, Responsive Multi-Role Switcher (Student, Peer Counselor, Clinical Admin), Web Audio API Guided Breathing & Binaural Frequencies.
- **Backend**: Express.js REST API with route modularity, security headers (Helmet, CORS), rate limiting, and in-memory mock repository.
- **Database Ready**: Prepared schema mappings for PostgreSQL / Prisma / TypeORM.
- **Testing**: Comprehensive automated test suites using Jest & Supertest, plus a complete Enterprise Test Matrix covering edge cases, security, concurrency, and compliance.

---

## 🧪 Running Automated Tests
```bash
npm test
```
