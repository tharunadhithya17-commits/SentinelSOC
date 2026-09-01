# SentinelSOC — Antigravity Development Guide

Open this folder as the project root.

## Goal
Develop the SentinelSOC Mini SOC web application from the supplied project requirements.

## Current implementation
- frontend/: React + Vite SOC dashboard
- backend/: Express API with JWT login and safe mock SOC data
- No real malware execution or real endpoint response actions
- Test response actions must remain SIMULATED

## Start
Backend:
`cd backend && npm install && npm start`

Frontend:
`cd frontend && npm install && npm run dev`

Demo login:
`analyst / analyst123`

## Next development direction
Preserve the existing UI and progressively add:
1. routing
2. persistent database
3. complete alert details
4. modular detection engine
5. incident workflow
6. endpoint details
7. threat-intel UI
8. MITRE matrix
9. investigation workbench
10. log explorer
11. demo mode / polling
12. report generation
13. security hardening
14. Docker

Do not hardcode secrets. Keep external threat-intelligence keys server-side in environment variables.
