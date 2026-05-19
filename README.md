# project-name

Brief one-liner about what this is.

## Features
- JWT authentication with refresh token support
- bcrypt password hashing (cost factor 12)
- UUID-based resource IDs (prevents enumeration)
- Zod input validation
- Parameterized queries (SQL injection prevention)
- Rate limiting on auth routes
- Helmet security headers

## Tech Stack
Node.js, Express, MySQL, mysql2, bcrypt, jsonwebtoken, uuid, zod, morgan

## Getting Started

# 1. Clone and install
npm install

# 3. Start
npm run dev

## API Reference
| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| POST | /auth/signup | No | Create account |
| POST | /auth/login | No | Get JWT |
| GET | /users/:id | Yes | Get own profile |
| PUT | /users/:id | Yes | Update own profile |
| DELETE | /users/:id | Yes | Delete own account |
