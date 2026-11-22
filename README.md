# SalonBook Server

Express.js and MongoDB REST API server for **SalonBook**, a salon appointment booking and beauty service management platform. It handles authentication, role-based authorization, slot-conflict prevention, Stripe payment checkout and webhook verification, admin management, and image uploads via ImgBB.

## Important Features

- **Authentication & Session Sync:** Email/password registration and login with `bcrypt` password hashing, `httpOnly` JWT cookie issuance (`salonbook_token`), Better Auth session synchronization (`/api/v1/auth/sync-session`), profile updates, and logout cookie cleanup.
- **Role-Based Access Control (RBAC):** `requireAuth` and `requireRole('admin' | 'client')` middlewares protect routes and enforce user block checks (`isBlocked`).
- **Salon Services Management:** Public listing of active services, admin-only full service view (`?all=true`), and admin CRUD endpoints (`POST`, `PATCH`, `DELETE` on `/api/v1/services`).
- **Appointment Booking & Conflict Detection:** Clients can book active services for a date and time slot with automatic overlap checks against `Pending` and `Confirmed` appointments, while clients and admins manage appointment statuses (`Confirmed`, `Cancelled`).
- **Stripe Payments & Webhooks:** Creates Stripe Checkout sessions for `Confirmed` unpaid appointments, verifies completed sessions, records transactions in MongoDB, and processes raw-body Stripe webhooks (`/api/v1/payments/webhook`).
- **Admin User Controls & Image Uploads:** Admins can view non-admin users and toggle account block/unblock status; `/api/v1/upload` uploads images to ImgBB using `multer` memory storage.

## Technology Stack

- **Runtime & Framework:** Node.js, Express.js
- **Database:** MongoDB (Native MongoDB Driver with index initialization)
- **Authentication & Security:** `jsonwebtoken`, `bcryptjs`, `cookie-parser`, `cors`, Better Auth session sync
- **Payments:** Stripe (`stripe` SDK + raw-body webhook verification)
- **File Uploads & Config:** `multer`, `dotenv`

## Installation Instructions

1. Clone the server repository and move into the project directory:
   ```bash
   git clone <https://github.com/hmmahbubrabbani/salonbook-server.git>
   cd salonbook-server