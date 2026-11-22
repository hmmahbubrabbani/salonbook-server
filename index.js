import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import Stripe from 'stripe';
import { MongoClient, ObjectId } from 'mongodb';

// ---------------------------------------------------------------------------
// 1. Environment Configuration & Startup Guard (salonbook-server)
// ---------------------------------------------------------------------------
const PORT = Number(process.env.PORT) || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const CLIENT_URL = (
  process.env.CLIENT_URL || 'https://salonbook-frontend-opal.vercel.app'
)
  .trim()
  .replace(/\/$/, '');
const MONGODB_URI = (process.env.MONGODB_URI || '').trim();
const MONGODB_DB_NAME = (process.env.MONGODB_DB_NAME || 'salonbook').trim();
const JWT_SECRET = (
  process.env.BETTER_AUTH_SECRET ||
  process.env.JWT_ACCESS_SECRET ||
  ''
).trim();
const STRIPE_SECRET_KEY = (process.env.STRIPE_SECRET_KEY || '').trim();
const STRIPE_WEBHOOK_SECRET = (process.env.STRIPE_WEBHOOK_SECRET || '').trim();
const IMGBB_API_KEY = (process.env.IMGBB_API_KEY || '').trim();
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const ADMIN_NAME = (process.env.ADMIN_NAME || 'SalonBook Admin').trim();

if (!CLIENT_URL) {
  console.error('[SalonBook] Missing CLIENT_URL in environment variables.');
  process.exit(1);
}

if (!MONGODB_URI) {
  console.error('[SalonBook] Missing MONGODB_URI in environment variables.');
  process.exit(1);
}

if (!JWT_SECRET || JWT_SECRET.length < 16) {
  console.error(
    '[SalonBook] Missing or too short JWT_ACCESS_SECRET (minimum 16 characters).'
  );
  process.exit(1);
}

const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// ---------------------------------------------------------------------------
// 2. MongoDB Connection & Indexes
// ---------------------------------------------------------------------------
const mongoClient = new MongoClient(MONGODB_URI, {
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
});

let db;
let dbInitPromise = null;

function cols() {
  if (!db) {
    throw new Error('Database connection is not initialized.');
  }
  return {
    users: db.collection('user'),
    accounts: db.collection('account'),
    services: db.collection('services'),
    appointments: db.collection('appointments'),
    transactions: db.collection('transactions'),
  };
}

async function ensureIndexSafe(collection, keys, options = {}) {
  try {
    await collection.createIndex(keys, options);
  } catch (err) {
    if (err?.code === 85 || err?.code === 86 || err?.code === 11000) {
      console.warn(
        `[SalonBook] Skipped index on ${collection.collectionName} (${JSON.stringify(keys)}): code ${err.code}`
      );
      return;
    }
    throw err;
  }
}

async function initDatabase() {
  await mongoClient.connect();
  db = mongoClient.db(MONGODB_DB_NAME);

  const { users, services, appointments, transactions } = cols();
  await Promise.all([
    ensureIndexSafe(users, { email: 1 }, { unique: true }),
    ensureIndexSafe(services, { isActive: 1 }),
    ensureIndexSafe(appointments, { date: 1, startTime: 1, status: 1 }),
    ensureIndexSafe(transactions, { stripeSessionId: 1 }, { unique: true, sparse: true }),
  ]);

  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const existingAdmin = await users.findOne({ email: ADMIN_EMAIL });
    if (!existingAdmin) {
      const now = new Date().toISOString();
      const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
      await users.insertOne({
        name: ADMIN_NAME,
        email: ADMIN_EMAIL,
        passwordHash,
        role: 'admin',
        phone: '',
        avatarUrl: '',
        image: '',
        emailVerified: true,
        isBlocked: false,
        createdAt: now,
        updatedAt: now,
      });
      console.log(`[SalonBook] Seeded admin account: ${ADMIN_EMAIL}`);
    }
  }

  console.log(`[SalonBook] Connected to MongoDB (${MONGODB_DB_NAME})`);
}

async function ensureDatabaseReady() {
  if (db) return db;
  if (!dbInitPromise) {
    dbInitPromise = initDatabase().catch((err) => {
      dbInitPromise = null;
      throw err;
    });
  }
  await dbInitPromise;
  return db;
}

// ---------------------------------------------------------------------------
// 3. Helper Functions & Middlewares
// ---------------------------------------------------------------------------
function cookieOptions() {
  const isHttps = NODE_ENV === 'production' || CLIENT_URL.startsWith('https://');
  return {
    httpOnly: true,
    secure: isHttps,
    sameSite: isHttps ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  };
}

function issueTokenCookie(res, user) {
  const token = jwt.sign(
    { userId: String(user._id), email: user.email, role: user.role || 'client' },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.cookie('salonbook_token', token, cookieOptions());
  return token;
}

function formatSafeUser(userDoc) {
  return {
    _id: userDoc._id.toHexString(),
    name: userDoc.name,
    email: userDoc.email,
    role: userDoc.role === 'admin' ? 'admin' : 'client',
    phone: userDoc.phone || '',
    avatarUrl: userDoc.avatarUrl || userDoc.image || '',
    isBlocked: Boolean(userDoc.isBlocked),
  };
}

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < 6) {
    return 'Password must be at least 6 characters long.';
  }
  if (!/[A-Z]/.test(password)) {
    return 'Password must contain at least one uppercase letter.';
  }
  if (!/[a-z]/.test(password)) {
    return 'Password must contain at least one lowercase letter.';
  }
  return null;
}

async function resolveBetterAuthUserFromCookieHeader(cookieHeader) {
  if (!cookieHeader) return null;
  try {
    const res = await fetch(`${CLIENT_URL}/api/auth/get-session`, {
      method: 'GET',
      headers: {
        cookie: cookieHeader,
        Origin: CLIENT_URL,
      },
      cache: 'no-store',
    });
    if (!res.ok) {
      console.warn('[SalonBook] get-session returned status:', res.status);
      return null;
    }
    const data = await res.json().catch(() => null);
    const email = String(data?.user?.email || '').toLowerCase().trim();
    if (!email) return null;

    const { users } = cols();
    return users.findOne({ email }, { projection: { passwordHash: 0, password: 0 } });
  } catch (err) {
    console.warn('[SalonBook] Failed to resolve Better Auth session:', err);
    return null;
  }
}

async function requireAuth(req, res, next) {
  try {
    const token =
      req.cookies?.salonbook_token ||
      (req.headers.authorization?.startsWith('Bearer ')
        ? req.headers.authorization.slice(7)
        : null);

    if (!token) {
      return res.status(401).json({ success: false, message: 'Authentication required.' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const { users } = cols();

    const query = ObjectId.isValid(decoded.userId)
      ? { _id: new ObjectId(decoded.userId) }
      : { email: String(decoded.email || '').toLowerCase() };

    const userDoc = await users.findOne(query, {
      projection: { passwordHash: 0, password: 0 },
    });

    if (!userDoc) {
      return res.status(401).json({ success: false, message: 'User account not found.' });
    }

    if (userDoc.isBlocked) {
      return res.status(403).json({
        success: false,
        code: 'USER_BLOCKED',
        message: 'Your account is blocked. Please contact SalonBook support.',
      });
    }

    req.user = formatSafeUser(userDoc);
    return next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired session.' });
  }
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, message: 'Authentication required.' });
    }
    if (req.user.isBlocked) {
      return res.status(403).json({ success: false, message: 'Account is blocked.' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Forbidden: you do not have permission for this action.',
      });
    }
    return next();
  };
}

async function recordVerifiedPayment(session) {
  const appointmentId = session.metadata?.appointmentId;
  if (!appointmentId || !ObjectId.isValid(appointmentId)) return null;

  const { appointments, transactions } = cols();
  const apptObjId = new ObjectId(appointmentId);
  const appointment = await appointments.findOne({ _id: apptObjId });
  if (!appointment) return null;

  const now = new Date().toISOString();
  await appointments.updateOne(
    { _id: apptObjId },
    {
      $set: {
        paymentStatus: 'Paid',
        stripeSessionId: session.id,
        updatedAt: now,
      },
    }
  );

  await transactions.updateOne(
    { stripeSessionId: session.id },
    {
      $setOnInsert: {
        appointmentId: apptObjId.toHexString(),
        clientId: appointment.clientId,
        customerName: appointment.customerName,
        customerEmail: appointment.customerEmail,
        serviceId: appointment.serviceId,
        serviceTitle: appointment.serviceTitle,
        appointmentDate: appointment.date,
        amountCents: session.amount_total ?? Number(appointment.servicePriceCents),
        currency: (session.currency || 'usd').toUpperCase(),
        stripeSessionId: session.id,
        paymentStatus: 'Paid',
        createdAt: now,
      },
    },
    { upsert: true }
  );

  return transactions.findOne({ stripeSessionId: session.id });
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
});

// ---------------------------------------------------------------------------
// 4. Express App Setup
// ---------------------------------------------------------------------------
const app = express();
app.set('trust proxy', 1);

app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok', service: 'salonbook-api' });
});

const allowedOrigins = new Set([CLIENT_URL]);
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.has(origin.replace(/\/$/, ''))) {
        callback(null, true);
      } else {
        callback(new Error(`CORS policy blocked origin: ${origin}`));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// Ensure MongoDB connection is ready before handling API routes
app.use(async (req, res, next) => {
  if (req.path === '/health') return next();
  try {
    await ensureDatabaseReady();
    return next();
  } catch (err) {
    return next(err);
  }
});

// Stripe Webhook MUST receive raw body BEFORE express.json()
app.post(
  '/api/v1/payments/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    if (!stripe || !STRIPE_WEBHOOK_SECRET) {
      return res.status(500).json({ error: 'Stripe webhook is not configured.' });
    }

    const sig = req.headers['stripe-signature'];
    if (!sig) {
      return res.status(400).json({ error: 'Missing stripe-signature header.' });
    }

    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      return res.status(400).send(`Webhook signature verification failed: ${err.message}`);
    }

    try {
      if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        if (session.payment_status === 'paid') {
          await recordVerifiedPayment(session);
        }
      }
      return res.status(200).json({ received: true });
    } catch (err) {
      console.error('[Stripe Webhook Error]', err);
      return res.status(500).json({ error: 'Failed to process webhook event.' });
    }
  }
);

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ---------------------------------------------------------------------------
// 5. Authentication & Profile Routes
// ---------------------------------------------------------------------------
app.post('/api/v1/auth/register', async (req, res, next) => {
  try {
    const { name, email, password, avatarUrl, image, phone } = req.body || {};
    const normalizedEmail = String(email || '').toLowerCase().trim();
    const resolvedAvatar = String(avatarUrl || image || '').trim();

    if (!String(name || '').trim() || !normalizedEmail || !password) {
      return res.status(400).json({
        success: false,
        message: 'Full name, email, and password are required.',
      });
    }

    const pwError = validatePassword(password);
    if (pwError) {
      return res.status(400).json({ success: false, message: pwError });
    }

    const { users, accounts } = cols();
    const existing = await users.findOne({ email: normalizedEmail });
    if (existing) {
      return res.status(409).json({
        success: false,
        message: 'An account with this email already exists.',
      });
    }

    const now = new Date().toISOString();
    const passwordHash = await bcrypt.hash(password, 12);

    const doc = {
      name: String(name).trim(),
      email: normalizedEmail,
      passwordHash,
      role: 'client',
      phone: String(phone || '').trim(),
      avatarUrl: resolvedAvatar,
      image: resolvedAvatar,
      emailVerified: false,
      isBlocked: false,
      createdAt: now,
      updatedAt: now,
    };

    const result = await users.insertOne(doc);
    const createdUser = formatSafeUser({ _id: result.insertedId, ...doc });

    await accounts.updateOne(
      {
        providerId: 'credential',
        accountId: normalizedEmail,
      },
      {
        $setOnInsert: {
          userId: result.insertedId.toHexString(),
          accountId: normalizedEmail,
          providerId: 'credential',
          password: passwordHash,
          createdAt: now,
        },
        $set: {
          updatedAt: now,
        },
      },
      { upsert: true }
    );

    const token = issueTokenCookie(res, createdUser);
    return res.status(201).json({
      success: true,
      message: 'Registration successful.',
      token,
      user: createdUser,
    });
  } catch (err) {
    return next(err);
  }
});

app.post('/api/v1/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    const normalizedEmail = String(email || '').toLowerCase().trim();

    if (!normalizedEmail || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required.',
      });
    }

    const { users, accounts } = cols();
    const userDoc = await users.findOne({ email: normalizedEmail });
    if (!userDoc) {
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }

    if (userDoc.isBlocked) {
      return res.status(403).json({
        success: false,
        message: 'Your account is blocked. Please contact SalonBook support.',
      });
    }

    let storedHash = userDoc.passwordHash || userDoc.password || null;
    if (!storedHash) {
      const accountDoc = await accounts.findOne({
        providerId: 'credential',
        $or: [
          { userId: userDoc._id.toHexString() },
          { userId: userDoc._id },
          { accountId: normalizedEmail },
        ],
      });
      storedHash = accountDoc?.password || null;
    }

    let valid = false;
    if (storedHash && storedHash.startsWith('$2')) {
      valid = await bcrypt.compare(password, storedHash);
    }

    if (!valid) {
      try {
        const baRes = await fetch(`${CLIENT_URL}/api/auth/sign-in/email`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Origin: CLIENT_URL },
          body: JSON.stringify({ email: normalizedEmail, password }),
        });
        if (baRes.ok) {
          valid = true;
        }
      } catch {
        // Ignore and fall through
      }
    }

    if (!valid) {
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }

    const safeUser = formatSafeUser(userDoc);
    const token = issueTokenCookie(res, safeUser);
    return res.status(200).json({
      success: true,
      message: 'Signed in successfully.',
      token,
      user: safeUser,
    });
  } catch (err) {
    return next(err);
  }
});

// Sync Better Auth session (e.g., after Google OAuth callback) into salonbook_token cookie
app.post('/api/v1/auth/sync-session', async (req, res, next) => {
  try {
    const userDoc = await resolveBetterAuthUserFromCookieHeader(req.headers.cookie);

    if (!userDoc) {
      return res.status(401).json({ success: false, message: 'No active session found.' });
    }

    if (userDoc.isBlocked) {
      return res.status(403).json({
        success: false,
        message: 'Your account is blocked. Please contact SalonBook support.',
      });
    }

    const { name, avatarUrl } = req.body || {};
    const trimmedName = String(name || '').trim();
    const trimmedAvatar = String(avatarUrl || '').trim();
    const profileUpdates = {};

    if (trimmedName && trimmedName !== userDoc.name) {
      profileUpdates.name = trimmedName;
    }
    if (trimmedAvatar && trimmedAvatar !== (userDoc.avatarUrl || userDoc.image || '')) {
      profileUpdates.avatarUrl = trimmedAvatar;
      profileUpdates.image = trimmedAvatar;
    }

    let finalDoc = userDoc;
    if (Object.keys(profileUpdates).length > 0) {
      profileUpdates.updatedAt = new Date().toISOString();
      const { users } = cols();
      const updatedDoc = await users.findOneAndUpdate(
        { _id: userDoc._id },
        { $set: profileUpdates },
        { returnDocument: 'after', projection: { passwordHash: 0, password: 0 } }
      );
      if (updatedDoc) {
        finalDoc = updatedDoc;
      }
    }

    const safeUser = formatSafeUser(finalDoc);
    const token = issueTokenCookie(res, safeUser);
    return res.status(200).json({ success: true, token, user: safeUser });
  } catch (err) {
    return next(err);
  }
});

app.post('/api/v1/auth/logout', (_req, res) => {
  const opts = cookieOptions();
  const clearOpts = {
    httpOnly: opts.httpOnly,
    secure: opts.secure,
    sameSite: opts.sameSite,
    path: '/',
  };
  res.clearCookie('salonbook_token', clearOpts);
  res.clearCookie('better-auth.session_token', clearOpts);
  res.clearCookie('__Secure-better-auth.session_token', clearOpts);
  return res.status(200).json({ success: true, message: 'Signed out.' });
});

app.get('/api/v1/auth/me', requireAuth, (req, res) => {
  return res.status(200).json({ success: true, user: req.user });
});

app.patch('/api/v1/profile', requireAuth, async (req, res, next) => {
  try {
    const { name, phone, avatarUrl } = req.body || {};
    const trimmedName = String(name || '').trim();
    if (!trimmedName) {
      return res.status(400).json({ success: false, message: 'Name is required.' });
    }

    const { users } = cols();
    const filter = ObjectId.isValid(req.user._id)
      ? { _id: new ObjectId(req.user._id) }
      : { email: req.user.email };

    const trimmedAvatar = String(avatarUrl || '').trim();
    const updated = await users.findOneAndUpdate(
      filter,
      {
        $set: {
          name: trimmedName,
          phone: String(phone || '').trim(),
          avatarUrl: trimmedAvatar,
          image: trimmedAvatar,
          updatedAt: new Date().toISOString(),
        },
      },
      { returnDocument: 'after', projection: { passwordHash: 0, password: 0 } }
    );

    return res.status(200).json({
      success: true,
      message: 'Profile updated.',
      user: updated
        ? formatSafeUser(updated)
        : {
            ...req.user,
            name: trimmedName,
            phone: String(phone || '').trim(),
            avatarUrl: trimmedAvatar,
          },
    });
  } catch (err) {
    return next(err);
  }
});

// ---------------------------------------------------------------------------
// 6. Services Routes
// ---------------------------------------------------------------------------
app.get('/api/v1/services', async (req, res, next) => {
  try {
    const { services } = cols();
    const includeAll = req.query.all === 'true';

    if (includeAll) {
      return requireAuth(req, res, () =>
        requireRole('admin')(req, res, async () => {
          const allDocs = await services.find({}).sort({ createdAt: -1 }).toArray();
          return res.status(200).json({ success: true, services: allDocs });
        })
      );
    }

    const activeDocs = await services.find({ isActive: true }).sort({ createdAt: -1 }).toArray();
    return res.status(200).json({ success: true, services: activeDocs });
  } catch (err) {
    return next(err);
  }
});

app.get('/api/v1/services/:id', requireAuth, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid service ID.' });
    }

    const { services } = cols();
    const service = await services.findOne({ _id: new ObjectId(id) });
    if (!service) {
      return res.status(404).json({ success: false, message: 'Service not found.' });
    }

    return res.status(200).json({ success: true, service, user: req.user });
  } catch (err) {
    return next(err);
  }
});

app.post('/api/v1/services', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { title, description, category, durationMinutes, priceCents, imageUrl, isActive } =
      req.body || {};

    const trimmedTitle = String(title || '').trim();
    const trimmedCategory = String(category || '').trim();
    const trimmedDesc = String(description || '').trim();
    const trimmedImg = String(imageUrl || '').trim();
    const numericPrice = Number(priceCents);
    const numericDuration = Number(durationMinutes);

    if (!trimmedTitle || !trimmedCategory || !trimmedDesc || !trimmedImg) {
      return res.status(400).json({
        success: false,
        message: 'Title, category, description, and uploaded image are required.',
      });
    }

    if (!Number.isFinite(numericPrice) || numericPrice <= 0) {
      return res.status(400).json({ success: false, message: 'Price must be positive.' });
    }

    if (!Number.isFinite(numericDuration) || numericDuration <= 0) {
      return res.status(400).json({ success: false, message: 'Duration must be positive.' });
    }

    const now = new Date().toISOString();
    const doc = {
      title: trimmedTitle,
      description: trimmedDesc,
      category: trimmedCategory,
      durationMinutes: Math.round(numericDuration),
      priceCents: Math.round(numericPrice),
      imageUrl: trimmedImg,
      isActive: isActive !== undefined ? Boolean(isActive) : true,
      createdAt: now,
      updatedAt: now,
    };

    const { services } = cols();
    const result = await services.insertOne(doc);
    return res.status(201).json({
      success: true,
      service: { _id: result.insertedId.toHexString(), ...doc },
    });
  } catch (err) {
    return next(err);
  }
});

app.patch('/api/v1/services/:id', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid service ID.' });
    }

    const body = req.body || {};
    const updates = { updatedAt: new Date().toISOString() };

    if (body.title !== undefined) updates.title = String(body.title).trim();
    if (body.category !== undefined) updates.category = String(body.category).trim();
    if (body.description !== undefined) updates.description = String(body.description).trim();
    if (body.imageUrl !== undefined) updates.imageUrl = String(body.imageUrl).trim();
    if (body.isActive !== undefined) updates.isActive = Boolean(body.isActive);

    if (body.priceCents !== undefined) {
      const p = Number(body.priceCents);
      if (!Number.isFinite(p) || p <= 0) {
        return res.status(400).json({ success: false, message: 'Price must be positive.' });
      }
      updates.priceCents = Math.round(p);
    }

    if (body.durationMinutes !== undefined) {
      const d = Number(body.durationMinutes);
      if (!Number.isFinite(d) || d <= 0) {
        return res.status(400).json({ success: false, message: 'Duration must be positive.' });
      }
      updates.durationMinutes = Math.round(d);
    }

    const { services } = cols();
    const updated = await services.findOneAndUpdate(
      { _id: new ObjectId(id) },
      { $set: updates },
      { returnDocument: 'after' }
    );

    if (!updated) {
      return res.status(404).json({ success: false, message: 'Service not found.' });
    }

    return res.status(200).json({ success: true, service: updated });
  } catch (err) {
    return next(err);
  }
});

app.delete('/api/v1/services/:id', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid service ID.' });
    }

    const { services } = cols();
    const result = await services.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: 'Service not found.' });
    }

    return res.status(200).json({ success: true, message: 'Service deleted.' });
  } catch (err) {
    return next(err);
  }
});

// ---------------------------------------------------------------------------
// 7. Appointments Routes
// ---------------------------------------------------------------------------
app.get('/api/v1/appointments', requireAuth, async (req, res, next) => {
  try {
    const { appointments } = cols();
    const filter = req.user.role === 'admin' ? {} : { clientId: req.user._id };
    const list = await appointments.find(filter).sort({ createdAt: -1 }).toArray();
    return res.status(200).json({ success: true, appointments: list });
  } catch (err) {
    return next(err);
  }
});

app.post('/api/v1/appointments', requireAuth, requireRole('client'), async (req, res, next) => {
  try {
    const { serviceId, date, startTime, message } = req.body || {};
    const trimmedDate = String(date || '').trim();
    const trimmedSlot = String(startTime || '').trim();

    if (!serviceId || !ObjectId.isValid(serviceId) || !trimmedDate || !trimmedSlot) {
      return res.status(400).json({
        success: false,
        message: 'Service ID, appointment date, and time slot are required.',
      });
    }

    const { services, appointments } = cols();
    const service = await services.findOne({ _id: new ObjectId(serviceId) });
    if (!service) {
      return res.status(404).json({ success: false, message: 'Service not found.' });
    }

    if (!service.isActive) {
      return res.status(400).json({
        success: false,
        message: 'Inactive services are not available for booking.',
      });
    }

    const conflict = await appointments.findOne({
      date: trimmedDate,
      startTime: trimmedSlot,
      status: { $in: ['Pending', 'Confirmed'] },
    });

    if (conflict) {
      return res.status(409).json({
        success: false,
        message: `Slot ${trimmedSlot} on ${trimmedDate} is already booked.`,
      });
    }

    const now = new Date().toISOString();
    const doc = {
      clientId: req.user._id,
      customerName: req.user.name,
      customerEmail: req.user.email,
      serviceId: service._id.toHexString(),
      serviceTitle: service.title,
      serviceCategory: service.category,
      serviceImage: service.imageUrl || '',
      servicePriceCents: Number(service.priceCents),
      date: trimmedDate,
      startTime: trimmedSlot,
      message: String(message || '').trim(),
      status: 'Pending',
      paymentStatus: 'Unpaid',
      createdAt: now,
      updatedAt: now,
    };

    const result = await appointments.insertOne(doc);
    return res.status(201).json({
      success: true,
      appointment: { _id: result.insertedId.toHexString(), ...doc },
    });
  } catch (err) {
    return next(err);
  }
});

app.patch('/api/v1/appointments/:id', requireAuth, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid appointment ID.' });
    }

    const { appointments } = cols();
    const apptObjId = new ObjectId(id);
    const appointment = await appointments.findOne({ _id: apptObjId });
    if (!appointment) {
      return res.status(404).json({ success: false, message: 'Appointment not found.' });
    }

    const nextStatus = String(req.body?.status || '');

    if (req.user.role === 'client') {
      if (appointment.clientId !== req.user._id) {
        return res.status(403).json({ success: false, message: 'Forbidden.' });
      }
      if (nextStatus !== 'Cancelled' || appointment.status !== 'Pending') {
        return res.status(400).json({
          success: false,
          message: 'Customers can only cancel their own Pending appointments.',
        });
      }
    } else if (req.user.role === 'admin') {
      if (nextStatus === 'Confirmed' && appointment.status !== 'Pending') {
        return res.status(400).json({
          success: false,
          message: 'Only Pending appointments can be confirmed.',
        });
      }
      if (
        nextStatus === 'Cancelled' &&
        !['Pending', 'Confirmed'].includes(String(appointment.status))
      ) {
        return res.status(400).json({
          success: false,
          message: 'Only Pending or Confirmed appointments can be cancelled.',
        });
      }
      if (!['Confirmed', 'Cancelled'].includes(nextStatus)) {
        return res.status(400).json({ success: false, message: 'Invalid status value.' });
      }
    }

    const updated = await appointments.findOneAndUpdate(
      { _id: apptObjId },
      { $set: { status: nextStatus, updatedAt: new Date().toISOString() } },
      { returnDocument: 'after' }
    );

    return res.status(200).json({ success: true, appointment: updated });
  } catch (err) {
    return next(err);
  }
});

// ---------------------------------------------------------------------------
// 8. Stripe Checkout, Verification & Transactions Routes
// ---------------------------------------------------------------------------
app.post('/api/v1/payments/checkout', requireAuth, requireRole('client'), async (req, res, next) => {
  try {
    if (!stripe) {
      return res.status(500).json({ success: false, message: 'Stripe is not configured.' });
    }

    const { appointmentId } = req.body || {};
    if (!appointmentId || !ObjectId.isValid(appointmentId)) {
      return res.status(400).json({ success: false, message: 'Invalid appointment ID.' });
    }

    const { appointments } = cols();
    const apptObjId = new ObjectId(appointmentId);
    const appointment = await appointments.findOne({ _id: apptObjId });

    if (!appointment) {
      return res.status(404).json({ success: false, message: 'Appointment not found.' });
    }

    if (appointment.clientId !== req.user._id) {
      return res.status(403).json({ success: false, message: 'Forbidden.' });
    }

    if (appointment.status !== 'Confirmed') {
      return res.status(400).json({
        success: false,
        message: 'Only Confirmed appointments can be paid.',
      });
    }

    if (appointment.paymentStatus === 'Paid') {
      return res.status(400).json({
        success: false,
        message: 'This appointment is already paid.',
      });
    }

    const unitAmount = Math.round(Number(appointment.servicePriceCents));
    if (!Number.isFinite(unitAmount) || unitAmount < 50) {
      return res.status(400).json({
        success: false,
        message: 'Invalid service price for Stripe checkout.',
      });
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      customer_email: req.user.email,
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: `${appointment.serviceTitle} (${appointment.date} ${appointment.startTime})`,
            },
            unit_amount: unitAmount,
          },
          quantity: 1,
        },
      ],
      metadata: {
        appointmentId: apptObjId.toHexString(),
        clientId: req.user._id,
      },
      success_url: `${CLIENT_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${CLIENT_URL}/payment/cancel?appointmentId=${apptObjId.toHexString()}`,
    });

    await appointments.updateOne(
      { _id: apptObjId },
      { $set: { stripeSessionId: session.id, updatedAt: new Date().toISOString() } }
    );

    return res.status(201).json({ success: true, url: session.url });
  } catch (err) {
    return next(err);
  }
});

app.get('/api/v1/payments/verify', requireAuth, async (req, res, next) => {
  try {
    if (!stripe) {
      return res.status(500).json({ success: false, message: 'Stripe is not configured.' });
    }

    const sessionId = String(req.query.session_id || '').trim();
    if (!sessionId) {
      return res.status(400).json({ success: false, message: 'Missing session_id.' });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.payment_status !== 'paid') {
      return res.status(400).json({ success: false, message: 'Payment not completed.' });
    }

    const transaction = await recordVerifiedPayment(session);
    return res.status(200).json({ success: true, transaction });
  } catch (err) {
    return next(err);
  }
});

app.get('/api/v1/transactions', requireAuth, requireRole('admin'), async (_req, res, next) => {
  try {
    const { transactions } = cols();
    const list = await transactions.find({}).sort({ createdAt: -1 }).toArray();
    return res.status(200).json({ success: true, transactions: list });
  } catch (err) {
    return next(err);
  }
});

// ---------------------------------------------------------------------------
// 9. Admin User Management & ImgBB Upload Routes
// ---------------------------------------------------------------------------
app.get('/api/v1/users', requireAuth, requireRole('admin'), async (_req, res, next) => {
  try {
    const { users } = cols();
    const list = await users
      .find({ role: { $ne: 'admin' } }, { projection: { passwordHash: 0, password: 0 } })
      .sort({ createdAt: -1 })
      .toArray();
    return res.status(200).json({ success: true, users: list });
  } catch (err) {
    return next(err);
  }
});

app.patch('/api/v1/users/:id/block', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID.' });
    }

    const { users } = cols();
    const updated = await users.findOneAndUpdate(
      { _id: new ObjectId(id), role: { $ne: 'admin' } },
      { $set: { isBlocked: Boolean(req.body?.isBlocked), updatedAt: new Date().toISOString() } },
      { returnDocument: 'after', projection: { passwordHash: 0, password: 0 } }
    );

    if (!updated) {
      return res.status(404).json({ success: false, message: 'Customer not found.' });
    }

    return res.status(200).json({ success: true, user: updated });
  } catch (err) {
    return next(err);
  }
});

app.post('/api/v1/upload', upload.single('image'), async (req, res, next) => {
  try {
    if (!IMGBB_API_KEY) {
      return res.status(500).json({ success: false, message: 'IMGBB_API_KEY is not set.' });
    }
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Image file is required.' });
    }

    const params = new URLSearchParams();
    params.append('key', IMGBB_API_KEY);
    params.append('image', req.file.buffer.toString('base64'));

    const response = await fetch('https://api.imgbb.com/1/upload', {
      method: 'POST',
      body: params,
    });
    const data = await response.json();

    if (!response.ok || !data?.success || !data?.data?.display_url) {
      return res.status(502).json({ success: false, message: 'ImgBB image upload failed.' });
    }

    return res.status(201).json({ success: true, url: data.data.display_url });
  } catch (err) {
    return next(err);
  }
});

// ---------------------------------------------------------------------------
// 10. 404 & Global Error Handlers
// ---------------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'API route not found.',
    debug: {
      method: req.method,
      url: req.url,
      originalUrl: req.originalUrl,
      path: req.path,
    },
  });
});

app.use((err, _req, res, _next) => {
  const status = err.statusCode || 500;
  res.status(status).json({
    success: false,
    message: NODE_ENV === 'production' && status === 500 ? 'Internal server error.' : err.message,
  });
});

// ---------------------------------------------------------------------------
// 11. Start Server (Local vs Vercel Serverless)
// ---------------------------------------------------------------------------
if (!process.env.VERCEL) {
  ensureDatabaseReady()
    .then(() => {
      app.listen(PORT, () => {
        console.log(`[SalonBook] Express server listening on port ${PORT} (${NODE_ENV})`);
      });
    })
    .catch((err) => {
      console.error('[SalonBook] Failed to start server:', err);
      process.exit(1);
    });
}

export default app;

