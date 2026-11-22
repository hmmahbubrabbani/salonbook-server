/**
 * Migration: fix Better Auth credential accounts created by salonbook-server.
 *
 * Bug: the Express register route stored
 *   userId   = hex string   (Better Auth stores ObjectId)
 *   accountId = email       (Better Auth requires accountId = user id)
 * Better Auth's findCredentialAccount() queries
 *   { userId: ObjectId(uid), providerId: "credential", accountId: uid }
 * so sign-in/email, password reset and setPassword never found these accounts.
 *
 * Fix (per account doc with providerId === "credential"):
 *   userId    -> ObjectId(uid)
 *   accountId -> uid hex string
 * Google accounts (providerId === "google") are NOT touched.
 * Also converts any string userId found in session/verification collections.
 *
 * Usage:
 *   node migrate-credential-accounts.mjs          # dry run (prints planned changes)
 *   node migrate-credential-accounts.mjs --apply  # perform the updates
 */
import { MongoClient, ObjectId } from 'mongodb';
import { readFileSync } from 'node:fs';

const APPLY = process.argv.includes('--apply');

const env = {};
for (const line of readFileSync(new URL('./.env', import.meta.url), 'utf8').split(/\r?\n/)) {
  const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
  if (m) env[m[1]] = m[2];
}
const uri = (env.MONGODB_URI || '').trim();
const dbName = (env.MONGODB_DB_NAME || 'SalonBookDB').trim();
if (!uri) {
  console.error('MONGODB_URI missing from salonbook-server/.env');
  process.exit(1);
}

const isUid = (v) => typeof v === 'string' && /^[0-9a-f]{24}$/i.test(v);

const client = new MongoClient(uri, { serverSelectionTimeoutMS: 15000 });
await client.connect();
const db = client.db(dbName);
console.log(`${APPLY ? 'APPLY' : 'DRY-RUN'} mode | database: ${dbName}\n`);

// ---------------------------------------------------------------------------
// 1. account collection — the actual bug
// ---------------------------------------------------------------------------
const userById = new Map();
for (const u of await db.collection('user').find({}, { projection: { email: 1 } }).toArray()) {
  userById.set(u._id.toHexString(), u.email);
}

const accounts = await db
  .collection('account')
  .find({ providerId: 'credential' })
  .toArray();

const accountUpdates = [];
const skipped = [];
for (const a of accounts) {
  const uidHex =
    a.userId instanceof ObjectId ? a.userId.toHexString() : isUid(a.userId) ? a.userId : null;

  if (!uidHex || !userById.has(uidHex)) {
    skipped.push(`_id=${a._id} userId=${String(a.userId)} (no matching user) — SKIPPED`);
    continue;
  }
  if (a.userId instanceof ObjectId && a.accountId === uidHex) continue; // already correct

  accountUpdates.push({
    updateOne: {
      filter: { _id: a._id },
      update: {
        $set: {
          userId: new ObjectId(uidHex),
          accountId: uidHex,
          updatedAt: new Date().toISOString(),
        },
      },
    },
    describe:
      `user=${userById.get(uidHex)}\n` +
      `    userId:    ${a.userId instanceof ObjectId ? 'ObjectId' : 'string'}(${String(a.userId).slice(0, 24)}) -> ObjectId(${uidHex})\n` +
      `    accountId: "${String(a.accountId).slice(0, 40)}" -> "${uidHex}"`,
  });
}

console.log(`--- account (providerId=credential): ${accounts.length} total, ${accountUpdates.length} to fix ---`);
for (const u of accountUpdates) console.log(`  ${u.describe}`);
for (const s of skipped) console.log(`  ${s}`);

// Duplicate guard: two credential accounts pointing at the same user?
const dupCheck = new Map();
for (const a of accounts) {
  const uidHex = a.userId instanceof ObjectId ? a.userId.toHexString() : a.userId;
  dupCheck.set(uidHex, (dupCheck.get(uidHex) || 0) + 1);
}
const dups = [...dupCheck.entries()].filter(([, n]) => n > 1);
if (dups.length) {
  console.error('ABORT: duplicate credential accounts for userId(s):', dups);
  await client.close();
  process.exit(1);
}

// ---------------------------------------------------------------------------
// 2. session / verification — string userIds (same ObjectId coercion)
// ---------------------------------------------------------------------------
const otherUpdates = [];
for (const collName of ['session', 'verification']) {
  const coll = db.collection(collName);
  const docs = await coll.find({ userId: { $type: 'string' } }).toArray();
  for (const d of docs) {
    if (!isUid(d.userId) || !userById.has(d.userId)) {
      skipped.push(`${collName} _id=${d._id} userId=${String(d.userId).slice(0, 30)} (no matching user) — SKIPPED`);
      continue;
    }
    otherUpdates.push({
      updateOne: {
        filter: { _id: d._id },
        update: { $set: { userId: new ObjectId(d.userId) } },
      },
      describe: `${collName} _id=${d._id}: userId string(${d.userId}) -> ObjectId`,
    });
  }
}
console.log(`\n--- session/verification: ${otherUpdates.length} string userId(s) to convert ---`);
for (const u of otherUpdates) console.log(`  ${u.describe}`);
for (const s of skipped) console.log(`  ${s}`);

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------
const allUpdates = [...accountUpdates, ...otherUpdates];
if (!APPLY) {
  console.log(`\nDry run only — ${allUpdates.length} update(s) planned. Re-run with --apply to execute.`);
} else if (!allUpdates.length) {
  console.log('\nNothing to do — all credential accounts already correct.');
} else {
  const res = await db
    .collection('account')
    .bulkWrite(
      accountUpdates.map((u) => ({ updateOne: u.updateOne })),
      { ordered: true }
    );
  let modified = res.modifiedCount;
  if (otherUpdates.length) {
    // split by collection
    for (const collName of ['session', 'verification']) {
      const ops = otherUpdates.filter((u) => u.describe.startsWith(collName));
      if (ops.length) {
        const r = await db
          .collection(collName)
          .bulkWrite(
            ops.map((u) => ({ updateOne: u.updateOne })),
            { ordered: true }
          );
        modified += r.modifiedCount;
      }
    }
  }
  console.log(`\nApplied: ${modified} document(s) modified.`);
}

// ---------------------------------------------------------------------------
// 3. Verify — simulate Better Auth findCredentialAccount for every user
// ---------------------------------------------------------------------------
console.log('\n--- verification: Better Auth findCredentialAccount per user ---');
let pass = 0;
let fail = 0;
let noCredential = 0;
for (const u of await db.collection('user').find({}).toArray()) {
  const uid = u._id;
  const match = await db.collection('account').findOne({
    userId: uid,
    providerId: 'credential',
    accountId: uid.toHexString(),
  });
  const google = await db.collection('account').findOne({ userId: uid, providerId: 'google' });
  if (match) {
    pass++;
  } else if (google) {
    noCredential++;
    console.log(`  OK(google-only) ${u.email}`);
  } else {
    fail++;
    console.log(`  FAIL ${u.email} (no credential account)`);
  }
}
console.log(`\nResult: ${pass} credential OK, ${noCredential} google-only OK, ${fail} FAIL`);

await client.close();
process.exit(fail > 0 ? 2 : 0);
