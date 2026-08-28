const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const PORT = process.env.PORT || 3000;
const RP_ID = process.env.RP_ID || 'localhost';
const EXPECTED_ORIGIN = process.env.EXPECTED_ORIGIN || `http://localhost:${PORT}`;

app.use(express.json());
app.use(cors());
app.use(cookieParser());
app.use(session({
  secret: 'webauthn-secret-key-demo-2026',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(express.static(path.join(__dirname, 'public')));
app.use('/node_modules', express.static(path.join(__dirname, 'node_modules')));

// In-memory Database
// users: { [username]: { id: string, username: string, currentChallenge?: string, credentials: [...] } }
const db = {
  users: {}
};

function getUser(username) {
  if (!db.users[username]) {
    db.users[username] = {
      id: Buffer.from(username).toString('base64url'),
      username: username,
      credentials: []
    };
  }
  return db.users[username];
}

// -------------------------------------------------------------
// 1. REGISTRATION ENDPOINTS
// -------------------------------------------------------------

// Step 1: Generate Registration Options
app.post('/api/register/options', async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const user = getUser(username);

    const options = await generateRegistrationOptions({
      rpName: 'WebAuthn Test App',
      rpID: RP_ID,
      userID: new Uint8Array(Buffer.from(user.id)),
      userName: user.username,
      userDisplayName: user.username,
      excludeCredentials: user.credentials.map(cred => ({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports,
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      attestationType: 'none',
    });

    req.session.currentChallenge = options.challenge;
    req.session.username = username;

    res.json({ options });
  } catch (error) {
    console.error('Error generating registration options:', error);
    res.status(500).json({ error: error.message });
  }
});

// Step 2: Verify Registration Response
app.post('/api/register/verify', async (req, res) => {
  try {
    const { username, response, deviceName } = req.body;
    const expectedChallenge = req.session.currentChallenge;

    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Session expired or no challenge found' });
    }

    const user = getUser(username);

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: EXPECTED_ORIGIN,
      expectedRPID: RP_ID,
    });

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      const { credential, credentialDeviceType, credentialBackedUp } = registrationInfo;
      const { id, publicKey, counter, transports } = credential;

      const newCredential = {
        id,
        publicKey: Buffer.from(publicKey).toString('base64url'),
        counter,
        transports: transports || [],
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        name: deviceName || `Passkey (${new Date().toLocaleDateString()})`,
        createdAt: new Date().toISOString(),
      };

      user.credentials.push(newCredential);
      req.session.userId = user.id;
      req.session.username = user.username;

      res.json({
        verified: true,
        user: { username: user.username, credentialsCount: user.credentials.length },
        credential: newCredential
      });
    } else {
      res.status(400).json({ verified: false, error: 'Registration verification failed' });
    }
  } catch (error) {
    console.error('Error verifying registration:', error);
    res.status(500).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// 2. AUTHENTICATION (SIGN-IN) ENDPOINTS
// -------------------------------------------------------------

// Step 1: Generate Authentication Options
app.post('/api/login/options', async (req, res) => {
  try {
    const { username } = req.body;

    let allowCredentials;

    if (username) {
      const user = db.users[username];
      if (!user || user.credentials.length === 0) {
        return res.status(404).json({ error: 'No registered credentials found for this user' });
      }
      allowCredentials = user.credentials.map(cred => ({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports,
      }));
    }

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials,
      userVerification: 'preferred',
    });

    req.session.currentChallenge = options.challenge;
    if (username) req.session.authUsername = username;

    res.json({ options });
  } catch (error) {
    console.error('Error generating login options:', error);
    res.status(500).json({ error: error.message });
  }
});

// Step 2: Verify Authentication Response
app.post('/api/login/verify', async (req, res) => {
  try {
    const { username, response } = req.body;
    const expectedChallenge = req.session.currentChallenge;

    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Session challenge expired or missing' });
    }

    let matchingUser = null;
    let matchingCred = null;

    if (username && db.users[username]) {
      matchingUser = db.users[username];
      matchingCred = matchingUser.credentials.find(c => c.id === response.id);
    } else {
      // Passkey / Discoverable Credential
      for (const u of Object.values(db.users)) {
        const found = u.credentials.find(c => c.id === response.id);
        if (found) {
          matchingUser = u;
          matchingCred = found;
          break;
        }
      }
    }

    if (!matchingCred || !matchingUser) {
      return res.status(400).json({ error: 'Credential not recognized by RP server' });
    }

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: EXPECTED_ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: matchingCred.id,
        publicKey: Buffer.from(matchingCred.publicKey, 'base64url'),
        counter: matchingCred.counter,
        transports: matchingCred.transports,
      },
    });

    const { verified, authenticationInfo } = verification;

    if (verified && authenticationInfo) {
      matchingCred.counter = authenticationInfo.newCounter;

      req.session.userId = matchingUser.id;
      req.session.username = matchingUser.username;

      res.json({
        verified: true,
        user: {
          username: matchingUser.username,
          credentialsCount: matchingUser.credentials.length,
          lastLogin: new Date().toISOString()
        },
        newCounter: matchingCred.counter
      });
    } else {
      res.status(400).json({ verified: false, error: 'Authentication verification failed' });
    }
  } catch (error) {
    console.error('Error verifying login:', error);
    res.status(500).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// 3. USER MANAGEMENT & UTILITY ENDPOINTS
// -------------------------------------------------------------

app.get('/api/user/me', (req, res) => {
  const username = req.session.username;
  if (!username || !db.users[username]) {
    return res.status(401).json({ authenticated: false });
  }

  const user = db.users[username];
  res.json({
    authenticated: true,
    user: {
      username: user.username,
      id: user.id,
      credentials: user.credentials.map(c => ({
        id: c.id,
        name: c.name,
        counter: c.counter,
        deviceType: c.deviceType,
        backedUp: c.backedUp,
        createdAt: c.createdAt,
        transports: c.transports
      }))
    }
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.delete('/api/credentials/:id', (req, res) => {
  const username = req.session.username;
  if (!username || !db.users[username]) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const user = db.users[username];
  user.credentials = user.credentials.filter(c => c.id !== req.params.id);
  res.json({ success: true, credentialsCount: user.credentials.length });
});

app.get('/api/users/list', (req, res) => {
  const summary = Object.values(db.users).map(u => ({
    username: u.username,
    credentialsCount: u.credentials.length,
  }));
  res.json({ users: summary });
});

app.post('/api/debug/reset', (req, res) => {
  db.users = {};
  req.session.destroy();
  res.json({ success: true, message: 'Database reset successfully' });
});

app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(` WebAuthn Test App Server running at:`);
  console.log(` ${EXPECTED_ORIGIN}`);
  console.log(`====================================================`);
});
