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
  secret: 'webauthn-l3-secret-key-demo-2026',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(express.static(path.join(__dirname, 'public')));
app.use('/node_modules', express.static(path.join(__dirname, 'node_modules')));

// In-memory Database
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
// 1. REGISTRATION ENDPOINTS (WebAuthn Level 3 Specs)
// -------------------------------------------------------------

app.post('/api/register/options', async (req, res) => {
  try {
    const { username, authenticatorAttachment, userVerification, hints } = req.body;
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }

    const user = getUser(username);

    // WebAuthn Level 3 Registration Options Configuration
    const options = await generateRegistrationOptions({
      rpName: 'WebAuthn L3 Test App',
      rpID: RP_ID,
      userID: new Uint8Array(Buffer.from(user.id)),
      userName: user.username,
      userDisplayName: user.username,
      // Exclude existing credentials to prevent double registration
      excludeCredentials: user.credentials.map(cred => ({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports,
      })),
      authenticatorSelection: {
        residentKey: 'preferred', // Level 3 Passkey requirement ('discouraged' | 'preferred' | 'required')
        userVerification: userVerification || 'preferred',
        authenticatorAttachment: authenticatorAttachment || undefined, // 'platform' | 'cross-platform'
      },
      attestationType: 'none',
      // WebAuthn Level 3 Extensions
      extensions: {
        credProps: true, // Returns rk boolean confirming Passkey storage
      },
      // WebAuthn Level 3 Hints
      hints: hints && hints.length > 0 ? hints : undefined, // ['security-key', 'client-device', 'hybrid']
    });

    req.session.currentChallenge = options.challenge;
    req.session.username = username;

    res.json({ options, specLevel: 'WebAuthn Level 3 (W3C Recommendation)' });
  } catch (error) {
    console.error('Error generating registration options:', error);
    res.status(500).json({ error: error.message });
  }
});

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

      // Extract WebAuthn L3 credProps extension result if present
      const clientExtensionResults = response.clientExtensionResults || {};
      const isResidentKeyCreated = clientExtensionResults.credProps ? clientExtensionResults.credProps.rk : undefined;

      const newCredential = {
        id,
        publicKey: Buffer.from(publicKey).toString('base64url'),
        counter,
        transports: transports || [],
        deviceType: credentialDeviceType, // 'singleDevice' | 'multiDevice' (Level 3)
        backedUp: credentialBackedUp, // boolean (Level 3 Sync State)
        isResidentKey: isResidentKeyCreated,
        name: deviceName || `Passkey (${new Date().toLocaleDateString()})`,
        createdAt: new Date().toISOString(),
      };

      user.credentials.push(newCredential);
      req.session.userId = user.id;
      req.session.username = user.username;

      res.json({
        verified: true,
        specLevel: 'WebAuthn Level 3 Verified',
        user: { username: user.username, credentialsCount: user.credentials.length },
        credential: newCredential,
        extensionResults: clientExtensionResults
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
// 2. AUTHENTICATION ENDPOINTS (WebAuthn Level 3 Specs)
// -------------------------------------------------------------

app.post('/api/login/options', async (req, res) => {
  try {
    const { username, userVerification, hints } = req.body;

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
      userVerification: userVerification || 'preferred',
      hints: hints && hints.length > 0 ? hints : undefined,
    });

    req.session.currentChallenge = options.challenge;
    if (username) req.session.authUsername = username;

    res.json({ options, specLevel: 'WebAuthn Level 3 (W3C Recommendation)' });
  } catch (error) {
    console.error('Error generating login options:', error);
    res.status(500).json({ error: error.message });
  }
});

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
      // Passkey / Discoverable Credential Search
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
        specLevel: 'WebAuthn Level 3 Assertion Verified',
        user: {
          username: matchingUser.username,
          credentialsCount: matchingUser.credentials.length,
          lastLogin: new Date().toISOString()
        },
        newCounter: matchingCred.counter,
        credentialDeviceType: authenticationInfo.credentialDeviceType, // L3 Device Type
        credentialBackedUp: authenticationInfo.credentialBackedUp, // L3 Backup State
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
// 3. USER MANAGEMENT & CAPABILITIES ENDPOINTS
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
        isResidentKey: c.isResidentKey,
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

app.post('/api/debug/reset', (req, res) => {
  db.users = {};
  req.session.destroy();
  res.json({ success: true, message: 'Database reset successfully' });
});

app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(` WebAuthn Level 3 Server running at:`);
  console.log(` ${EXPECTED_ORIGIN}`);
  console.log(`====================================================`);
});
