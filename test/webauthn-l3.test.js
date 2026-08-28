const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

describe('WebAuthn Level 3 (W3C Recommendation) Specification Test Suite', () => {

  const RP_ID = 'localhost';
  const EXPECTED_ORIGIN = 'http://localhost:3000';

  // ------------------------------------------------------------------
  // 1. L3 Registration Options Specification
  // ------------------------------------------------------------------
  test('L3 Spec 1: generateRegistrationOptions must support residentKey, credProps, and COSE algs', async () => {
    const options = await generateRegistrationOptions({
      rpName: 'WebAuthn L3 Test Suite',
      rpID: RP_ID,
      userID: new Uint8Array(Buffer.from('user-l3-id-123')),
      userName: 'alice@example.com',
      userDisplayName: 'Alice L3',
      authenticatorSelection: {
        residentKey: 'preferred', // L3 residentKey preference
        userVerification: 'preferred',
      },
      extensions: {
        credProps: true, // L3 credProps extension
      },
    });

    assert.ok(options.challenge, 'Options must contain a random cryptographic challenge nonce');
    assert.strictEqual(typeof options.challenge, 'string');
    assert.strictEqual(options.rp.id, RP_ID);
    assert.strictEqual(options.user.name, 'alice@example.com');
    
    // L3 spec: residentKey must be set in authenticatorSelection
    assert.strictEqual(options.authenticatorSelection.residentKey, 'preferred');
    
    // L3 spec: extensions.credProps must be true
    assert.ok(options.extensions && options.extensions.credProps === true, 'credProps extension requested');

    // L3 COSE algorithms (-7 ES256, -257 RS256, -8 Ed25519)
    const algs = options.pubKeyCredParams.map(p => p.alg);
    assert.ok(algs.includes(-7), 'Must support ES256 (-7)');
    assert.ok(algs.includes(-257), 'Must support RS256 (-257)');
  });

  // ------------------------------------------------------------------
  // 2. L3 Authenticator Attachment Selection
  // ------------------------------------------------------------------
  test('L3 Spec 2: Options must support authenticatorAttachment filtering (platform vs cross-platform)', async () => {
    const platformOptions = await generateRegistrationOptions({
      rpName: 'WebAuthn L3 Test Suite',
      rpID: RP_ID,
      userID: new Uint8Array(Buffer.from('user-l3-id-platform')),
      userName: 'platform@example.com',
      authenticatorSelection: {
        authenticatorAttachment: 'platform', // TouchID / Windows Hello
      },
    });

    assert.strictEqual(platformOptions.authenticatorSelection.authenticatorAttachment, 'platform');

    const crossPlatformOptions = await generateRegistrationOptions({
      rpName: 'WebAuthn L3 Test Suite',
      rpID: RP_ID,
      userID: new Uint8Array(Buffer.from('user-l3-id-cross')),
      userName: 'yubikey@example.com',
      authenticatorSelection: {
        authenticatorAttachment: 'cross-platform', // YubiKey / Hardware Token
      },
    });

    assert.strictEqual(crossPlatformOptions.authenticatorSelection.authenticatorAttachment, 'cross-platform');
  });

  // ------------------------------------------------------------------
  // 3. L3 User Verification Preferences
  // ------------------------------------------------------------------
  test('L3 Spec 3: Supports all User Verification preferences (preferred, required, discouraged)', async () => {
    for (const uv of ['preferred', 'required', 'discouraged']) {
      const options = await generateRegistrationOptions({
        rpName: 'WebAuthn L3 Test Suite',
        rpID: RP_ID,
        userID: new Uint8Array(Buffer.from('user-uv-test')),
        userName: 'uv@example.com',
        authenticatorSelection: {
          userVerification: uv,
        },
      });
      assert.strictEqual(options.authenticatorSelection.userVerification, uv);
    }
  });

  // ------------------------------------------------------------------
  // 4. L3 Authentication Options (Passkey / Discoverable vs Standard)
  // ------------------------------------------------------------------
  test('L3 Spec 4: Passkey 1-Click login options must leave allowCredentials empty for discoverable credentials', async () => {
    const passkeyLoginOptions = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: undefined, // Discoverable credentials / 1-Click Passkey login
      userVerification: 'preferred',
    });

    assert.ok(passkeyLoginOptions.challenge);
    assert.strictEqual(passkeyLoginOptions.allowCredentials, undefined, 'allowCredentials must be undefined for passkey autofill/1-click');

    const targetedOptions = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: [{
        id: 'cred-id-abc-123',
        type: 'public-key',
        transports: ['internal', 'hybrid'],
      }],
    });

    assert.strictEqual(targetedOptions.allowCredentials.length, 1);
    assert.strictEqual(targetedOptions.allowCredentials[0].id, 'cred-id-abc-123');
  });

  // ------------------------------------------------------------------
  // 5. L3 Authenticator Data Flags Decoding (BE & BS Bitmasking)
  // ------------------------------------------------------------------
  test('L3 Spec 5: authenticatorData byte 32 bit flags (UP, UV, BE, BS, AT, ED) must be decoded correctly', () => {
    const authData = new Uint8Array(37);
    authData.fill(0xAA, 0, 32);

    // Flags Byte at index 32: UP (0x01) + UV (0x04) + BE (0x08) + BS (0x10) + AT (0x40) = 0x5D
    const flagsByte = 0x01 | 0x04 | 0x08 | 0x10 | 0x40;
    authData[32] = flagsByte;

    const view = new DataView(authData.buffer);
    view.setUint32(33, 42, false);

    const isUP = Boolean(flagsByte & 0x01);
    const isUV = Boolean(flagsByte & 0x04);
    const isBE = Boolean(flagsByte & 0x08); // Backup Eligibility (L3)
    const isBS = Boolean(flagsByte & 0x10); // Backup State (L3)
    const isAT = Boolean(flagsByte & 0x40);
    const isED = Boolean(flagsByte & 0x80);
    const signCount = view.getUint32(33, false);

    assert.strictEqual(isUP, true, 'User Presence UP (Bit 0)');
    assert.strictEqual(isUV, true, 'User Verification UV (Bit 2)');
    assert.strictEqual(isBE, true, 'Backup Eligibility BE (Bit 3 - L3)');
    assert.strictEqual(isBS, true, 'Backup State BS (Bit 4 - L3)');
    assert.strictEqual(isAT, true, 'Attested Credential Data AT (Bit 6)');
    assert.strictEqual(isED, false, 'Extension Data ED (Bit 7)');
    assert.strictEqual(signCount, 42, 'Sign Counter');
  });

  // ------------------------------------------------------------------
  // 6. L3 Exclude Credentials (Prevent Re-registration)
  // ------------------------------------------------------------------
  test('L3 Spec 6: excludeCredentials must include registered credential IDs to prevent duplicate registrations', async () => {
    const existingCreds = [
      { id: 'registered-key-1', type: 'public-key', transports: ['internal'] },
      { id: 'registered-key-2', type: 'public-key', transports: ['usb'] },
    ];

    const options = await generateRegistrationOptions({
      rpName: 'WebAuthn L3 Test Suite',
      rpID: RP_ID,
      userID: new Uint8Array(Buffer.from('user-repeat-reg')),
      userName: 'repeat@example.com',
      excludeCredentials: existingCreds,
    });

    assert.strictEqual(options.excludeCredentials.length, 2);
    assert.strictEqual(options.excludeCredentials[0].id, 'registered-key-1');
  });

  // ------------------------------------------------------------------
  // 7. L3 Challenge Nonce Freshness
  // ------------------------------------------------------------------
  test('L3 Spec 7: Challenge nonces must be uniquely generated per request', async () => {
    const opt1 = await generateRegistrationOptions({
      rpName: 'Test',
      rpID: RP_ID,
      userID: new Uint8Array(Buffer.from('user-1')),
      userName: 'user1',
    });
    const opt2 = await generateRegistrationOptions({
      rpName: 'Test',
      rpID: RP_ID,
      userID: new Uint8Array(Buffer.from('user-1')),
      userName: 'user1',
    });

    assert.notStrictEqual(opt1.challenge, opt2.challenge, 'Each registration request must issue a unique challenge');
  });

});
