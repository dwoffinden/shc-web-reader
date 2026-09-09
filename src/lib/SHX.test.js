jest.mock('smart-health-card-decoder', () => ({
  verify: jest.fn(),
  Directory: { create: jest.fn() },
}));

import { CompactEncrypt } from 'jose';
import { verifySHX, inflateRaw } from './SHX.js';

// Helper based on upstream jose v6 compress helper:
// https://github.com/panva/jose/blob/v6.2.12/src/lib/deflate.ts
async function deflateRaw(buffer) {
  const cs = new CompressionStream('deflate-raw');
  const writer = cs.writable.getWriter();
  writer.write(buffer).catch(() => {});
  writer.close().catch(() => {});
  const chunks = [];
  const reader = cs.readable.getReader();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const totalLength = chunks.reduce((acc, c) => acc + c.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

// Helper to create a JWE with alg: dir, enc: A256GCM, and optional zip: DEF
async function createJWE(payloadObj, keyBytes, { zip } = {}) {
  const encoded = new TextEncoder().encode(JSON.stringify(payloadObj));
  const plaintext = new Uint8Array(encoded.buffer, encoded.byteOffset, encoded.byteLength);
  const enc = new CompactEncrypt(plaintext).setProtectedHeader({
    alg: 'dir',
    enc: 'A256GCM',
    ...(zip ? { zip } : {}),
  });
  return enc.encrypt(keyBytes, { deflateRaw });
}

function createSHL(manifestUrl, keyBytes) {
  const shlPayload = {
    url: manifestUrl,
    key: Buffer.from(keyBytes).toString('base64url'),
  };
  return 'shlink:/' + Buffer.from(JSON.stringify(shlPayload)).toString('base64url');
}

describe('inflateRaw helper', () => {
  it('round-trips raw deflate compression and decompression', async () => {
    const text = 'Hello SMART Health Links with raw DEFLATE compression!';
    const compressed = await deflateRaw(new TextEncoder().encode(text));
    const decompressed = await inflateRaw(compressed);
    expect(new TextDecoder().decode(decompressed)).toEqual(text);
  });

  it('aborts and throws an error if decompressed size exceeds maxBytes limit', async () => {
    const text = 'This is a test text that is more than twenty bytes long.';
    const compressed = await deflateRaw(new TextEncoder().encode(text));
    await expect(inflateRaw(compressed, 20)).rejects.toThrow(
      /Decompressed payload exceeded safety limit of 20 bytes/
    );
  });
});

describe('verifySHX SMART Health Links support', () => {
  const mockFhirBundle = {
    resourceType: 'Bundle',
    type: 'collection',
    entry: [
      {
        fullUrl: 'resource:0',
        resource: {
          resourceType: 'Patient',
          id: 'test-patient-1',
          name: [{ family: 'Simpson', given: ['Homer'] }],
        },
      },
    ],
  };

  afterEach(() => {
    if (global.fetch && global.fetch.mockRestore) {
      global.fetch.mockRestore();
    }
  });

  it('successfully verifies an uncompressed SMART Health Link', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const jwe = await createJWE(mockFhirBundle, key, { zip: undefined });
    const manifestUrl = 'https://example.org/shl/manifest-uncompressed';
    const shl = createSHL(manifestUrl, key);

    jest.spyOn(global, 'fetch').mockImplementation(async (url) => {
      if (url === manifestUrl) {
        return {
          status: 200,
          json: async () => ({
            files: [{ contentType: 'application/fhir+json', embedded: jwe }],
          }),
        };
      }
      throw new Error(`Unexpected fetch to ${url}`);
    });

    const result = await verifySHX(shl);

    expect(result.shxStatus).toBe('ok');
    expect(result.bundles).toHaveLength(1);
    expect(result.bundles[0].fhir).toEqual(mockFhirBundle);
  });

  it('successfully verifies a compressed SMART Health Link (zip: DEF)', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const jwe = await createJWE(mockFhirBundle, key, { zip: 'DEF' });
    const manifestUrl = 'https://example.org/shl/manifest-compressed';
    const shl = createSHL(manifestUrl, key);

    jest.spyOn(global, 'fetch').mockImplementation(async (url) => {
      if (url === manifestUrl) {
        return {
          status: 200,
          json: async () => ({
            files: [{ contentType: 'application/fhir+json', embedded: jwe }],
          }),
        };
      }
      throw new Error(`Unexpected fetch to ${url}`);
    });

    const result = await verifySHX(shl);

    expect(result.shxStatus).toBe('ok');
    expect(result.bundles).toHaveLength(1);
    expect(result.bundles[0].fhir).toEqual(mockFhirBundle);
  });

  it('gracefully returns an error status if a compressed payload fails decompression', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const badJwe = await createJWE(mockFhirBundle, key, { zip: undefined });
    const parts = badJwe.split('.');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    header.zip = 'DEF';
    const tamperedJwe = Buffer.from(JSON.stringify(header)).toString('base64url') + '.' + parts.slice(1).join('.');

    const manifestUrl = 'https://example.org/shl/manifest-tampered';
    const shl = createSHL(manifestUrl, key);

    jest.spyOn(global, 'fetch').mockImplementation(async (url) => ({
      status: 200,
      json: async () => ({
        files: [{ contentType: 'application/fhir+json', embedded: tamperedJwe }],
      }),
    }));

    const result = await verifySHX(shl);
    expect(result.shxStatus).toBe('error');
    expect(result.reasons).toBeDefined();
    expect(result.reasons.length).toBeGreaterThan(0);
  });
});

