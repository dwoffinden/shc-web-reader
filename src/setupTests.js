const { TextEncoder, TextDecoder } = require('util');
const nodeCrypto = require('crypto');
const { DecompressionStream, CompressionStream } = require('stream/web');

if (typeof global.TextEncoder === 'undefined') {
  global.TextEncoder = TextEncoder;
}
if (typeof global.TextDecoder === 'undefined') {
  global.TextDecoder = TextDecoder;
}

if (!global.crypto) {
  global.crypto = nodeCrypto.webcrypto;
}
if (typeof window !== 'undefined' && !window.crypto) {
  window.crypto = nodeCrypto.webcrypto;
}

// Ensure Web Streams compression APIs are available in jsdom test environment
global.DecompressionStream = DecompressionStream;
global.CompressionStream = CompressionStream;
if (typeof window !== 'undefined') {
  window.DecompressionStream = DecompressionStream;
  window.CompressionStream = CompressionStream;
}
