// ===== Audio Steganography (VoxCrypt Secure Comms) =====
// Embeds encrypted ciphertext into a WAV audio carrier using LSB (Least
// Significant Bit) modification of audio samples. Produces a real .wav
// file the analyst can download, share, and later extract + decrypt.
//
// This is the "make it pakka" secure channel: the evidence report is first
// encrypted (AES/DES via the crypto module), then the ciphertext bytes are
// hidden inside a generated audio waveform so the payload looks like sound.

// ----- WAV encoding/decoding (browser, no deps) -----

function writeStr(view: DataView, offset: number, str: string) {
  for (let i = 0; i < str.length; i++) view.setUint8(offset + i, str.charCodeAt(i));
}

function readStr(view: DataView, offset: number, len: number): string {
  let s = '';
  for (let i = 0; i < len; i++) s += String.fromCharCode(view.getUint8(offset + i));
  return s;
}

// Encode a Float32 sample array (-1..1) into a 16-bit PCM WAV Blob.
function encodeWav(samples: Float32Array, sampleRate: number): Blob {
  const numChannels = 1;
  const bytesPerSample = 2;
  const blockAlign = numChannels * bytesPerSample;
  const dataSize = samples.length * bytesPerSample;
  const bufferSize = 44 + dataSize;
  const buffer = new ArrayBuffer(bufferSize);
  const view = new DataView(buffer);

  writeStr(view, 0, 'RIFF');
  view.setUint32(4, 36 + dataSize, true);
  writeStr(view, 8, 'WAVE');
  writeStr(view, 12, 'fmt ');
  view.setUint32(16, 16, true); // PCM chunk size
  view.setUint16(20, 1, true); // audio format = PCM
  view.setUint16(22, numChannels, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * blockAlign, true);
  view.setUint16(32, blockAlign, true);
  view.setUint16(34, 16, true); // bits per sample
  writeStr(view, 36, 'data');
  view.setUint32(40, dataSize, true);

  let offset = 44;
  for (let i = 0; i < samples.length; i++) {
    const s = Math.max(-1, Math.min(1, samples[i]));
    view.setInt16(offset, s < 0 ? s * 0x8000 : s * 0x7fff, true);
    offset += 2;
  }

  return new Blob([buffer], { type: 'audio/wav' });
}

// Decode a WAV file Blob back into Float32 samples + sample rate.
async function decodeWav(blob: Blob): Promise<{ samples: Float32Array; sampleRate: number }> {
  const buf = await blob.arrayBuffer();
  const view = new DataView(buf);
  if (readStr(view, 0, 4) !== 'RIFF' || readStr(view, 8, 4) !== 'WAVE') {
    throw new Error('Not a valid WAV file');
  }
  const sampleRate = view.getUint32(24, true);
  const numChannels = view.getUint16(22, true);
  const bitsPerSample = view.getUint16(34, true);
  if (bitsPerSample !== 16) throw new Error('Only 16-bit PCM WAV supported');

  // Find data chunk
  let offset = 36;
  while (offset < buf.byteLength - 8) {
    const chunkId = readStr(view, offset, 4);
    const chunkSize = view.getUint32(offset + 4, true);
    if (chunkId === 'data') {
      offset += 8;
      const sampleCount = Math.floor(chunkSize / (numChannels * 2));
      const samples = new Float32Array(sampleCount);
      for (let i = 0; i < sampleCount; i++) {
        const sampleIdx = offset + i * numChannels * 2;
        let s = view.getInt16(sampleIdx, true);
        samples[i] = s / 0x8000;
      }
      return { samples, sampleRate };
    }
    offset += 8 + chunkSize;
  }
  throw new Error('No data chunk found in WAV');
}

// ----- Carrier audio generation -----
// Generate a pleasant cyber-themed tone the carrier — low hum + sweep.
export function generateCarrierAudio(durationSec = 4, sampleRate = 44100): Float32Array {
  const samples = new Float32Array(durationSec * sampleRate);
  for (let i = 0; i < samples.length; i++) {
    const t = i / sampleRate;
    const progress = t / durationSec;
    // Base hum
    const base = Math.sin(2 * Math.PI * 220 * t) * 0.15;
    // Slow sweep
    const sweepFreq = 400 + 600 * progress;
    const sweep = Math.sin(2 * Math.PI * sweepFreq * t) * 0.1;
    // Subtle harmonic
    const harmonic = Math.sin(2 * Math.PI * 880 * t) * 0.04;
    // Amplitude envelope (fade in/out)
    const env = Math.min(1, t * 3) * Math.min(1, (durationSec - t) * 3);
    samples[i] = (base + sweep + harmonic) * env;
  }
  return samples;
}

// ----- LSB embedding / extraction -----

const HEADER_MAGIC = [0x56, 0x58, 0x43, 0x54]; // "VXCT"
// Header: 4 bytes magic + 4 bytes payload length (big endian) = 64 bits hidden in 64 samples.

export interface StegoResult {
  audioBlob: Blob;
  audioUrl: string;
  carrierSamples: number;
  embeddedBytes: number;
  capacityBytes: number;
  sampleRate: number;
  durationSec: number;
}

// Embed a byte payload (ciphertext) into generated carrier audio via LSB.
export async function embedInAudio(payload: Uint8Array, durationSec = 4, sampleRate = 44100): Promise<StegoResult> {
  const samples = generateCarrierAudio(durationSec, sampleRate);
  const capacityBytes = Math.floor((samples.length - 64) / 8);
  if (payload.length > capacityBytes) {
    // Auto-expand duration to fit
    const neededDuration = Math.ceil((payload.length * 8 + 64) / sampleRate) + 1;
    return embedInAudio(payload, neededDuration, sampleRate);
  }

  // Embed header: magic (4 bytes) + length (4 bytes) = 64 bits → 64 samples
  const headerBytes = new Uint8Array(8);
  headerBytes.set(HEADER_MAGIC, 0);
  const view = new DataView(headerBytes.buffer);
  view.setUint32(4, payload.length, false); // big endian
  embedBits(samples, 0, headerBytes, 8);

  // Embed payload
  embedBits(samples, 64, payload, 8);

  const blob = encodeWav(samples, sampleRate);
  const audioUrl = URL.createObjectURL(blob);
  return {
    audioBlob: blob,
    audioUrl,
    carrierSamples: samples.length,
    embeddedBytes: payload.length,
    capacityBytes,
    sampleRate,
    durationSec,
  };
}

function embedBits(samples: Float32Array, startSample: number, data: Uint8Array, bitsPerByte: number) {
  let sampleIdx = startSample;
  for (let byteIdx = 0; byteIdx < data.length; byteIdx++) {
    for (let bit = 0; bit < bitsPerByte; bit++) {
      const bitVal = (data[byteIdx] >> (7 - bit)) & 1;
      // Convert sample to 16-bit int, modify LSB, convert back
      let intSample = Math.round(samples[sampleIdx] * 0x7fff);
      intSample = (intSample & ~1) | bitVal;
      samples[sampleIdx] = intSample / 0x7fff;
      sampleIdx++;
    }
  }
}

// Extract a byte payload from a WAV file (carrier audio with embedded data).
export async function extractFromAudio(blob: Blob): Promise<{ payload: Uint8Array; valid: boolean }> {
  const { samples } = await decodeWav(blob);
  // Read header
  const headerBytes = extractBits(samples, 0, 8);
  const view = new DataView(headerBytes.buffer);
  const magic = [headerBytes[0], headerBytes[1], headerBytes[2], headerBytes[3]];
  const validMagic = magic.every((b, i) => b === HEADER_MAGIC[i]);
  if (!validMagic) {
    return { payload: new Uint8Array(0), valid: false };
  }
  const length = view.getUint32(4, false);
  if (length <= 0 || 64 + length * 8 > samples.length) {
    return { payload: new Uint8Array(0), valid: false };
  }
  const payload = extractBits(samples, 64, length);
  return { payload, valid: true };
}

function extractBits(samples: Float32Array, startSample: number, byteCount: number): Uint8Array {
  const out = new Uint8Array(byteCount);
  let sampleIdx = startSample;
  for (let byteIdx = 0; byteIdx < byteCount; byteIdx++) {
    let byte = 0;
    for (let bit = 0; bit < 8; bit++) {
      const intSample = Math.round(samples[sampleIdx] * 0x7fff);
      const bitVal = intSample & 1;
      byte = (byte << 1) | bitVal;
      sampleIdx++;
    }
    out[byteIdx] = byte;
  }
  return out;
}

// Helpers to convert between base64 strings and Uint8Arrays (for bridging
// crypto payloads to the steganography byte interface).
export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// Generate a short waveform preview array for visualization.
export function waveformPreview(samples: Float32Array, bars = 60): number[] {
  const chunkSize = Math.floor(samples.length / bars);
  const peaks: number[] = [];
  for (let i = 0; i < bars; i++) {
    let max = 0;
    const start = i * chunkSize;
    for (let j = 0; j < chunkSize; j++) {
      const v = Math.abs(samples[start + j] || 0);
      if (v > max) max = v;
    }
    peaks.push(max);
  }
  return peaks;
}
