const http = require('http');
const crypto = require('crypto');

const BASE_URL = process.env.API_URL || 'http://localhost:8080';
const USER_ID = 'usr-test-1234';
const PAN = '4539123456789012'; // Cuenta ISO: 912345678901
const PIN = '1234'; // PIN inicial por defecto en modo simulador

function request(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : {}
    };

    const req = http.request(url, options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, raw: data });
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function buildIsoFormat4(pin, pan) {
  const digits = pan.replace(/\D/g, '');
  const account12 = digits.length >= 13
    ? digits.substring(digits.length - 13, digits.length - 1)
    : digits.padStart(12, '0');

  const hex = `44${pin}AAAAAAAAAA0000${account12}`;
  return Buffer.from(hex, 'hex');
}

async function run() {
  console.log(`[1] Obteniendo llave pública RSA activa desde ${BASE_URL}/api/v1/security/pin-key...`);
  const keyRes = await request('GET', '/api/v1/security/pin-key');
  if (keyRes.status !== 200) {
    console.error('Error al obtener llave:', keyRes);
    process.exit(1);
  }

  const { publicKeyPem, keyId, algorithm } = keyRes.body;
  console.log(`✓ Llave obtenida: keyId=${keyId}, algorithm=${algorithm}`);

  console.log(`\n[2] Cifrando PIN "${PIN}" con ISO 9564 Formato 4 + RSA-OAEP SHA-256...`);
  const pinBlockBytes = buildIsoFormat4(PIN, PAN);
  const encryptedBytes = crypto.publicEncrypt({
    key: publicKeyPem,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, pinBlockBytes);
  const encryptedPinB64 = encryptedBytes.toString('base64');
  console.log(`✓ Criptograma generado (${encryptedBytes.length} bytes, Base64 len: ${encryptedPinB64.length})`);

  console.log(`\n[3] Probando POST /api/v1/account/verify-pin...`);
  const verifyRes = await request('POST', '/api/v1/account/verify-pin', {
    userId: USER_ID,
    panOrAccountNumber: PAN,
    encryptedPin: encryptedPinB64
  });

  console.log(`Respuesta verify-pin (Status ${verifyRes.status}):`, verifyRes.body || verifyRes.raw);
}

run().catch(console.error);

