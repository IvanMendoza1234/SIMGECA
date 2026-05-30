const functions = require('firebase-functions');
const admin     = require('firebase-admin');
const axios     = require('axios');
const crypto    = require('crypto');

admin.initializeApp();
const db = admin.firestore();

const CLIENT_ID     = process.env.TUYA_CLIENT_ID;
const CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET;
const BASE_URL      = 'https://openapi.tuyaus.com';

// ── Firma requerida por Tuya ──
function generateSign(clientId, secret, timestamp, accessToken, method, path, body = '') {
  const contentHash  = crypto.createHash('sha256').update(body).digest('hex');
  const stringToSign = [method, contentHash, '', path].join('\n');
  const signStr      = clientId + (accessToken || '') + timestamp + stringToSign;
  return crypto.createHmac('sha256', secret).update(signStr).digest('hex').toUpperCase();
}

// ── Obtener token de Tuya ──
async function getTuyaToken() {
  const snap = await db.collection('config').doc('tuya').get();
  const cfg  = snap.exists ? snap.data() : {};
  if (cfg.access_token && cfg.expire_time > Date.now()) {
    return cfg.access_token;
  }
  const timestamp = Date.now().toString();
  const path      = '/v1.0/token?grant_type=1';
  const sign      = generateSign(CLIENT_ID, CLIENT_SECRET, timestamp, '', 'GET', path);
  const res = await axios.get(`${BASE_URL}${path}`, {
    headers: {
      'client_id':   CLIENT_ID,
      'sign':        sign,
      'sign_method': 'HMAC-SHA256',
      't':           timestamp,
    }
  });
  if (!res.data.success) throw new Error(`Tuya token error: ${res.data.msg}`);
  const token = res.data.result;
  await db.collection('config').doc('tuya').set({
    access_token:  token.access_token,
    refresh_token: token.refresh_token,
    expire_time:   Date.now() + (token.expire_time * 1000) - 60000,
  }, { merge: true });
  return token.access_token;
}

// ── Encender o apagar el AC (onRequest) ──
exports.controlarAC = functions.https.onRequest(async (req, res) => {
  // CORS
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.status(204).send(''); return; }
  if (req.method !== 'POST')    { res.status(405).json({ error: 'Method not allowed' }); return; }

  // Verificar token de Firebase
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'No autenticado' }); return;
  }
  try {
    await admin.auth().verifyIdToken(authHeader.split('Bearer ')[1]);
  } catch(e) {
    res.status(401).json({ error: 'Token inválido' }); return;
  }

  // Leer body
  const body    = req.body || {};
  const payload = body.data || body;
  const { deviceId, accion } = payload;

  if (!deviceId || !accion) {
    res.status(400).json({ error: 'Faltan deviceId o accion' }); return;
  }

  try {
    const token     = await getTuyaToken();
    const timestamp = Date.now().toString();
    const path      = `/v1.0/devices/${deviceId}/commands`;
    const bodyStr   = JSON.stringify({
      commands: [{ code: 'switch_1', value: accion === 'on' }]
    });
    const sign = generateSign(CLIENT_ID, CLIENT_SECRET, timestamp, token, 'POST', path, bodyStr);

    const tuyaRes = await axios.post(`${BASE_URL}${path}`, JSON.parse(bodyStr), {
      headers: {
        'client_id':    CLIENT_ID,
        'access_token': token,
        'sign':         sign,
        'sign_method':  'HMAC-SHA256',
        't':            timestamp,
        'Content-Type': 'application/json',
      }
    });

    if (!tuyaRes.data.success) throw new Error(`Tuya error: ${tuyaRes.data.msg}`);

    // Actualizar estado en Firestore
    const snap = await db.collection('aires_acondicionados')
      .where('hw_id', '==', deviceId).limit(1).get();
    if (!snap.empty) {
      await snap.docs[0].ref.update({
        modoControl: accion === 'on' ? 'encendido' : 'apagado',
        estado:      accion === 'on' ? 'encendido' : 'apagado',
      });
    }

    res.status(200).json({ ok: true });
  } catch(e) {
    console.error('controlarAC:', e.message);
    res.status(500).json({ error: e.message });
  }
});
