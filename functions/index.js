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

// ── Encender o apagar el AC ──
exports.controlarAC = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'No autenticado');
  }

  const { deviceId, accion } = data;

  try {
    const token     = await getTuyaToken();
    const timestamp = Date.now().toString();
    const path      = `/v1.0/devices/${deviceId}/commands`;
    const body      = JSON.stringify({
      commands: [{ code: 'switch_1', value: accion === 'on' }]
    });
    const sign = generateSign(CLIENT_ID, CLIENT_SECRET, timestamp, token, 'POST', path, body);

    const res = await axios.post(`${BASE_URL}${path}`, JSON.parse(body), {
      headers: {
        'client_id':    CLIENT_ID,
        'access_token': token,
        'sign':         sign,
        'sign_method':  'HMAC-SHA256',
        't':            timestamp,
        'Content-Type': 'application/json',
      }
    });

    if (!res.data.success) throw new Error(`Tuya error: ${res.data.msg}`);

    // Actualizar estado en Firestore
    const snap = await db.collection('aires_acondicionados')
      .where('hw_id', '==', deviceId).limit(1).get();

    if (!snap.empty) {
      await snap.docs[0].ref.update({
        modoControl: accion === 'on' ? 'encendido' : 'apagado',
        estado:      accion === 'on' ? 'encendido' : 'apagado',
      });
    }

    return { ok: true };

  } catch(e) {
    console.error('controlarAC:', e.message);
    throw new functions.https.HttpsError('internal', e.message);
  }
});