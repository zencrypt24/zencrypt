const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const axios = require('axios');
const FormData = require('form-data');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ===== BACKBLAZE CONFIG =====
const B2_KEY_ID = '003449285593f470000000001';
const B2_APP_KEY = 'K0032MQbNZaUdXMEGa1AsvidqCMssVw';
const B2_BUCKET_ID = 'f40469b2c89595d993df0417';
const B2_BUCKET_NAME = 'zencrypt-files';

// ===== IN-MEMORY DATABASE =====
// (tokens & metadata store হবে এখানে)
const tokenStore = {};

// ===== MULTER SETUP (file upload) =====
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 * 1024 } // 5GB
});

// ===== TOKEN GENERATE =====
function generateToken() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  let token = '';
  for (let i = 0; i < 24; i++) {
    if (i > 0 && i % 6 === 0) token += '-';
    token += chars[Math.floor(Math.random() * chars.length)];
  }
  return token;
}

// ===== GET B2 AUTH TOKEN =====
async function getB2Auth() {
  const credentials = Buffer.from(`${B2_KEY_ID}:${B2_APP_KEY}`).toString('base64');
  const res = await axios.get(
    'https://api.backblazeb2.com/b2api/v2/b2_authorize_account',
    { headers: { Authorization: `Basic ${credentials}` } }
  );
  return res.data;
}

// ===== GET UPLOAD URL =====
async function getUploadUrl(authToken, apiUrl) {
  const res = await axios.post(
    `${apiUrl}/b2api/v2/b2_get_upload_url`,
    { bucketId: B2_BUCKET_ID },
    { headers: { Authorization: authToken } }
  );
  return res.data;
}

// ===== API: GENERATE TOKEN =====
app.get('/api/generate-token', (req, res) => {
  const token = generateToken();
  res.json({ token });
});

// ===== API: UPLOAD FILE =====
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    const { token, tokenPassword, filePassword, expireSeconds } = req.body;
    const file = req.file;

    if (!token || !tokenPassword || !file) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Hash passwords
    const tokenPassHash = crypto.createHash('sha256').update(tokenPassword).digest('hex');
    const filePassHash = filePassword 
      ? crypto.createHash('sha256').update(filePassword).digest('hex')
      : null;

    // Upload to Backblaze
    const auth = await getB2Auth();
    const uploadUrl = await getUploadUrl(auth.authorizationToken, auth.apiUrl);

    const fileName = `${token}/${Date.now()}_${file.originalname}`;
    const sha1 = crypto.createHash('sha1').update(file.buffer).digest('hex');

    await axios.post(uploadUrl.uploadUrl, file.buffer, {
      headers: {
        Authorization: uploadUrl.authorizationToken,
        'X-Bz-File-Name': encodeURIComponent(fileName),
        'Content-Type': file.mimetype,
        'Content-Length': file.size,
        'X-Bz-Content-Sha1': sha1,
      }
    });

    // Save token metadata
    const expireAt = Date.now() + (parseInt(expireSeconds) || 86400) * 1000;
    tokenStore[token] = {
      tokenPassHash,
      filePassHash,
      fileName: file.originalname,
      b2FileName: fileName,
      fileSize: file.size,
      fileMime: file.mimetype,
      expireAt,
      createdAt: Date.now()
    };

    // Auto delete after expiry
    setTimeout(() => {
      delete tokenStore[token];
    }, (parseInt(expireSeconds) || 86400) * 1000);

    res.json({ success: true, token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ===== API: VERIFY TOKEN =====
app.post('/api/verify-token', (req, res) => {
  const { token, tokenPassword } = req.body;

  const data = tokenStore[token];
  if (!data) {
    return res.status(404).json({ error: 'Invalid token' });
  }

  if (Date.now() > data.expireAt) {
    delete tokenStore[token];
    return res.status(410).json({ error: 'Token expired' });
  }

  const hash = crypto.createHash('sha256').update(tokenPassword).digest('hex');
  if (hash !== data.tokenPassHash) {
    return res.status(401).json({ error: 'Wrong password' });
  }

  // Token verified — return file info
  res.json({
    success: true,
    fileName: data.fileName,
    fileSize: data.fileSize,
    hasFilePassword: !!data.filePassHash,
    expireAt: data.expireAt
  });
});

// ===== API: DOWNLOAD FILE =====
app.post('/api/download', async (req, res) => {
  const { token, tokenPassword, filePassword } = req.body;

  const data = tokenStore[token];
  if (!data) return res.status(404).json({ error: 'Invalid token' });
  if (Date.now() > data.expireAt) return res.status(410).json({ error: 'Expired' });

  const tokenHash = crypto.createHash('sha256').update(tokenPassword).digest('hex');
  if (tokenHash !== data.tokenPassHash) return res.status(401).json({ error: 'Wrong token password' });

  if (data.filePassHash) {
    if (!filePassword) return res.status(401).json({ error: 'File password required' });
    const fileHash = crypto.createHash('sha256').update(filePassword).digest('hex');
    if (fileHash !== data.filePassHash) return res.status(401).json({ error: 'Wrong file password' });
  }

  // Get download URL from B2
  const auth = await getB2Auth();
  const downloadUrl = `${auth.downloadUrl}/file/${B2_BUCKET_NAME}/${encodeURIComponent(data.b2FileName)}`;

  const fileRes = await axios.get(downloadUrl, {
    headers: { Authorization: auth.authorizationToken },
    responseType: 'stream'
  });

  res.setHeader('Content-Disposition', `attachment; filename="${data.fileName}"`);
  res.setHeader('Content-Type', data.fileMime);
  fileRes.data.pipe(res);
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Zencrypt server running on port ${PORT}`);
});v