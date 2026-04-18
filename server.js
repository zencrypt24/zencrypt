const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const axios = require('axios');
const cors = require('cors');
const AdmZip = require('adm-zip');

const app = express();
app.use(cors());
app.use(express.json());

const B2_KEY_ID = process.env.B2_KEY_ID;
const B2_APP_KEY = process.env.B2_APP_KEY;
const B2_BUCKET_ID = process.env.B2_BUCKET_ID;
const B2_BUCKET_NAME = 'zencrypt-files';

const tokenStore = {};

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 * 1024 }
});

// ===== TOKEN GENERATE =====
function generateToken() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789@#$%';
  let token = '';
  for (let i = 0; i < 4; i++) {
    if (i > 0) token += '-';
    for (let j = 0; j < 6; j++) {
      token += chars[Math.floor(Math.random() * chars.length)];
    }
  }
  return token;
}

// ===== CREATE PASSWORD PROTECTED ZIP =====
function createProtectedZip(fileBuffer, fileName, password) {
  const zip = new AdmZip();
  zip.addFile(fileName, fileBuffer);
  const zipBuffer = zip.toBuffer();
  
  // Encrypt the zip buffer with AES using the password
  const key = crypto.scryptSync(password, 'zencrypt_salt_v2', 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(zipBuffer), cipher.final()]);
  
  // Store IV + encrypted data
  return Buffer.concat([Buffer.from('ZENC'), iv, encrypted]);
}

// ===== B2 AUTH =====
async function getB2Auth() {
  const credentials = Buffer.from(`${B2_KEY_ID}:${B2_APP_KEY}`).toString('base64');
  const res = await axios.get(
    'https://api.backblazeb2.com/b2api/v2/b2_authorize_account',
    { headers: { Authorization: `Basic ${credentials}` } }
  );
  return res.data;
}

async function getUploadUrl(authToken, apiUrl) {
  const res = await axios.post(
    `${apiUrl}/b2api/v2/b2_get_upload_url`,
    { bucketId: B2_BUCKET_ID },
    { headers: { Authorization: authToken } }
  );
  return res.data;
}

async function deleteFromB2(auth, b2FileName, fileId) {
  try {
    await axios.post(
      `${auth.apiUrl}/b2api/v2/b2_delete_file_version`,
      { fileName: b2FileName, fileId: fileId },
      { headers: { Authorization: auth.authorizationToken } }
    );
    console.log(`Deleted: ${b2FileName}`);
  } catch (err) {
    console.error('Delete error:', err.message);
  }
}

// ===== API: GENERATE TOKEN =====
app.get('/api/generate-token', (req, res) => {
  res.json({ token: generateToken() });
});

// ===== API: UPLOAD =====
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    const {
      token, tokenPassword, filePassword,
      expireSeconds, viewLimit, downloadLimit,
      mysteryMode
    } = req.body;
    const file = req.file;

    if (!token || !tokenPassword || !file) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const expire = Math.min(parseInt(expireSeconds) || 86400, 86400);
    const tokenPassHash = crypto.createHash('sha256').update(tokenPassword).digest('hex');
    const filePassHash = filePassword
      ? crypto.createHash('sha256').update(filePassword).digest('hex')
      : null;

    const isMystery = mysteryMode === 'true';

    let uploadBuffer;
    let uploadFileName;

    if (isMystery && filePassword) {
      uploadBuffer = createProtectedZip(file.buffer, file.originalname, filePassword);
      uploadFileName = `${token}/zencrypt_pkg_${Date.now()}.zen`;
    } else {
      uploadBuffer = file.buffer;
      uploadFileName = `${token}/${Date.now()}_${file.originalname}`;
    }

    const auth = await getB2Auth();
    const uploadUrl = await getUploadUrl(auth.authorizationToken, auth.apiUrl);
    const sha1 = crypto.createHash('sha1').update(uploadBuffer).digest('hex');

    const uploadRes = await axios.post(uploadUrl.uploadUrl, uploadBuffer, {
      headers: {
        Authorization: uploadUrl.authorizationToken,
        'X-Bz-File-Name': encodeURIComponent(uploadFileName),
        'Content-Type': 'application/octet-stream',
        'Content-Length': uploadBuffer.length,
        'X-Bz-Content-Sha1': sha1,
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
    });

    const expireAt = Date.now() + expire * 1000;

    tokenStore[token] = {
      tokenPassHash,
      filePassHash,
      originalName: file.originalname,
      fileSize: file.size,
      b2FileName: uploadFileName,
      fileId: uploadRes.data.fileId,
      expireAt,
      isMystery,
      viewLimit: viewLimit === 'unlimited' ? 'unlimited' : parseInt(viewLimit) || 1,
      downloadLimit: downloadLimit === 'unlimited' ? 'unlimited' : parseInt(downloadLimit) || 1,
      viewCount: 0,
      downloadCount: 0,
      createdAt: Date.now()
    };

    setTimeout(async () => {
      if (tokenStore[token]) {
        const a = await getB2Auth();
        await deleteFromB2(a, tokenStore[token].b2FileName, tokenStore[token].fileId);
        delete tokenStore[token];
      }
    }, expire * 1000);

    res.json({ success: true, token });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Upload failed: ' + err.message });
  }
});

// ===== API: VERIFY TOKEN =====
app.post('/api/verify-token', (req, res) => {
  const { token, tokenPassword } = req.body;
  const data = tokenStore[token];

  if (!data) return res.status(404).json({ error: 'Invalid token' });
  if (Date.now() > data.expireAt) {
    delete tokenStore[token];
    return res.status(410).json({ error: 'Token expired' });
  }

  const hash = crypto.createHash('sha256').update(tokenPassword).digest('hex');
  if (hash !== data.tokenPassHash) {
    return res.status(401).json({ error: 'Wrong password' });
  }

  if (data.viewLimit !== 'unlimited') {
    if (data.viewCount >= data.viewLimit) {
      return res.status(403).json({ error: 'View limit exceeded' });
    }
    data.viewCount++;
  }

  res.json({
    success: true,
    fileSize: data.fileSize,
    hasFilePassword: !!data.filePassHash,
    isMystery: data.isMystery,
    expireAt: data.expireAt,
    viewLimit: data.viewLimit,
    viewCount: data.viewCount,
    downloadLimit: data.downloadLimit,
    downloadCount: data.downloadCount
  });
});

// ===== API: DOWNLOAD =====
app.post('/api/download', async (req, res) => {
  const { token, tokenPassword, filePassword } = req.body;
  const data = tokenStore[token];

  if (!data) return res.status(404).json({ error: 'Invalid token' });
  if (Date.now() > data.expireAt) return res.status(410).json({ error: 'Expired' });

  if (data.downloadLimit !== 'unlimited') {
    if (data.downloadCount >= data.downloadLimit) {
      return res.status(410).json({ error: 'Download limit reached' });
    }
  }

  const tokenHash = crypto.createHash('sha256').update(tokenPassword).digest('hex');
  if (tokenHash !== data.tokenPassHash) {
    return res.status(401).json({ error: 'Wrong token password' });
  }

  if (data.filePassHash) {
    if (!filePassword) return res.status(401).json({ error: 'File password required' });
    const fileHash = crypto.createHash('sha256').update(filePassword).digest('hex');
    if (fileHash !== data.filePassHash) {
      return res.status(401).json({ error: 'Wrong file password' });
    }
  }

  try {
    const auth = await getB2Auth();
    const downloadUrl = `${auth.downloadUrl}/file/${B2_BUCKET_NAME}/${encodeURIComponent(data.b2FileName)}`;

    const fileRes = await axios.get(downloadUrl, {
      headers: { Authorization: auth.authorizationToken },
      responseType: 'arraybuffer'
    });

    // Decrypt if mystery mode
    let responseBuffer = Buffer.from(fileRes.data);
    
    if (data.isMystery && data.filePassHash) {
      const header = responseBuffer.slice(0, 4).toString();
      if (header === 'ZENC') {
        const iv = responseBuffer.slice(4, 20);
        const encrypted = responseBuffer.slice(20);
        const key = crypto.scryptSync(
          req.body.filePassword, 'zencrypt_salt_v2', 32
        );
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        responseBuffer = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      }
    }

    const downloadName = data.isMystery
      ? `zencrypt_${crypto.randomBytes(4).toString('hex')}.zip`
      : data.originalName;

    res.setHeader('Content-Disposition', `attachment; filename="${downloadName}"`);
    res.setHeader('Content-Type', data.isMystery ? 'application/zip' : 'application/octet-stream');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.send(responseBuffer);

    data.downloadCount++;

    if (data.downloadLimit !== 'unlimited' && data.downloadCount >= data.downloadLimit) {
      setTimeout(async () => {
        const a = await getB2Auth();
        await deleteFromB2(a, data.b2FileName, data.fileId);
        delete tokenStore[token];
      }, 5000);
    }

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Download failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Zencrypt server running on port ${PORT}`);
});
