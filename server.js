const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const axios = require('axios');
const cors = require('cors');
const archiver = require('archiver');
const { PassThrough } = require('stream');

// Fix for archiver-zip-encrypted
require('archiver-zip-encrypted');

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
function createEncryptedZip(fileBuffer, fileName, password) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const passThrough = new PassThrough();

    passThrough.on('data', chunk => chunks.push(chunk));
    passThrough.on('end', () => resolve(Buffer.concat(chunks)));
    passThrough.on('error', reject);

    const archive = archiver.create('zip-encrypted', {
      zlib: { level: 8 },
      encryptionMethod: 'aes256',
      password: password
    });

    archive.on('error', reject);
    archive.pipe(passThrough);
    archive.append(fileBuffer, { name: fileName });
    archive.finalize();
  });
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
    let uploadMime;

    if (isMystery && filePassword) {
      // Create password protected ZIP
      uploadBuffer = await createEncryptedZip(file.buffer, file.originalname, filePassword);
      uploadFileName = `${token}/zencrypt_pkg_${Date.now()}.zip`;
      uploadMime = 'application/zip';
    } else {
      // Normal upload
      uploadBuffer = file.buffer;
      uploadFileName = `${token}/${Date.now()}_${file.originalname}`;
      uploadMime = file.mimetype;
    }

    // Upload to B2
    const auth = await getB2Auth();
    const uploadUrl = await getUploadUrl(auth.authorizationToken, auth.apiUrl);
    const sha1 = crypto.createHash('sha1').update(uploadBuffer).digest('hex');

    const uploadRes = await axios.post(uploadUrl.uploadUrl, uploadBuffer, {
      headers: {
        Authorization: uploadUrl.authorizationToken,
        'X-Bz-File-Name': encodeURIComponent(uploadFileName),
        'Content-Type': uploadMime,
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
      uploadMime,
      viewLimit: viewLimit === 'unlimited' ? 'unlimited' : parseInt(viewLimit) || 1,
      downloadLimit: downloadLimit === 'unlimited' ? 'unlimited' : parseInt(downloadLimit) || 1,
      viewCount: 0,
      downloadCount: 0,
      createdAt: Date.now()
    };

    // Auto delete on expiry
    setTimeout(async () => {
      if (tokenStore[token]) {
        const a = await getB2Auth();
        await deleteFromB2(a, tokenStore[token].b2FileName, tokenStore[token].fileId);
        delete tokenStore[token];
        console.log(`Token ${token} expired`);
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
      return res.status(410).json({ error: 'Download limit reached. File deleted.' });
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

    // Set download filename
    let downloadName;
    if (data.isMystery) {
      downloadName = `zencrypt_pkg_${crypto.randomBytes(6).toString('hex')}.zip`;
    } else {
      downloadName = data.originalName;
    }

    res.setHeader('Content-Disposition', `attachment; filename="${downloadName}"`);
    res.setHeader('Content-Type', data.isMystery ? 'application/zip' : data.uploadMime);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.send(Buffer.from(fileRes.data));

    // Update download count
    data.downloadCount++;

    // Delete if download limit reached
    if (data.downloadLimit !== 'unlimited' && data.downloadCount >= data.downloadLimit) {
      setTimeout(async () => {
        const a = await getB2Auth();
        await deleteFromB2(a, data.b2FileName, data.fileId);
        delete tokenStore[token];
        console.log(`Token ${token} deleted after download limit`);
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
