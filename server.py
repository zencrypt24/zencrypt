from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
import os, io, hashlib, secrets, string, time, threading, requests, pyzipper, base64

app = Flask(__name__)
CORS(app)

B2_KEY_ID = os.environ.get('B2_KEY_ID')
B2_APP_KEY = os.environ.get('B2_APP_KEY')
B2_BUCKET_ID = os.environ.get('B2_BUCKET_ID')
B2_BUCKET_NAME = 'zencrypt-files'

token_store = {}

def generate_token():
    chars = string.ascii_letters + string.digits + '@#$%'
    return '-'.join(''.join(secrets.choice(chars) for _ in range(6)) for _ in range(4))

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def create_zip(buf, name, pw):
    z = io.BytesIO()
    with pyzipper.AESZipFile(z, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(pw.encode())
        zf.writestr(name, buf)
    z.seek(0)
    return z.read()

def get_b2_auth():
    cred = base64.b64encode(f'{B2_KEY_ID}:{B2_APP_KEY}'.encode()).decode()
    r = requests.get('https://api.backblazeb2.com/b2api/v2/b2_authorize_account',
                     headers={'Authorization': f'Basic {cred}'})
    return r.json()

def get_upload_url(auth):
    r = requests.post(f"{auth['apiUrl']}/b2api/v2/b2_get_upload_url",
                      json={'bucketId': B2_BUCKET_ID},
                      headers={'Authorization': auth['authorizationToken']})
    return r.json()

def delete_from_b2(fname, fid):
    try:
        auth = get_b2_auth()
        requests.post(f"{auth['apiUrl']}/b2api/v2/b2_delete_file_version",
                      json={'fileName': fname, 'fileId': fid},
                      headers={'Authorization': auth['authorizationToken']})
    except Exception as e:
        print(f'Delete error: {e}')

def auto_delete(token, seconds):
    time.sleep(seconds)
    if token in token_store:
        d = token_store[token]
        delete_from_b2(d['b2_file_name'], d['file_id'])
        del token_store[token]
        print(f'Token {token} expired')

# ===== STORAGE STATS =====
@app.route('/api/storage-stats', methods=['GET'])
def api_storage_stats():
    try:
        auth = get_b2_auth()
        # Get bucket info
        r = requests.post(f"{auth['apiUrl']}/b2api/v2/b2_list_buckets",
                          json={'accountId': auth['accountId'], 'bucketName': B2_BUCKET_NAME},
                          headers={'Authorization': auth['authorizationToken']})
        buckets = r.json().get('buckets', [])

        # Count files size
        list_r = requests.post(f"{auth['apiUrl']}/b2api/v2/b2_list_file_names",
                               json={'bucketId': B2_BUCKET_ID, 'maxFileCount': 1000},
                               headers={'Authorization': auth['authorizationToken']})
        files = list_r.json().get('files', [])
        used_bytes = sum(f.get('contentLength', 0) for f in files)

        max_bytes = 10 * 1024 * 1024 * 1024  # 10GB
        free_bytes = max(0, max_bytes - used_bytes)
        used_pct = round((used_bytes / max_bytes) * 100, 1)

        return jsonify({
            'total_gb': 10.0,
            'used_gb': round(used_bytes / (1024**3), 3),
            'free_gb': round(free_bytes / (1024**3), 3),
            'used_pct': used_pct
        })
    except Exception as e:
        return jsonify({
            'total_gb': 10.0,
            'used_gb': 0.0,
            'free_gb': 10.0,
            'used_pct': 0.0
        })

# ===== GENERATE TOKEN =====
@app.route('/api/generate-token', methods=['GET'])
def api_gen_token():
    return jsonify({'token': generate_token()})

# ===== CHUNKED UPLOAD INIT =====
@app.route('/api/upload-init', methods=['POST'])
def api_upload_init():
    try:
        data = request.get_json()
        token = data.get('token')
        token_pw = data.get('tokenPassword')
        file_pw = data.get('filePassword', '')
        expire_sec = min(int(data.get('expireSeconds', 86400)), 86400)
        view_limit = data.get('viewLimit', 'unlimited')
        dl_limit = data.get('downloadLimit', 'unlimited')
        mystery = data.get('mysteryMode', False)
        file_name = data.get('fileName', 'file')
        file_size = data.get('fileSize', 0)

        if not token or not token_pw:
            return jsonify({'error': 'Missing fields'}), 400

        is_mystery = mystery and bool(file_pw)
        upload_name = f'{token}/zencrypt_pkg_{int(time.time()*1000)}.zip' if is_mystery else f'{token}/{int(time.time()*1000)}_{file_name}'
        orig_name = f'zencrypt_{secrets.token_hex(4)}.zip' if is_mystery else file_name

        # Get B2 large file upload URL
        auth = get_b2_auth()
        r = requests.post(f"{auth['apiUrl']}/b2api/v2/b2_start_large_file",
                          json={
                              'bucketId': B2_BUCKET_ID,
                              'fileName': requests.utils.quote(upload_name),
                              'contentType': 'application/octet-stream'
                          },
                          headers={'Authorization': auth['authorizationToken']})
        large_file = r.json()

        # Store pending upload info
        session_id = secrets.token_hex(16)
        token_store[f'pending_{session_id}'] = {
            'token': token,
            'token_hash': hash_pw(token_pw),
            'file_hash': hash_pw(file_pw) if file_pw else None,
            'orig_name': orig_name,
            'file_size': file_size,
            'b2_file_name': upload_name,
            'large_file_id': large_file['fileId'],
            'b2_auth': auth,
            'is_mystery': is_mystery,
            'file_pw': file_pw if is_mystery else '',
            'expire_sec': expire_sec,
            'view_limit': 'unlimited' if view_limit == 'unlimited' else int(view_limit),
            'dl_limit': 'unlimited' if dl_limit == 'unlimited' else int(dl_limit),
            'parts': [],
            'created': time.time()
        }

        return jsonify({'session_id': session_id, 'file_id': large_file['fileId']})

    except Exception as e:
        print(f'Upload init error: {e}')
        return jsonify({'error': str(e)}), 500

# ===== UPLOAD CHUNK =====
@app.route('/api/upload-chunk', methods=['POST'])
def api_upload_chunk():
    try:
        session_id = request.form.get('session_id')
        part_num = int(request.form.get('part_number', 1))
        chunk = request.files.get('chunk')

        pending = token_store.get(f'pending_{session_id}')
        if not pending:
            return jsonify({'error': 'Invalid session'}), 404

        auth = pending['b2_auth']
        large_file_id = pending['large_file_id']

        # Get part upload URL
        r = requests.post(f"{auth['apiUrl']}/b2api/v2/b2_get_upload_part_url",
                          json={'fileId': large_file_id},
                          headers={'Authorization': auth['authorizationToken']})
        part_url_data = r.json()

        chunk_data = chunk.read()
        sha1 = hashlib.sha1(chunk_data).hexdigest()

        # Upload part
        requests.post(part_url_data['uploadUrl'], data=chunk_data, headers={
            'Authorization': part_url_data['authorizationToken'],
            'X-Bz-Part-Number': str(part_num),
            'Content-Length': str(len(chunk_data)),
            'X-Bz-Content-Sha1': sha1,
        })

        pending['parts'].append({'partNumber': part_num, 'sha1': sha1})
        return jsonify({'success': True, 'part': part_num})

    except Exception as e:
        print(f'Chunk upload error: {e}')
        return jsonify({'error': str(e)}), 500

# ===== UPLOAD FINISH =====
@app.route('/api/upload-finish', methods=['POST'])
def api_upload_finish():
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        token = data.get('token')

        pending = token_store.get(f'pending_{session_id}')
        if not pending:
            return jsonify({'error': 'Invalid session'}), 404

        auth = pending['b2_auth']
        large_file_id = pending['large_file_id']

        # Sort parts
        parts_sorted = sorted(pending['parts'], key=lambda x: x['partNumber'])
        sha1_list = [p['sha1'] for p in parts_sorted]

        # Finish large file
        r = requests.post(f"{auth['apiUrl']}/b2api/v2/b2_finish_large_file",
                          json={'fileId': large_file_id, 'partSha1Array': sha1_list},
                          headers={'Authorization': auth['authorizationToken']})
        finished = r.json()

        expire_at = time.time() + pending['expire_sec']
        token_store[token] = {
            'token_hash': pending['token_hash'],
            'file_hash': pending['file_hash'],
            'orig_name': pending['orig_name'],
            'file_size': pending['file_size'],
            'b2_file_name': pending['b2_file_name'],
            'file_id': finished.get('fileId', large_file_id),
            'expire_at': expire_at,
            'is_mystery': pending['is_mystery'],
            'view_limit': pending['view_limit'],
            'dl_limit': pending['dl_limit'],
            'view_count': 0,
            'dl_count': 0,
        }

        del token_store[f'pending_{session_id}']
        threading.Thread(target=auto_delete, args=(token, pending['expire_sec']), daemon=True).start()

        return jsonify({'success': True, 'token': token})

    except Exception as e:
        print(f'Upload finish error: {e}')
        return jsonify({'error': str(e)}), 500

# ===== SMALL FILE UPLOAD (fallback for <5MB) =====
@app.route('/api/upload', methods=['POST'])
def api_upload():
    try:
        token = request.form.get('token')
        token_pw = request.form.get('tokenPassword')
        file_pw = request.form.get('filePassword', '')
        expire_sec = min(int(request.form.get('expireSeconds', 86400)), 86400)
        view_limit = request.form.get('viewLimit', 'unlimited')
        dl_limit = request.form.get('downloadLimit', 'unlimited')
        mystery = request.form.get('mysteryMode', 'false') == 'true'
        file = request.files.get('file')

        if not token or not token_pw or not file:
            return jsonify({'error': 'Missing fields'}), 400

        token_hash = hash_pw(token_pw)
        file_hash = hash_pw(file_pw) if file_pw else None
        buf = file.read()
        fname = file.filename
        is_mystery = mystery and bool(file_pw)

        if is_mystery:
            upload_buf = create_zip(buf, fname, file_pw)
            upload_name = f'{token}/zencrypt_pkg_{int(time.time()*1000)}.zip'
            orig_name = f'zencrypt_{secrets.token_hex(4)}.zip'
        else:
            upload_buf = buf
            upload_name = f'{token}/{int(time.time()*1000)}_{fname}'
            orig_name = fname

        auth = get_b2_auth()
        url_data = get_upload_url(auth)
        sha1 = hashlib.sha1(upload_buf).hexdigest()

        r = requests.post(url_data['uploadUrl'], data=upload_buf, headers={
            'Authorization': url_data['authorizationToken'],
            'X-Bz-File-Name': requests.utils.quote(upload_name),
            'Content-Type': 'application/octet-stream',
            'Content-Length': str(len(upload_buf)),
            'X-Bz-Content-Sha1': sha1,
        })

        d = r.json()
        expire_at = time.time() + expire_sec
        token_store[token] = {
            'token_hash': token_hash,
            'file_hash': file_hash,
            'orig_name': orig_name,
            'file_size': len(buf),
            'b2_file_name': upload_name,
            'file_id': d['fileId'],
            'expire_at': expire_at,
            'is_mystery': is_mystery,
            'view_limit': 'unlimited' if view_limit == 'unlimited' else int(view_limit),
            'dl_limit': 'unlimited' if dl_limit == 'unlimited' else int(dl_limit),
            'view_count': 0,
            'dl_count': 0,
        }

        threading.Thread(target=auto_delete, args=(token, expire_sec), daemon=True).start()
        return jsonify({'success': True, 'token': token})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== VERIFY TOKEN =====
@app.route('/api/verify-token', methods=['POST'])
def api_verify():
    d = request.get_json()
    token = d.get('token')
    pw = d.get('tokenPassword')
    data = token_store.get(token)

    if not data: return jsonify({'error': 'Invalid token'}), 404
    if time.time() > data['expire_at']:
        del token_store[token]
        return jsonify({'error': 'Token expired'}), 410
    if hash_pw(pw) != data['token_hash']:
        return jsonify({'error': 'Wrong password'}), 401

    if data['view_limit'] != 'unlimited':
        if data['view_count'] >= data['view_limit']:
            return jsonify({'error': 'View limit exceeded'}), 403
        data['view_count'] += 1

    return jsonify({
        'success': True,
        'fileSize': data['file_size'],
        'originalName': data['orig_name'],
        'hasFilePassword': bool(data['file_hash']),
        'isMystery': data['is_mystery'],
        'expireAt': data['expire_at'] * 1000,
        'viewLimit': data['view_limit'],
        'viewCount': data['view_count'],
        'downloadLimit': data['dl_limit'],
        'downloadCount': data['dl_count'],
    })

# ===== DOWNLOAD =====
@app.route('/api/download', methods=['POST'])
def api_download():
    d = request.get_json()
    token = d.get('token')
    tp = d.get('tokenPassword')
    fp = d.get('filePassword', '')
    data = token_store.get(token)

    if not data: return jsonify({'error': 'Invalid token'}), 404
    if time.time() > data['expire_at']: return jsonify({'error': 'Expired'}), 410
    if data['dl_limit'] != 'unlimited' and data['dl_count'] >= data['dl_limit']:
        return jsonify({'error': 'Download limit reached'}), 410
    if hash_pw(tp) != data['token_hash']:
        return jsonify({'error': 'Wrong token password'}), 401
    if data['file_hash']:
        if not fp: return jsonify({'error': 'File password required'}), 401
        if hash_pw(fp) != data['file_hash']:
            return jsonify({'error': 'Wrong file password'}), 401

    try:
        auth = get_b2_auth()
        url = f"{auth['downloadUrl']}/file/{B2_BUCKET_NAME}/{requests.utils.quote(data['b2_file_name'])}"
        r = requests.get(url, headers={'Authorization': auth['authorizationToken']}, stream=True)

        data['dl_count'] += 1
        if data['dl_limit'] != 'unlimited' and data['dl_count'] >= data['dl_limit']:
            def delayed():
                time.sleep(5)
                delete_from_b2(data['b2_file_name'], data['file_id'])
                token_store.pop(token, None)
            threading.Thread(target=delayed, daemon=True).start()

        def generate():
            for chunk in r.iter_content(chunk_size=8192):
                yield chunk

        return Response(
            generate(),
            headers={
                'Content-Disposition': f'attachment; filename="{data["orig_name"]}"',
                'Content-Type': 'application/octet-stream',
            }
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 3000)))
