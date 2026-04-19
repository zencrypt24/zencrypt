from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import io
import hashlib
import secrets
import string
import time
import threading
import requests
import pyzipper
import base64

app = Flask(__name__)
CORS(app)

B2_KEY_ID = os.environ.get('B2_KEY_ID')
B2_APP_KEY = os.environ.get('B2_APP_KEY')
B2_BUCKET_ID = os.environ.get('B2_BUCKET_ID')
B2_BUCKET_NAME = 'zencrypt-files'

token_store = {}

def generate_token():
    chars = string.ascii_letters + string.digits + '@#$%'
    segments = []
    for _ in range(4):
        seg = ''.join(secrets.choice(chars) for _ in range(6))
        segments.append(seg)
    return '-'.join(segments)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_protected_zip(file_buffer, file_name, password):
    zip_buffer = io.BytesIO()
    with pyzipper.AESZipFile(zip_buffer, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode())
        zf.writestr(file_name, file_buffer)
    zip_buffer.seek(0)
    return zip_buffer.read()

def get_b2_auth():
    credentials = base64.b64encode(f'{B2_KEY_ID}:{B2_APP_KEY}'.encode()).decode()
    res = requests.get(
        'https://api.backblazeb2.com/b2api/v2/b2_authorize_account',
        headers={'Authorization': f'Basic {credentials}'}
    )
    return res.json()

def get_upload_url(auth_token, api_url):
    res = requests.post(
        f'{api_url}/b2api/v2/b2_get_upload_url',
        json={'bucketId': B2_BUCKET_ID},
        headers={'Authorization': auth_token}
    )
    return res.json()

def delete_from_b2(auth, b2_file_name, file_id):
    try:
        requests.post(
            f'{auth["apiUrl"]}/b2api/v2/b2_delete_file_version',
            json={'fileName': b2_file_name, 'fileId': file_id},
            headers={'Authorization': auth['authorizationToken']}
        )
        print(f'Deleted: {b2_file_name}')
    except Exception as e:
        print(f'Delete error: {e}')

def auto_delete(token, expire_seconds):
    time.sleep(expire_seconds)
    if token in token_store:
        data = token_store[token]
        auth = get_b2_auth()
        delete_from_b2(auth, data['b2_file_name'], data['file_id'])
        del token_store[token]
        print(f'Token {token} expired and deleted')

@app.route('/api/generate-token', methods=['GET'])
def api_generate_token():
    return jsonify({'token': generate_token()})

@app.route('/api/upload', methods=['POST'])
def api_upload():
    try:
        token = request.form.get('token')
        token_password = request.form.get('tokenPassword')
        file_password = request.form.get('filePassword', '')
        expire_seconds = min(int(request.form.get('expireSeconds', 86400)), 86400)
        view_limit = request.form.get('viewLimit', 'unlimited')
        download_limit = request.form.get('downloadLimit', 'unlimited')
        mystery_mode = request.form.get('mysteryMode', 'false') == 'true'
        file = request.files.get('file')

        if not token or not token_password or not file:
            return jsonify({'error': 'Missing required fields'}), 400

        token_pass_hash = hash_password(token_password)
        file_pass_hash = hash_password(file_password) if file_password else None

        file_buffer = file.read()
        file_name = file.filename

        if mystery_mode and file_password:
            upload_buffer = create_protected_zip(file_buffer, file_name, file_password)
            upload_file_name = f'{token}/zencrypt_pkg_{int(time.time()*1000)}.zip'
        else:
            upload_buffer = file_buffer
            upload_file_name = f'{token}/{int(time.time()*1000)}_{file_name}'

        auth = get_b2_auth()
        upload_url_data = get_upload_url(auth['authorizationToken'], auth['apiUrl'])

        import hashlib as hl
        sha1 = hl.sha1(upload_buffer).hexdigest()

        upload_res = requests.post(
            upload_url_data['uploadUrl'],
            data=upload_buffer,
            headers={
                'Authorization': upload_url_data['authorizationToken'],
                'X-Bz-File-Name': requests.utils.quote(upload_file_name),
                'Content-Type': 'application/octet-stream',
                'Content-Length': str(len(upload_buffer)),
                'X-Bz-Content-Sha1': sha1,
            }
        )

        upload_data = upload_res.json()
        expire_at = time.time() + expire_seconds

        token_store[token] = {
            'token_pass_hash': token_pass_hash,
            'file_pass_hash': file_pass_hash,
            'original_name': file_name,
            'file_size': len(file_buffer),
            'b2_file_name': upload_file_name,
            'file_id': upload_data['fileId'],
            'expire_at': expire_at,
            'is_mystery': mystery_mode and bool(file_password),
            'view_limit': 'unlimited' if view_limit == 'unlimited' else int(view_limit),
            'download_limit': 'unlimited' if download_limit == 'unlimited' else int(download_limit),
            'view_count': 0,
            'download_count': 0,
        }

        t = threading.Thread(target=auto_delete, args=(token, expire_seconds), daemon=True)
        t.start()

        return jsonify({'success': True, 'token': token})

    except Exception as e:
        print(f'Upload error: {e}')
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/verify-token', methods=['POST'])
def api_verify_token():
    data_req = request.get_json()
    token = data_req.get('token')
    token_password = data_req.get('tokenPassword')

    data = token_store.get(token)
    if not data:
        return jsonify({'error': 'Invalid token'}), 404
    if time.time() > data['expire_at']:
        del token_store[token]
        return jsonify({'error': 'Token expired'}), 410

    if hash_password(token_password) != data['token_pass_hash']:
        return jsonify({'error': 'Wrong password'}), 401

    if data['view_limit'] != 'unlimited':
        if data['view_count'] >= data['view_limit']:
            return jsonify({'error': 'View limit exceeded'}), 403
        data['view_count'] += 1

    return jsonify({
        'success': True,
        'fileSize': data['file_size'],
        'hasFilePassword': bool(data['file_pass_hash']),
        'isMystery': data['is_mystery'],
        'expireAt': data['expire_at'] * 1000,
        'viewLimit': data['view_limit'],
        'viewCount': data['view_count'],
        'downloadLimit': data['download_limit'],
        'downloadCount': data['download_count'],
    })

@app.route('/api/download', methods=['POST'])
def api_download():
    data_req = request.get_json()
    token = data_req.get('token')
    token_password = data_req.get('tokenPassword')
    file_password = data_req.get('filePassword', '')

    data = token_store.get(token)
    if not data:
        return jsonify({'error': 'Invalid token'}), 404
    if time.time() > data['expire_at']:
        return jsonify({'error': 'Expired'}), 410
    if data['download_limit'] != 'unlimited' and data['download_count'] >= data['download_limit']:
        return jsonify({'error': 'Download limit reached'}), 410
    if hash_password(token_password) != data['token_pass_hash']:
        return jsonify({'error': 'Wrong token password'}), 401
    if data['file_pass_hash']:
        if not file_password:
            return jsonify({'error': 'File password required'}), 401
        if hash_password(file_password) != data['file_pass_hash']:
            return jsonify({'error': 'Wrong file password'}), 401

    try:
        auth = get_b2_auth()
        download_url = f"{auth['downloadUrl']}/file/{B2_BUCKET_NAME}/{requests.utils.quote(data['b2_file_name'])}"
        file_res = requests.get(download_url, headers={'Authorization': auth['authorizationToken']})

        if data['is_mystery']:
            download_name = f"zencrypt_{secrets.token_hex(4)}.zip"
        else:
            download_name = data['original_name']

        data['download_count'] += 1

        if data['download_limit'] != 'unlimited' and data['download_count'] >= data['download_limit']:
            def delayed_delete():
                time.sleep(5)
                auth2 = get_b2_auth()
                delete_from_b2(auth2, data['b2_file_name'], data['file_id'])
                if token in token_store:
                    del token_store[token]
            threading.Thread(target=delayed_delete, daemon=True).start()

        return send_file(
            io.BytesIO(file_res.content),
            as_attachment=True,
            download_name=download_name,
            mimetype='application/octet-stream'
        )

    except Exception as e:
        print(f'Download error: {e}')
        return jsonify({'error': 'Download failed'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)