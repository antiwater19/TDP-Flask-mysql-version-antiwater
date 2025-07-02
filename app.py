from functools import wraps
import os, jwt, datetime, requests, base64
from flask import Flask, render_template, jsonify, request, redirect, url_for, Response, g, make_response
from jwt import PyJWKClient
import pymysql
import json
import boto3
from contextlib import contextmanager
from dotenv import load_dotenv

load_dotenv()  # .env 파일 로드

# 환경변수 로드 확인
print("=== 환경변수 로드 확인 ===")
print(f"COGNITO_USER_POOL_ID: {os.environ.get('COGNITO_USER_POOL_ID')}")
print(f"COGNITO_APP_CLIENT_ID: {os.environ.get('COGNITO_APP_CLIENT_ID')}")
print(f"COGNITO_APP_CLIENT_SECRET: {os.environ.get('COGNITO_APP_CLIENT_SECRET')}")
print(f"COGNITO_DOMAIN: {os.environ.get('COGNITO_DOMAIN')}")
print("========================")

# 🔑 AWS Secrets Manager에서 시크릿 불러오기 함수
def get_secret(secret_name, region_name="ap-northeast-1"):
    session = boto3.session.Session()
    client = session.client('secretsmanager', region_name=region_name)

    response = client.get_secret_value(SecretId=secret_name)
    secret = json.loads(response['SecretString'])
    return secret


# 🔐 시크릿 로드 (시크릿 이름: flask/app1)
secret = get_secret('flask/app1')

app = Flask(__name__)
app.secret_key = secret['flask_secret']

# === AWS Cognito 설정 ===
COGNITO_REGION = "ap-northeast-1" # 여기 리전 수정해서 써야함
COGNITO_USER_POOL_ID = secret['cognito_user_pool_id'] #os.environ.get("COGNITO_USER_POOL_ID")
COGNITO_APP_CLIENT_ID = secret['cognito_app_client_id'] #os.environ.get("COGNITO_APP_CLIENT_ID")
COGNITO_APP_CLIENT_SECRET = secret['cognito_app_client_secret'] #os.environ.get("COGNITO_APP_CLIENT_SECRET")
COGNITO_DOMAIN = secret['cognito_domain'] #os.environ.get("COGNITO_DOMAIN")
COGNITO_KEYS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json" # f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
REDIRECT_URI = "https://www.antiwater19.co.kr/callback"

# === DB 설정 ===
DATABASE_CONFIG = {
    'host': secret['host'],
    'user': secret['username'],
    'password': secret['password'],
    'database': secret['dbname'],
    'charset': 'utf8mb4',
    'autocommit': True
}

@contextmanager
def get_db_connection():
    conn = pymysql.connect(**DATABASE_CONFIG)
    try:
        yield conn
    finally:
        conn.close()

# === Cognito 토큰 검증 ===
def verify_cognito_token(token):
    jwks_client = PyJWKClient(COGNITO_KEYS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    payload = jwt.decode(token, signing_key.key, algorithms=["RS256"], audience=COGNITO_APP_CLIENT_ID)
    return payload

def login_check(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Authorization 헤더에서 토큰 확인
        token = request.headers.get("Authorization")
        
        # 헤더에 없으면 쿠키에서 확인
        if not token:
            token = request.cookies.get('auth_token')
            
        print(f"Received token: {token}")
        if not token:
            print("No token provided")
            return redirect('/')
        try:
            payload = verify_cognito_token(token)
            print(f"Token payload: {payload}")
            g.user_id = payload.get('cognito:username')
            ensure_user_exists(g.user_id)
        except Exception as e:
            print(f"Token verification failed: {e}")
            return redirect('/')
        return f(*args, **kwargs)
    return decorated

# === 유저 확인 및 정보 ===
def ensure_user_exists(user_id):
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users WHERE user_id = %s", (user_id,))
        if cur.fetchone()[0] == 0:
            cur.execute("INSERT INTO users (user_id, user_nickname) VALUES (%s, %s)", (user_id, user_id))

def get_user_info(user_id):
    with get_db_connection() as conn:
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        return cur.fetchone()

# === Cognito 로그인 후 처리 ===
@app.route('/callback')
def callback():
    print("=== CALLBACK DEBUG START ===")
    print(f"Request args: {dict(request.args)}")
    print(f"Request form: {dict(request.form)}")
    print(f"Request URL: {request.url}")
    print(f"Request method: {request.method}")
    
    code = request.args.get('code')
    error = request.args.get('error')
    error_description = request.args.get('error_description')
    
    print(f"Authorization Code: {code}")
    print(f"Error: {error}")
    print(f"Error description: {error_description}")
    
    if error:
        print(f"❌ OAuth Error: {error} - {error_description}")
        return f"OAuth Error: {error} - {error_description}", 400
    
    if not code:
        print("❌ No authorization code found")
        return "Authorization code not found", 400

    token_url = f"https://{COGNITO_DOMAIN}/oauth2/token"
    
    # 디버그 정보 출력
    print(f"COGNITO_APP_CLIENT_ID: {COGNITO_APP_CLIENT_ID}")
    print(f"COGNITO_APP_CLIENT_SECRET: {'***masked***' if COGNITO_APP_CLIENT_SECRET else 'None'}")
    print(f"COGNITO_DOMAIN: {COGNITO_DOMAIN}")
    print(f"Token URL: {token_url}")
    
    # Client Secret이 있는 경우와 없는 경우 구분
    if COGNITO_APP_CLIENT_SECRET:
        # Basic Auth 헤더 생성
        auth_string = f"{COGNITO_APP_CLIENT_ID}:{COGNITO_APP_CLIENT_SECRET}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {auth_b64}'
        }
        
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI
        }
        
        print(f"Using Basic Auth: {auth_b64[:20]}...")
        print(f"Request headers: {headers}")
        print(f"Request data: {data}")
    else:
        # Client Secret 없는 경우
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'grant_type': 'authorization_code',
            'client_id': COGNITO_APP_CLIENT_ID,
            'code': code,
            'redirect_uri': REDIRECT_URI
        }
        print("No Client Secret - using client_id in body")
        print(f"Request headers: {headers}")
        print(f"Request data: {data}")

    print("🔄 Requesting token from Cognito...")
    response = requests.post(token_url, data=data, headers=headers)
    
    print(f"Token response status: {response.status_code}")
    print(f"Token response headers: {dict(response.headers)}")
    print(f"Token response body: {response.text}")
    
    if response.status_code != 200:
        print(f"❌ Token request failed: {response.status_code} - {response.text}")
        return f"Failed to get token: {response.text}", 400

    tokens = response.json()
    id_token = tokens.get('id_token')
    access_token = tokens.get('access_token')
    
    print(f"✅ Received tokens: {list(tokens.keys())}")
    print(f"ID Token (first 50 chars): {id_token[:50] if id_token else 'None'}...")
    print(f"Access Token (first 50 chars): {access_token[:50] if access_token else 'None'}...")

    # ID 토큰 페이로드 디코딩 (검증 없이)
    if id_token:
        try:
            import json
            # JWT는 header.payload.signature 형태
            parts = id_token.split('.')
            if len(parts) >= 2:
                payload_part = parts[1]
                # Base64 패딩 추가
                payload_part += '=' * (4 - len(payload_part) % 4)
                payload_bytes = base64.b64decode(payload_part)
                payload = json.loads(payload_bytes)
                print(f"🔍 ID Token payload: {json.dumps(payload, indent=2)}")
                
                # 중요한 클레임들 확인
                print(f"📧 Email in token: {payload.get('email', 'NOT_FOUND')}")
                print(f"👤 Name in token: {payload.get('name', 'NOT_FOUND')}")
                print(f"🏷️ Nickname in token: {payload.get('nickname', 'NOT_FOUND')}")
                print(f"🆔 Username in token: {payload.get('cognito:username', 'NOT_FOUND')}")
                
        except Exception as e:
            print(f"❌ Token decode error: {e}")

    # 카카오 API 직접 호출로 확인
    if access_token:
        print("🔄 Calling Kakao API directly...")
        try:
            kakao_api_url = "https://kapi.kakao.com/v2/user/me"
            kakao_headers = {"Authorization": f"Bearer {access_token}"}
            kakao_response = requests.get(kakao_api_url, headers=kakao_headers)
            print(f"Kakao API response status: {kakao_response.status_code}")
            if kakao_response.status_code == 200:
                kakao_data = kakao_response.json()
                print(f"🎯 Kakao API response: {json.dumps(kakao_data, indent=2, ensure_ascii=False)}")
                
                # 카카오에서 실제로 제공하는 데이터 확인
                kakao_account = kakao_data.get('kakao_account', {})
                print(f"📧 Kakao email: {kakao_account.get('email', 'NOT_FOUND')}")
                print(f"👤 Kakao name: {kakao_account.get('name', 'NOT_FOUND')}")
                print(f"🏷️ Kakao nickname: {kakao_account.get('profile', {}).get('nickname', 'NOT_FOUND')}")
            else:
                print(f"❌ Kakao API error: {kakao_response.text}")
        except Exception as e:
            print(f"❌ Kakao API call error: {e}")

    print("=== CALLBACK DEBUG END ===")

    # 토큰을 쿠키와 localStorage 모두에 저장하도록 수정
    response_html = f'''
    <script>
        localStorage.setItem('token', '{id_token}');
        window.location.href = '/main_page';
    </script>
    '''
    response = make_response(response_html)
    response.set_cookie('auth_token', id_token, secure=False, httponly=False)
    
    return response

@app.route('/')
def login_page():
    return render_template('login_page.html')

# 경로 리다이렉트 추가
@app.route('/home')
def home_redirect():
    return redirect('/main_page')

@app.route('/login')
def login_redirect():
    return redirect('/')

# 로그아웃 라우터 추가
@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(jsonify({'result': 'success'}))
    response.set_cookie('auth_token', '', expires=0)
    return response

@app.route('/main_page')
@login_check
def main_page():
    return render_template('home.html')

@app.route('/user', methods=['GET'])
@login_check
def read_user():
    user = get_user_info(g.user_id)
    if user:
        user.pop('user_password', None)
        return jsonify({'result': 'success', 'user_info': user})
    return jsonify({'result': 'fail'})

@app.route('/update_profile', methods=['POST'])
@login_check
def update_profile():
    nickname = request.form['nickname_give']
    github_id = request.form['github_id_give']
    about = request.form['about_give']
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE users SET user_nickname = %s, github_id = %s, user_profile_info = %s
            WHERE user_id = %s
        """, (nickname, github_id, about, g.user_id))
    return jsonify({"result": "success", 'msg': '프로필 업데이트 완료'})

@app.route('/til', methods=['POST'])
@login_check
def create_til():
    data = request.form
    til_title = data['til_title_give']
    til_content = data['til_content_give']
    til_user = g.user_id
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COALESCE(MAX(til_idx), 0)+1 FROM til")
        til_idx = cur.fetchone()[0]
        cur.execute("""
            INSERT INTO til (til_idx, til_title, til_user, til_content)
            VALUES (%s, %s, %s, %s)
        """, (til_idx, til_title, til_user, til_content))
    return jsonify({'msg': '작성 완료'})

@app.route('/til/<idx>', methods=['GET'])
@login_check
def get_til(idx):
    with get_db_connection() as conn:
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute("SELECT * FROM til WHERE til_idx = %s", (int(idx),))
        return jsonify({'til': cur.fetchone()})

@app.route('/til/<idx>', methods=['PUT'])
@login_check
def update_til(idx):
    data = request.form or request.json
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE til SET til_title = %s, til_content = %s WHERE til_idx = %s AND til_user = %s
        """, (data['til_title_give'], data['til_content_give'], int(idx), g.user_id))
    return jsonify({'msg': '수정 완료'})

@app.route('/til/<idx>', methods=['DELETE'])
@login_check
def delete_til(idx):
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM til WHERE til_idx = %s AND til_user = %s", (int(idx), g.user_id))
    return jsonify({'msg': '삭제 완료'})

@app.route('/til/board', methods=['GET'])
@login_check
def til_board():
    with get_db_connection() as conn:
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute("SELECT * FROM til ORDER BY til_idx DESC")
        all_til = cur.fetchall()
    return jsonify({'til_count': len(all_til), 'all_til': all_til})

@app.route('/til/user', methods=['POST'])
@login_check
def user_til():
    user_id = request.form['til_user_give']
    with get_db_connection() as conn:
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute("SELECT * FROM til WHERE til_user = %s ORDER BY til_idx DESC", (user_id,))
        return jsonify({'my_til': cur.fetchall()})

@app.route('/til_board_detail')
@login_check
def til_board_detail():
    keyword = request.args.get("keyword")
    setting = request.args.get("setting")
    col = {'제목': 'til_title', '작성자': 'til_user', '내용': 'til_content'}.get(setting, 'til_title')
    with get_db_connection() as conn:
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute(f"SELECT * FROM til WHERE {col} LIKE %s", (f"%{keyword}%",))
        return jsonify({'temp': cur.fetchall()})

@app.route('/til/comment/<idx>', methods=['GET'])
@login_check
def get_comment(idx):
    with get_db_connection() as conn:
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute("SELECT * FROM comments WHERE til_idx = %s", (int(idx),))
        return jsonify({'comment': cur.fetchall(), 'writer': g.user_id})

@app.route('/til/comment', methods=['POST'])
@login_check
def post_comment():
    comment = request.form['comment_give']
    date = request.form['date_give']
    til_idx = request.form['til_idx_give']
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COALESCE(MAX(comment_idx), 0)+1 FROM comments")
        comment_idx = cur.fetchone()[0]
        cur.execute("""
            INSERT INTO comments (comment_idx, til_idx, til_comment, til_comment_day, user_nickname)
            VALUES (%s, %s, %s, %s, %s)
        """, (comment_idx, til_idx, comment, date, g.user_id))
    return jsonify({'msg': '댓글 작성 완료'})

@app.route('/til/comment', methods=['DELETE'])
@login_check
def delete_comment():
    comment_idx = request.form['comment_idx_give']
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM comments WHERE comment_idx = %s AND user_nickname = %s", (int(comment_idx), g.user_id))
    return jsonify({'msg': '댓글 삭제 완료'})

@app.route('/update_like', methods=['POST'])
@login_check
def update_like():
    til_idx = request.form['til_idx_give']
    action = request.form['action_give']
    with get_db_connection() as conn:
        cur = conn.cursor()
        if action == 'like':
            cur.execute("INSERT IGNORE INTO likes (user_id, til_idx) VALUES (%s, %s)", (g.user_id, til_idx))
        elif action == 'unlike':
            cur.execute("DELETE FROM likes WHERE user_id = %s AND til_idx = %s", (g.user_id, til_idx))
        cur.execute("SELECT COUNT(*) FROM likes WHERE til_idx = %s", (til_idx,))
        count = cur.fetchone()[0]
    return jsonify({'count': count})

@app.route('/heart/<idx>', methods=['GET'])
@login_check
def get_heart(idx):
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM likes WHERE til_idx = %s", (int(idx),))
        count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM likes WHERE til_idx = %s AND user_id = %s", (int(idx), g.user_id))
        liked = cur.fetchone()[0] > 0
    return jsonify({'count': count, 'action': liked})

@app.route('/til/rank', methods=['GET'])
@login_check
def til_rank():
    with get_db_connection() as conn:
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute("SELECT til_user AS _id, COUNT(*) AS til_score FROM til GROUP BY til_user ORDER BY til_score DESC")
        return jsonify({'til_rank': cur.fetchall()})

# === 추가 라우트들 (원본에서 누락된 것들) ===
@app.route('/create_page')
@login_check
def create_page():
    return render_template('create.html')

@app.route('/detail')
@login_check  
def detail():
    return render_template('detail.html')

@app.route('/til_board')
@login_check
def til_board_page():
    return render_template('til_board.html')

@app.route('/til_board_detail_page')
@login_check
def til_board_detail_page():
    return render_template('til_board_detail.html')

@app.route('/mytil_page')
@login_check
def mytil_page():
    return render_template('mytil_page.html')

@app.route('/my_page')
@login_check
def my_page():
    return render_template('my_page.html')

@app.route('/status/<idx>', methods=['GET'])
@login_check
def get_status(idx):
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM til WHERE til_idx = %s AND til_user = %s", (int(idx), g.user_id))
        status = cur.fetchone()[0] > 0
    return jsonify({'status': status})

@app.route('/til/user/<idx>', methods=['GET'])
@login_check
def get_til_user(idx):
    with get_db_connection() as conn:
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute("""
            SELECT u.user_nickname, u.github_id as githhub_id, u.user_profile_info
            FROM til t
            JOIN users u ON t.til_user = u.user_id
            WHERE t.til_idx = %s
        """, (int(idx),))
        result = cur.fetchone()
        if result:
            return jsonify(result)
        return jsonify({'user_nickname': '', 'githhub_id': '', 'user_profile_info': ''})

@app.route('/til/view/<idx>', methods=['PUT'])
@login_check
def update_view(idx):
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE til SET til_view = 1 - COALESCE(til_view, 0) WHERE til_idx = %s AND til_user = %s", (int(idx), g.user_id))
    return jsonify({'msg': '공개 설정 변경 완료'})

@app.route('/flag', methods=['GET'])
@login_check
def get_flag():
    # 임시로 0 반환 (실제 로직은 구현 필요)
    return jsonify({'flag': 0})

@app.route('/healthz')
def health_check():
    return "OK", 200

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)