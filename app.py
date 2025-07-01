# app.py
from functools import wraps
import os, jwt, datetime
from flask import Flask, render_template, jsonify, request, redirect, url_for, Response, g
from jwt import PyJWKClient
import boto3
import pymysql
from contextlib import contextmanager

app = Flask(__name__)

# === AWS Cognito 설정 ===
COGNITO_REGION = "ap-northeast-2"
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID")
COGNITO_APP_CLIENT_ID = os.environ.get("COGNITO_APP_CLIENT_ID")
COGNITO_KEYS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"

# === DB 설정 ===
DATABASE_CONFIG = {
    'host': os.environ.get('MYSQL_HOST'),
    'user': os.environ.get('MYSQL_USER'),
    'password': os.environ.get('MYSQL_PASSWORD'),
    'database': os.environ.get('MYSQL_DB'),
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
        token = request.headers.get("Authorization")
        if not token:
            return Response(status=401)
        try:
            payload = verify_cognito_token(token)
            g.user_id = payload['cognito:username']
            ensure_user_exists(g.user_id)
        except Exception:
            return Response(status=401)
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

@app.route('/')
def login_page():
    return render_template('login_page.html')

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

# === TIL ===
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
            INSERT INTO comments (comment_idx, til_idx, til_comment, til_comment_day, user_nickmane)
            VALUES (%s, %s, %s, %s, %s)
        """, (comment_idx, til_idx, comment, date, g.user_id))
    return jsonify({'msg': '댓글 작성 완료'})

@app.route('/til/comment', methods=['DELETE'])
@login_check
def delete_comment():
    comment_idx = request.form['comment_idx_give']
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM comments WHERE comment_idx = %s AND user_nickmane = %s", (int(comment_idx), g.user_id))
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

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
