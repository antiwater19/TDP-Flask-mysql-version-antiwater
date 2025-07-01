from functools import wraps
import os, jwt, datetime, hashlib
from flask import Flask, render_template, jsonify, request, redirect, url_for, Response, g
from werkzeug.utils import secure_filename
import boto3
import pymysql
import json
from contextlib import contextmanager

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

# 환경변수에서 설정 로드 (로컬 개발용)
DATABASE_CONFIG = {
    'host': secret['host'],
    'user': secret['username'],
    'password': secret['password'],
    'database': secret['dbname'],
    'charset': 'utf8mb4',
    'autocommit': True
}

# DATABASE_CONFIG = {
#     'host': os.environ.get('127.0.0.4:3306'),
#     'user': os.environ.get('anti'),
#     'password': os.environ.get('admin'),
#     'database': os.environ.get('frodo'),
#     'charset': 'utf8mb4',
#     'autocommit': True
# }

SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here')

@contextmanager
def get_db_connection():
    """데이터베이스 연결 컨텍스트 매니저"""
    connection = None
    try:
        connection = pymysql.connect(**DATABASE_CONFIG)
        yield connection
    except Exception as e:
        if connection:
            connection.rollback()
        raise e
    finally:
        if connection:
            connection.close()

def init_database():
    """데이터베이스 테이블 초기화"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # users 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(50) UNIQUE NOT NULL,
                user_password VARCHAR(64) NOT NULL,
                user_nickname VARCHAR(50) NOT NULL,
                github_id VARCHAR(50) DEFAULT '',
                user_profile_pic VARCHAR(255) DEFAULT '',
                user_profile_pic_real VARCHAR(255) DEFAULT 'static/profile_pics/profile_placeholder.png',
                user_profile_info TEXT ,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        ''')
        
        # til 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS til (
                id INT AUTO_INCREMENT PRIMARY KEY,
                til_idx INT UNIQUE NOT NULL,
                til_title VARCHAR(255) NOT NULL,
                til_user VARCHAR(50) NOT NULL,
                til_content TEXT NOT NULL,
                til_day TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                til_update_day TIMESTAMP NULL,
                til_view BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (til_user) REFERENCES users(user_id) ON DELETE CASCADE,
                INDEX idx_til_user (til_user),
                INDEX idx_til_day (til_day)
            )
        ''')
        
        # comments 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                comment_idx INT UNIQUE NOT NULL,
                til_idx INT NOT NULL,
                user_id VARCHAR(50) NOT NULL,
                user_nickname VARCHAR(50) NOT NULL,
                til_comment TEXT NOT NULL,
                til_comment_day TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (til_idx) REFERENCES til(til_idx) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                INDEX idx_til_idx (til_idx)
            )
        ''')
        
        # likes 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS likes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                til_idx INT NOT NULL,
                user_id VARCHAR(50) NOT NULL,
                type VARCHAR(20) DEFAULT 'heart',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (til_idx) REFERENCES til(til_idx) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                UNIQUE KEY unique_like (til_idx, user_id, type),
                INDEX idx_til_idx (til_idx)
            )
        ''')
        
        conn.commit()

def login_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        access_token = request.headers.get("Authorization")
        if access_token is not None:
            try:
                payload = jwt.decode(access_token, SECRET_KEY, algorithms=["HS256"])
            except jwt.InvalidTokenError:
                return Response(status=401)

            if payload is None:
                return Response(status=401)

            user_id = payload["id"]
            g.user_id = user_id
            g.user = get_user_info(user_id)
        else:
            g.user_id = "비회원"
            g.user = None
        return f(*args, **kwargs)

    return decorated_function

def get_user_info(user_id):
    """사용자 정보 조회"""
    with get_db_connection() as conn:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        return cursor.fetchone()

def get_next_til_idx():
    """다음 TIL 인덱스 생성"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(til_idx) FROM til")
        result = cursor.fetchone()
        return (result[0] + 1) if result[0] else 1

def get_next_comment_idx():
    """다음 댓글 인덱스 생성"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(comment_idx) FROM comments")
        result = cursor.fetchone()
        return (result[0] + 1) if result[0] else 1

# 라우트 정의
@app.route('/')
@app.route('/login')
def login_page():
    return render_template('login_page.html')

@app.route('/signup_page')
def signup_page():
    return render_template('signup_page.html')

@app.route('/mytil_page')
@login_check
def mytil_page():
    return render_template('mytil_page.html')

@app.route('/create_page')
@login_check
def create_page():
    return render_template('create.html')

@app.route('/detail')
@login_check
def detail_page():
    return render_template('detail.html')

@app.route('/main_page')
@login_check
def home():
    return render_template('home.html')

@app.route('/flag', methods=['GET'])
@login_check
def read_flag():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        today = datetime.datetime.now().strftime('%Y-%m-%d')
        cursor.execute("""
            SELECT COUNT(*) FROM til 
            WHERE til_user = %s AND DATE(til_day) = %s
        """, (g.user_id, today))
        
        flag = 1 if cursor.fetchone()[0] > 0 else 0
        return jsonify({'flag': flag})

@app.route('/til_board')
@login_check
def list_page():
    return render_template('til_board.html')

@app.route('/til/comment', methods=['POST'])
@login_check
def create_comment():
    user_info = get_user_info(g.user_id)
    comment_receive = request.form['comment_give']
    date_receive = request.form['date_give']
    til_idx_receive = int(request.form['til_idx_give'])
    
    comment_idx = get_next_comment_idx()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO comments (comment_idx, til_idx, user_id, user_nickname, til_comment, til_comment_day)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (comment_idx, til_idx_receive, user_info["user_id"], 
              user_info["user_nickname"], comment_receive, date_receive))
        
    return jsonify({'msg': '댓글작성 완료'})

@app.route('/til/comment/<idx>', methods=['GET'])
@login_check
def read_comment(idx):
    user_info = get_user_info(g.user_id)
    
    with get_db_connection() as conn:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("""
            SELECT comment_idx, til_idx, til_comment, til_comment_day, user_nickname
            FROM comments WHERE til_idx = %s
            ORDER BY created_at ASC
        """, (int(idx),))
        comments = cursor.fetchall()
        
    writer = user_info['user_nickname'] if user_info else ''
    return jsonify({'comment': comments, 'writer': writer})

@app.route('/til/comment', methods=['DELETE'])
@login_check
def delete_comment():
    comment_idx_receive = int(request.form['comment_idx_give'])
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM comments WHERE comment_idx = %s", (comment_idx_receive,))
        
    return jsonify({'result': "success", 'msg': '삭제 완료'})

@app.route('/til_board_detail_page')
@login_check
def search_detail_page():
    return render_template('til_board_detail.html')

@app.route('/til_board_detail')
@login_check
def search():
    keyword = request.args.get("keyword")
    setting = request.args.get("setting")
    
    # 설정에 따른 컬럼 매핑
    column_map = {
        '제목': 'til_title',
        '작성자': 'til_user',
        '내용': 'til_content'
    }
    
    search_column = column_map.get(setting, 'til_title')
    
    with get_db_connection() as conn:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute(f"""
            SELECT til_idx, til_title, til_user, til_content, til_day
            FROM til WHERE {search_column} LIKE %s AND til_view = TRUE
            ORDER BY til_day DESC
        """, (f'%{keyword}%',))
        results = cursor.fetchall()
        
    return jsonify({'result': "success", 'temp': results})

@app.route('/my_page')
@login_check
def my_page():
    return render_template('my_page.html')

@app.route('/til/board', methods=['GET'])
@login_check
def read_all_til():
    with get_db_connection() as conn:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("""
            SELECT til_idx, til_title, til_user, til_content, til_day, til_view
            FROM til WHERE til_view = TRUE
            ORDER BY til_day DESC
        """)
        all_til = cursor.fetchall()
        
        cursor.execute("SELECT COUNT(*) FROM til WHERE til_view = TRUE")
        til_count = cursor.fetchone()['COUNT(*)']
        
    return jsonify({'result': "success", 'all_til': all_til, "til_count": til_count})

@app.route('/til/user', methods=['POST'])
@login_check
def read_user_til():
    til_user_receive = request.form['til_user_give']
    
    with get_db_connection() as conn:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("""
            SELECT til_idx, til_title, til_user, til_content, til_day, til_view
            FROM til WHERE til_user = %s
            ORDER BY til_day DESC
        """, (til_user_receive,))
        my_til = cursor.fetchall()
        
    return jsonify({'result': 'success', 'my_til': my_til})

@app.route('/til/rank', methods=['GET'])
@login_check
def rank_til():
    with get_db_connection() as conn:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("""
            SELECT til_user as _id, COUNT(*) as til_score
            FROM til
            GROUP BY til_user
            ORDER BY til_score DESC
        """)
        agg_result = cursor.fetchall()
        
    return jsonify({'result': "success", 'til_rank': agg_result})

@app.route('/til', methods=['POST'])
@login_check
def create_til():
    user_info = get_user_info(g.user_id)
    til_title_receive = request.form['til_title_give']
    til_content_receive = request.form['til_content_give']
    
    til_idx = get_next_til_idx()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO til (til_idx, til_title, til_user, til_content, til_day, til_view)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (til_idx, til_title_receive, user_info['user_id'], 
              til_content_receive, datetime.datetime.now(), True))
        
    return jsonify({'msg': 'til 작성 완료!'})

@app.route('/til/<idx>', methods=['GET'])
@login_check
def read_til(idx):
    with get_db_connection() as conn:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("""
            SELECT til_idx, til_title, til_user, til_content, til_day, til_update_day, til_view
            FROM til WHERE til_idx = %s
        """, (int(idx),))
        til = cursor.fetchone()
        
    return jsonify({"til": til})

@app.route('/til/user/<idx>', methods=['GET'])
@login_check
def read_til_user(idx):
    with get_db_connection() as conn:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT til_user FROM til WHERE til_idx = %s", (int(idx),))
        til_result = cursor.fetchone()
        
        if til_result:
            cursor.execute("""
                SELECT user_nickname, github_id, user_profile_info
                FROM users WHERE user_id = %s
            """, (til_result['til_user'],))
            user_info = cursor.fetchone()
            
            return jsonify({
                "user_nickname": user_info['user_nickname'],
                'github_id': user_info['github_id'],
                'user_profile_info': user_info['user_profile_info']
            })
    
    return jsonify({"error": "User not found"}), 404

@app.route('/heart/<idx>', methods=['GET'])
@login_check
def read_heart(idx):
    user_id = g.user_id
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM likes 
            WHERE til_idx = %s AND type = 'heart'
        """, (int(idx),))
        count = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM likes 
            WHERE user_id = %s AND til_idx = %s
        """, (user_id, int(idx)))
        action = cursor.fetchone()[0] > 0
        
    return jsonify({'count': count, 'action': action})

@app.route('/status/<idx>', methods=['GET'])
@login_check
def read_status(idx):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT til_user FROM til WHERE til_idx = %s", (int(idx),))
        result = cursor.fetchone()
        
        status = result[0] == g.user_id if result else False
        
    return jsonify({"status": status})

@app.route('/til/<idx>', methods=['DELETE'])
@login_check
def delete_til(idx):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM til WHERE til_idx = %s", (int(idx),))
        
    return jsonify({'msg': 'til 삭제 완료!'})

@app.route('/til/<idx>', methods=['PUT'])
@login_check
def update_til(idx):
    til_title_receive = request.form['til_title_give']
    til_content_receive = request.form['til_content_give']
    current_time = datetime.datetime.now()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE til SET til_title = %s, til_content = %s, til_update_day = %s
            WHERE til_idx = %s
        """, (til_title_receive, til_content_receive, current_time, int(idx)))
        
    return jsonify({'msg': '수정 완료!'})

@app.route('/til/view/<idx>', methods=['PUT'])
@login_check
def update_view(idx):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT til_view FROM til WHERE til_idx = %s", (int(idx),))
        result = cursor.fetchone()
        
        if result:
            current_view = result[0]
            new_view = not current_view
            
            cursor.execute("""
                UPDATE til SET til_view = %s WHERE til_idx = %s
            """, (new_view, int(idx)))
            
    return jsonify({'msg': '변경 완료!'})

@app.route('/update_like', methods=['POST'])
@login_check
def update_like():
    til_idx_receive = int(request.form["til_idx_give"])
    type_receive = request.form["type_give"]
    action_receive = request.form["action_give"]
    user_info = get_user_info(g.user_id)
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        if action_receive == "like":
            cursor.execute("""
                INSERT IGNORE INTO likes (til_idx, type, user_id)
                VALUES (%s, %s, %s)
            """, (til_idx_receive, type_receive, user_info['user_id']))
        else:
            cursor.execute("""
                DELETE FROM likes 
                WHERE til_idx = %s AND type = %s AND user_id = %s
            """, (til_idx_receive, type_receive, user_info['user_id']))
        
        cursor.execute("""
            SELECT COUNT(*) FROM likes 
            WHERE til_idx = %s AND type = %s
        """, (til_idx_receive, type_receive))
        count = cursor.fetchone()[0]
        
    return jsonify({"result": "success", 'msg': 'updated', "count": count})

@app.route('/user', methods=['POST'])
def create_user():
    user_id = request.form['user_id_give']
    user_password = request.form['user_pw_give']
    user_nickname = request.form['user_nickname_give']

    pw_hash = hashlib.sha256(user_password.encode('utf-8')).hexdigest()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (user_id, user_password, user_nickname, github_id, 
                                 user_profile_pic, user_profile_pic_real, user_profile_info)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, pw_hash, user_nickname, '', '', 
                  'static/profile_pics/profile_placeholder.png', ''))
            
            return jsonify({'result': 'success'})
        except pymysql.IntegrityError:
            return jsonify({'result': 'fail', 'msg': '이미 존재하는 아이디입니다.'})

@app.route('/user', methods=['GET'])
@login_check
def read_user():
    user_info = get_user_info(g.user_id)
    if user_info:
        # 비밀번호 제거
        user_info.pop('user_password', None)
        return jsonify({'result': 'success', 'user_info': user_info})
    return jsonify({'result': 'fail', 'msg': '사용자를 찾을 수 없습니다.'})

@app.route('/login', methods=['POST'])
def login():
    user_id_receive = request.form['user_id_give']
    user_pw_receive = request.form['user_pw_give']
    pw_hash = hashlib.sha256(user_pw_receive.encode('utf-8')).hexdigest()
    
    with get_db_connection() as conn:
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("""
            SELECT user_id FROM users 
            WHERE user_id = %s AND user_password = %s
        """, (user_id_receive, pw_hash))
        result = cursor.fetchone()

    if result:
        payload = {
            "id": user_id_receive,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=60 * 60 * 24)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return jsonify({'result': 'success', 'token': token})
    else:
        return jsonify({'result': 'fail', 'msg': '아이디/비밀번호가 일치하지 않습니다.'})

@app.route('/check_dup', methods=['POST'])
def check_dup():
    user_id_receive = request.form['user_id_give']
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE user_id = %s", (user_id_receive,))
        exists = cursor.fetchone()[0] > 0
        
    return jsonify({'result': 'success', 'exists': exists})

@app.route('/update_profile', methods=['POST'])
@login_check
def save_img():
    user_id = g.user_id
    name_receive = request.form["nickname_give"]
    github_id_receive = request.form["github_id_give"]
    about_receive = request.form["about_give"]
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        if 'file_give' in request.files:
            file = request.files["file_give"]
            filename = secure_filename(file.filename)
            extension = filename.split(".")[-1]

            file_path = os.environ.get("S3_URI", "") + str(filename)

            # S3 업로드 (AWS 설정이 있는 경우)
            if os.environ.get("AWS_ACCESS_KEY_ID"):
                s3 = boto3.client('s3',
                              aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
                              aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"))
                s3.put_object(
                    ACL="public-read",
                    Bucket=os.environ.get("S3_BUCKET"),
                    Body=file,
                    Key=filename,
                    ContentType=extension)
            
            cursor.execute("""
                UPDATE users SET user_nickname = %s, github_id = %s, 
                               user_profile_info = %s, user_profile_pic = %s, 
                               user_profile_pic_real = %s
                WHERE user_id = %s
            """, (name_receive, github_id_receive, about_receive, 
                  filename, file_path, user_id))
        else:
            cursor.execute("""
                UPDATE users SET user_nickname = %s, github_id = %s, 
                               user_profile_info = %s
                WHERE user_id = %s
            """, (name_receive, github_id_receive, about_receive, user_id))
        
    return jsonify({"result": "success", 'msg': '프로필을 업데이트했습니다.'})

if __name__ == '__main__':
    init_database()  # 데이터베이스 초기화
    app.run('0.0.0.0', port=5000, debug=True)