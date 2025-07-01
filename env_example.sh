# 로컬 개발 환경 설정
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=tdp

# JWT 시크릿 키 (반드시 변경하세요)
SECRET_KEY=your-very-secure-secret-key-here

# AWS 설정 (옵셔널 - S3 이미지 업로드용)
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
S3_BUCKET=your_s3_bucket_name
S3_URI=https://your_s3_bucket.s3.amazonaws.com/

# AWS RDS 설정 (프로덕션 환경)
# DB_HOST=your-rds-endpoint.region.rds.amazonaws.com
# DB_PORT=3306