FROM python:3.13-slim

WORKDIR /app

COPY app/ /app/

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 设置默认执行命令
CMD ["python", "main.py"]
