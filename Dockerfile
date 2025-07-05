# 使用官方的 Python 3.10 slim 版本的镜像作为基础
FROM python:3.10-slim

# 设置工作目录
WORKDIR /app

# 复制依赖文件到工作目录
COPY requirements.txt .

# 安装依赖库，--no-cache-dir 可以减小镜像体积
RUN pip install --no-cache-dir -r requirements.txt

# 复制你的应用代码到工作目录
COPY main.py .

# 暴露应用运行的端口 7860
EXPOSE 7860

# 容器启动时运行的命令
# 使用 uvicorn 启动 FastAPI 应用
# --host 0.0.0.0 确保可以从容器外部访问
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]
