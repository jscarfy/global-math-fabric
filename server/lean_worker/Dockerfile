FROM leanprover/lean4:stable
WORKDIR /app
# python is already in this image on most tags; if not, uncomment:
# RUN apt-get update && apt-get install -y python3 python3-pip && rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install --no-cache-dir -r requirements.txt
COPY requirements.txt /app/requirements.txt
COPY app.py /app/app.py
EXPOSE 8090
CMD ["python3","-m","uvicorn","app:app","--host","0.0.0.0","--port","8090"]
