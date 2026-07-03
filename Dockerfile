FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY clean_engine.py .
COPY app.py .
COPY .streamlit/ .streamlit/

# Code Engine inyecta la variable PORT y espera que la app escuche ahí (default 8080)
ENV PORT=8080
EXPOSE 8080

CMD streamlit run app.py \
    --server.port=${PORT} \
    --server.address=0.0.0.0 \
    --server.headless=true \
    --browser.gatherUsageStats=false
