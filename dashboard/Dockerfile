FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN groupadd --gid 10002 dashboard \
    && useradd --uid 10002 --gid 10002 --create-home --shell /usr/sbin/nologin dashboard

COPY --chown=dashboard:dashboard app.py .
COPY --chown=dashboard:dashboard .streamlit /app/.streamlit

USER dashboard

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
