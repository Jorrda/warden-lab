FROM python:3.12-slim
WORKDIR /srv/portal
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV FLASK_ENV=production
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:create_app()"]
