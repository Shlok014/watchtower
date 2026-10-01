FROM node:22-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
ENV VITE_API_URL=/api/v1
ENV VITE_PUBLIC_DEMO=1
RUN npm run build

FROM python:3.13-slim AS runtime
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/backend \
    WATCHTOWER_PUBLIC_DEMO=1 \
    WATCHTOWER_SOURCES=synthetic \
    WATCHTOWER_DATA_DIR=/tmp/watchtower
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt gunicorn==23.0.0
COPY backend/ /app/backend/
COPY --from=frontend-build /app/frontend/dist/ /app/frontend/dist/
EXPOSE 10000
CMD ["sh", "-c", "exec gunicorn --workers 1 --threads 4 --timeout 60 --bind 0.0.0.0:${PORT:-10000} 'watchtower.app:create_app()'"]
