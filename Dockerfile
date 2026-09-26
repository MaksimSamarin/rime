FROM node:22-bookworm-slim AS dashboard
WORKDIR /dashboard
COPY app/dashboard/package*.json ./
COPY app/dashboard/chakra.config.ts ./
RUN npm ci
COPY app/dashboard/ ./
RUN VITE_BASE_API=/api/ npm run build -- --outDir build --assetsDir statics --emptyOutDir \
    && cp build/index.html build/404.html

# Match the isolated lab runtime and Xray; no floating core download on build.
FROM gozargah/marzban@sha256:8e422c21997e5d2e3fa231eeff73c0a19193c20fc02fa4958e9368abb9623b8d
WORKDIR /code
COPY requirements.txt requirements-panel.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . /code
COPY --from=dashboard /dashboard/build /code/app/dashboard/build
CMD ["bash", "-c", "alembic upgrade head && exec python main.py"]
