# Match the isolated lab runtime and Xray; no floating core download on build.
FROM gozargah/marzban@sha256:8e422c21997e5d2e3fa231eeff73c0a19193c20fc02fa4958e9368abb9623b8d
WORKDIR /code
# Remove the inherited frontend before copying the single Rime console.
RUN rm -rf /code/app/dashboard /code/build_dashboard.sh /code/marzban.code-workspace
COPY requirements.txt requirements-panel.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.txt -c requirements.lock
COPY . /code
# Public code must remain traversable when the runtime uses a non-root UID.
RUN find /code -type d -exec chmod 755 {} +
CMD ["bash", "-c", "alembic upgrade head && exec python main.py"]
