FROM python:3.12-slim
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vulnapp/ vulnapp/
USER app
ENV APP_HOST=0.0.0.0 APP_PORT=5000 APP_MODE=fixed
EXPOSE 5000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5000/')" || exit 1
CMD ["python", "-m", "vulnapp.app"]
