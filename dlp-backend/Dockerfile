FROM python:3.12-slim

WORKDIR /app

# Git is required for repository/history scans; Tesseract and English/Hindi
# language data provide OCR for scanned PDF pages.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git tesseract-ocr tesseract-ocr-eng tesseract-ocr-hin libxml2 libxmlsec1 libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["sh", "scripts/docker-entrypoint.sh"]
