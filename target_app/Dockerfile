FROM python:3.12-slim

WORKDIR /srv
RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn[standard]>=0.30"

COPY app/ /srv/app/

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
