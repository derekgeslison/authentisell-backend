FROM tiangolo/uvicorn-gunicorn-fastapi:python3.10
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
COPY authentisell-8d296228cc89.json /app/authentisell-8d296228cc89.json
ENV GOOGLE_APPLICATION_CREDENTIALS=/app/authentisell-8d296228cc89.json
EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "debug"]