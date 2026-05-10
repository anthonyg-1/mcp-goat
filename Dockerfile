# SECURITY WARNING: This image contains INTENTIONAL VULNERABILITIES for training purposes.
# DO NOT deploy on a public network. Bind to localhost only via docker-compose port mapping.

FROM python:3.12-slim

WORKDIR /app

COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server/ .

# The container itself listens on all interfaces (0.0.0.0) so Docker networking works.
# The host-side binding is restricted to 127.0.0.1 by docker-compose.yml port mapping.
EXPOSE 8000

CMD ["python", "main.py"]
