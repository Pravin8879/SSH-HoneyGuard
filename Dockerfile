FROM python:3.11-slim

# Create a dedicated non-root user
RUN groupadd --gid 10001 honeyguard \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin honeyguard

WORKDIR /app

# Copy only the dependency file for now
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the project source
COPY --chown=honeyguard:honeyguard . .

# Switch away from root
USER honeyguard

# SSH honeypot listens on port 2222.
EXPOSE 2222

# Start the Phase 6 SSH honeypot.
CMD ["python", "-m", "app.main"]
