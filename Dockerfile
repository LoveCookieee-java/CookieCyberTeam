# Generated for Smithery and containerized MCP deployment
FROM python:3.11-slim

WORKDIR /app

# Copy package files
COPY pyproject.toml README.md server.py ./
COPY core/ ./core/

# Install the package in container
RUN pip install --no-cache-dir .

# Default stdio entrypoint for MCP
ENTRYPOINT ["cookie-cyber-team", "--stdio"]
