# Use Alpine for smaller image size
FROM alpine:3.19

# Install Python and required packages
RUN apk add --no-cache \
    python3 \
    py3-pip \
    curl \
    git

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.48.3

# Set working directory
WORKDIR /app

# Copy the scanner script
COPY scan.py /app/scan.py

# Make script executable
RUN chmod +x /app/scan.py

# Set the entrypoint
ENTRYPOINT ["python3", "/app/scan.py"]