# Use official Python runtime as base image
FROM python:3.11-slim

# Set working directory in container
WORKDIR /app

# Copy the Python script into the container
COPY hello.py /app/hello.py

# Make sure the script is executable
RUN chmod +x /app/hello.py

# Set the entrypoint to run the Python script
ENTRYPOINT ["python", "/app/hello.py"]