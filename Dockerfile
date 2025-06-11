# Use an official Python runtime as a base image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy local code to the container image
COPY . .

# Install any dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Command to run on container start
CMD ["python", "app.py"]
