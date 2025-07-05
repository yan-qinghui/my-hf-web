# -----------------------------------------------------------------------------
# Dockerfile for HuggingFace WebDAV Server
# -----------------------------------------------------------------------------

# --- Stage 1: Define the Base Image ---
# Use a slim, official Python image. 'bookworm' is a stable Debian release.
# This matches the base image we inferred from 'docker history'.
FROM python:3.9-slim-bookworm

# --- Environment Variables ---
# Set the language to prevent locale errors with certain tools.
ENV LANG C.UTF-8
# Prevents Python from writing .pyc files to disk.
ENV PYTHONDONTWRITEBYTECODE 1
# Ensures Python output is sent straight to the terminal without buffering.
ENV PYTHONUNBUFFERED 1

# --- System Setup ---
# Create a non-root user and group to run the application.
# This is a critical security best practice.
RUN useradd -m -u 1000 user

# Set the working directory for the application.
WORKDIR /code

# --- Python Dependencies ---
# Copy only the requirements file first to leverage Docker's layer caching.
# The layer containing these dependencies will only be rebuilt if requirements.txt changes.
COPY requirements.txt .

# Install Python dependencies.
# --no-cache-dir: Disables the pip cache, which reduces image size.
# --upgrade pip: It's good practice to use the latest version of pip.
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# --- Application Code ---
# Copy the application source code into the container.
# This is done after installing dependencies, so changes to the code
# won't cause the dependencies to be re-installed.
COPY app.py .

# Change the ownership of the application code to the non-root user.
RUN chown -R user:user /code

# Switch to the non-root user.
# From this point on, all subsequent commands will be run as 'user'.
USER user

# --- Networking ---
# Expose the port the application will run on.
# This is documentation for the user and for linking containers.
# It does not actually publish the port.
EXPOSE 7860

# --- Run Command ---
# Define the command to run the application when the container starts.
# Uses exec form to be the container's main process (PID 1).
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860"]
