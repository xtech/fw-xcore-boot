# Use the official Python image from the Docker Hub
FROM python:3.10-alpine

# Set the working directory for the container
WORKDIR /usr/src/app

# Copy the current directory contents into the container at /usr/src/app
COPY . .

# Install any dependencies specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Command to run your Python script along with the specified arguments
ENTRYPOINT ["python", "xbot-boot.py"]
