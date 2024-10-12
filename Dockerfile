# Use an official Node.js image as the base image
FROM node:22-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of your application code to the working directory
COPY . .

# Expose the port on which the app will run
EXPOSE 3000

# Define the command to run both setup.js and server.js
CMD ["sh", "-c", "node setup.js && node server.js"]
