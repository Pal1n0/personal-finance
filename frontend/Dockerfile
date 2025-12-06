# Frontend Dockerfile
FROM node:22

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm ci --legacy-peer-deps

# Copy the rest of the project
COPY . .

# Expose port for Vite dev server
EXPOSE 5173

# CMD to start the dev server
CMD ["npm", "run", "dev"]
