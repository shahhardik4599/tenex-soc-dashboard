# /frontend/Dockerfile
FROM node:20-alpine

WORKDIR /app

# Disable Next.js telemetry during build (standard practice)
ENV NEXT_TELEMETRY_DISABLED 1

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the code
COPY . .

# Build the application
RUN npm run build

EXPOSE 3000

# Start the application
CMD ["npm", "start"]