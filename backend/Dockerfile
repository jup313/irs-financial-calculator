# Stage 1: Build Stage
# This stage installs all dependencies (including dev) and can be used for building/testing.
FROM node:18-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# If you have a build step (e.g., for TypeScript or a frontend framework), it would go here.
# RUN npm run build

# ---

# Stage 2: Production Stage
# This stage creates the final, lean image with only production dependencies.
FROM node:18-alpine

WORKDIR /app

# Create a non-root user for better security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Create /data directory for SQLite and give appuser ownership
# Must be done as root BEFORE switching user
RUN mkdir -p /data && chown appuser:appgroup /data

# Copy package files from the builder stage
COPY --from=builder /app/package*.json ./

# Install ONLY production dependencies using npm ci for reliability
RUN npm ci --only=production

# Copy the application source code from the builder stage
# The .dockerignore file will prevent node_modules from the host from being copied.
COPY --from=builder /app .

# Switch to the non-root user
USER appuser

EXPOSE 8080

CMD ["npm", "run", "start"]
