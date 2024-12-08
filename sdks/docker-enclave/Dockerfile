# Use the official Nginx image as the base image
FROM nginx:alpine

# Copy a custom index.html to the Nginx html directory
COPY index.html /usr/share/nginx/html/index.html

# Expose port 8001
EXPOSE 8001

# Update the Nginx configuration to listen on port 8001
RUN sed -i 's/listen 80;/listen 8001;/' /etc/nginx/conf.d/default.conf

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]
