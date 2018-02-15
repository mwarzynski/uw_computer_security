FROM ubuntu

# Install nginx
RUN \
  apt-get update && \
  apt-get install -y nginx && \
  echo "\ndaemon off;" >> /etc/nginx/nginx.conf && \
  chown -R www-data:www-data /var/lib/nginx && \
  ln -sf /dev/stdout /var/log/nginx/access.log 

# Configure nginx
ADD ./default /etc/nginx/sites-available/default
ADD ./index.html /var/www/html/index.html

# Define default command.
CMD ["nginx"]

# Expose ports.
EXPOSE 80
