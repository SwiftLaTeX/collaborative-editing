
FROM node:8
RUN apt-get update && apt-get install -y git
RUN git clone https://github.com/SwiftLaTeX/collaborative-editing /app && \
    cd /app && npm install && echo "0.1"

WORKDIR /app
CMD ["npm", "start"]