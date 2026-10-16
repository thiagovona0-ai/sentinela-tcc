FROM node:20-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json ./
COPY server.js index.html app.js style.css ./
COPY mascote-transparente.png ./
USER node
EXPOSE 3000
CMD ["npm", "start"]
