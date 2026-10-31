# Dashboard: build with Node, serve the static files with Nginx on port 3000.
FROM node:25-alpine@sha256:bdf2cca6fe3dabd014ea60163eca3f0f7015fbd5c7ee1b0e9ccb4ced6eb02ef4 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY index.html vite.config.js ./
COPY src src
RUN npm run build

FROM nginx:1.30-alpine@sha256:0e52bd054126cdc040b1276c0af347aeb02a41b9cfe305d6094767ac30e97949
# nginx only serves files: drop curl (and libcurl) instead of patching them; brotli-libs stays (freetype needs it).
# shortcut: the brotli upgrade unpins one package; remove it once a Dependabot digest bump ships brotli >= 1.2.1.
RUN apk del --no-cache curl && apk upgrade --no-cache brotli-libs
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 3000
