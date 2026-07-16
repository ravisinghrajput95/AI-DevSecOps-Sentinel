# =========================================================
# AI DevSecOps Sentinel — frontend image
# Stage 1 builds the Vite bundle; stage 2 serves it with
# nginx, which also reverse-proxies the API paths to the
# backend container (same-origin, mirroring the dev proxy).
#
# NOTE: VITE_SENTINEL_API_KEY is baked into the JS bundle at
# build time. A key shipped to browsers is visible to anyone
# who can load the page — it gates casual/scripted access,
# not determined users. Real per-user auth is a later tier.
# =========================================================

FROM node:22-alpine AS build

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci

ARG VITE_SENTINEL_API_KEY=
ENV VITE_SENTINEL_API_KEY=${VITE_SENTINEL_API_KEY}

COPY . .
RUN npm run build


FROM nginx:1.29-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /build/dist /usr/share/nginx/html

EXPOSE 80
