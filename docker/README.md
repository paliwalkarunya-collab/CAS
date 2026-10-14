# CAS-SE Docker Infrastructure Guide

This directory documents the multi-container development environment configured in `docker-compose.yml`.

## Services

1. **`cas-se-api`** (FastAPI)
   - Exposes REST API on port `8000`.
   - Runs with Python 3.13 and uvicorn.
   - Depends on healthy Postgres, MinIO, Redis, and OPA.

2. **`cas-se-opa`** (Open Policy Agent)
   - Evaluates Rego policies on port `8181`.
   - Mounts policies from `./opa/policies`.
   - Exposes `/health` endpoint for readiness.

3. **`cas-se-worker`** (Celery)
   - Executes background ML workloads and asynchronous tasks.
   - Connected to Redis broker (`cas-redis`).

4. **`cas-postgres`** (PostgreSQL 16)
   - Reference relational database holding `cas_*` overlay schema.
   - Port `5432`.

5. **`cas-minio`** (MinIO S3-Compatible Storage)
   - Reference object storage engine holding ciphertext blobs.
   - Port `9000` (S3 API), `9001` (Web console).

6. **`cas-redis`** (Redis 7)
   - Message broker and caching layer on port `6379`.

## Quick Start
```bash
docker compose up -d --build
docker compose ps
docker compose logs -f cas-se-api
```
