# WatchTower: AI SOC Analyst

A self-hosted security operations project. WatchTower collects system
logs, stores them in PostgreSQL, and is being extended with detection
rules and an AI triage agent that works under human approval. Built as
a portfolio project for SOC and security analyst roles.

## Current status

Phase 1, log ingestion, is working and tested for Linux authentication
logs. A real collector run sends events through the API and stores them
in the database with no manual steps.

Working today:

- One event schema (SchemaEventIn) shared by the API, the database
  layer, and the collectors, with the same field names in all three
  places
- FastAPI ingest service: POST /events and GET /health
- PostgreSQL 16 running in Docker, with an events table
- Linux auth normalizer: turns Failed password and Accepted password
  lines from auth.log into login_failed and login_success events, and
  always keeps the raw line
- Linux collector: reads a log file, translates each line, sends the
  events to the API, and prints the stored database ids
- A pytest suite of 5 tests covering the normalizer and the collector

## How it flows

    Linux auth.log
      -> collector (reads and ships, nothing more)
      -> normalizer (translates lines into events)
      -> HTTP POST to the ingest API
      -> PostgreSQL events table
      -> the new id travels back to the collector

## Tech stack

Python 3.13, FastAPI, Pydantic, SQLAlchemy, PostgreSQL 16 (Docker),
httpx, pytest, and a VirtualBox lab running Ubuntu.

## Project structure

    collectors/          Log readers and shippers. Kept deliberately dumb.
    services/ingest/     Ingest API, event schema, normalizer, database layer.
    services/detection/  Detection rules (planned).
    services/agent/      AI triage agent (planned).
    services/intel/      Threat intel lookups (planned).
    services/reports/    Shift reports (planned).
    tests/               Pytest suite and sample log fixtures.
    docker-compose.yml   PostgreSQL service.
    requirements.txt     Python dependencies.

## Run it

1. Create and activate a virtual environment, then install:

       python -m venv .venv
       .\.venv\Scripts\Activate.ps1
       python -m pip install -r requirements.txt

2. Copy .env.example to .env and set your own values.

3. Start the database:

       docker compose up -d

4. Start the ingest API:

       uvicorn services.ingest.main:app --port 8000

5. Send a sample log through the collector:

       python -m collectors.linux_auth tests/fixtures/auth_sample.log

6. Run the tests:

       python -m pytest

## Roadmap

- Phase 1: log ingestion (Linux auth done, web access logs next)
- Phase 2: detection rules mapped to MITRE ATT&CK
- Phase 3: AI triage agent with human approval gates
- Phase 4: SOC dashboard with shift logs
- Phase 5: isolated attack lab scenarios and a proof pack

## Safety and secrets

Training lab only. Attack work runs inside an isolated VirtualBox lab
on a host-only network, against my own virtual machines. Secrets live
in .env, which is never committed to Git. The .env.example file shows
the required variables with placeholder values only.
