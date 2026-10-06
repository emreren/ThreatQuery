# ThreatQuery API

ThreatQuery is a threat intelligence aggregation and analysis API that allows security professionals and organizations to query multiple threat intelligence sources from a unified interface. This project is designed to streamline the process of looking up indicators of compromise (IOCs) across different threat intelligence platforms and databases.

## Features

- IOC Lookup across multiple intelligence sources
- Indicator type detection (IP, Domain, URL, File hash)
- Threat score aggregation and analysis
- RESTful API for easy integration with security tools
- Comprehensive threat data enrichment
- Spoken briefings in Turkish or English (ElevenLabs text-to-speech)

## Technology Stack

- FastAPI for the API framework
- PostgreSQL for database storage
- SQLAlchemy for ORM
- Docker for containerization
- Python 3.11+

## Setup and Installation

### Environment Configuration

1. Copy `.env.example` to `.env` for Docker settings:
   ```bash
   cp .env.example .env
   ```

2. Copy `.env.example` to `.env.secret` for local development and add your API keys:
   ```bash
   cp .env.example .env.secret
   ```
   Then edit `.env.secret` to add your actual API keys.

Environment variables override both files. `LOG_LEVEL` and `LOG_FILE` (default `app.log`) set logging.

### Docker Installation (Recommended)

```bash
docker compose up -d
```

`.env.secret` is not copied into the image (see `.dockerignore`); Compose mounts the project
directory, so the running container still reads it. Postgres data is kept in the `pgdata` volume.

### Manual Installation

1. Clone the repository
2. Install dependencies using Poetry:
   ```bash
   poetry install
   ```
3. Configure environment variables in `.env` and `.env.secret` files
4. Run the application:
   ```bash
   uvicorn threatquery.main:app --reload
   ```

## API Documentation

After starting the application, visit `http://localhost:8000/docs` for the Swagger UI documentation.

`GET /search/?ioc_value=<indicator>` accepts IPv4/IPv6 addresses, domains, URLs and MD5/SHA-1/SHA-256
hashes; anything else gets a 400 response and is not sent to the sources.

## Tests

```bash
poetry run pytest
```

The tests mock every external API and use a temporary SQLite database, so they need no API keys,
no Postgres and no network.

## Spoken briefings

`GET /brief/?ioc_value=<indicator>&lang=tr` runs the same analysis as `/search/` and returns a short
spoken summary as MP3 (`lang=en` for English), generated with the ElevenLabs text-to-speech API
(`eleven_multilingual_v2`). Add `ELEVENLABS_API_KEY` to `.env.secret` (or the environment);
`ELEVENLABS_VOICE_ID` picks another voice.

```bash
curl -o brief.mp3 "http://localhost:8000/brief/?ioc_value=203.0.113.45&lang=tr"
curl "http://localhost:8000/brief/?ioc_value=203.0.113.45&lang=en&text_only=true"
```

`text_only=true` returns only the text, `normalize=false` keeps the raw API values.

Normalisation is deliberately narrow. Briefings were compared with raw values and with everything
spelled out (IP addresses, timestamps, identifiers): IP addresses, `botnet_cc` and English names inside
Turkish sentences (VirusTotal, Cobalt Strike, Netherlands) were read correctly as they were; the raw
timestamp `2026-09-14 08:41:07 UTC` was the one thing read awkwardly in Turkish. So only timestamps and
source identifiers are rewritten (`14 Eylül 2026`, `botnet komuta kontrol sunucusu`); hashes are
shortened to their first 8 characters because a full SHA-256 takes too long to listen to.

## License

This project is proprietary and confidential.