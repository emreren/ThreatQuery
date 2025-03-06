# ThreatQuery API

ThreatQuery is a threat intelligence aggregation and analysis API that allows security professionals and organizations to query multiple threat intelligence sources from a unified interface. This project is designed to streamline the process of looking up indicators of compromise (IOCs) across different threat intelligence platforms and databases.

## Features

- IOC Lookup across multiple intelligence sources
- Indicator type detection (IP, Domain, URL, File hash)
- Threat score aggregation and analysis
- RESTful API for easy integration with security tools
- Comprehensive threat data enrichment

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

### Docker Installation (Recommended)

```bash
docker compose up -d
```

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

## License

This project is proprietary and confidential.