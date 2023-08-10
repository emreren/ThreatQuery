FROM python:3.11

RUN pip install poetry

COPY . /app
WORKDIR /app

COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi --no-root

COPY . .

CMD ["uvicorn", "threatquery.main:app", "--host", "0.0.0.0", "--port", "8000"]
