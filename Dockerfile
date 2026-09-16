FROM python:3.14-slim AS build

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN uv venv /opt/venv && uv pip install --python /opt/venv/bin/python --no-cache .

FROM python:3.14-slim

# pg_dump for `dmarc-service backup`
RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 7700 --create-home dmarc
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

USER 7700
WORKDIR /home/dmarc

# web: 8000, smtp: 2525 (map to 25 at the LB/host; binding <1024 needs root)
EXPOSE 8000 2525

ENTRYPOINT ["dmarc-service"]
CMD ["web"]
