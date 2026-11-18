FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-deps -e .

RUN useradd --create-home --uid 10001 monitor \
 && mkdir -p /app/out \
 && chown -R monitor:monitor /app
USER monitor

ENTRYPOINT ["dns-monitor"]
CMD ["--help"]
