# Docker

The image is based on `python:3.12-slim`, installs the package as a non-root `monitor` user, and exposes the `dns-monitor` CLI as its entrypoint.

```bash
# Demo (no privileges, deterministic output)
docker compose -f docker/docker-compose.yml run --rm demo

# Live capture on Linux (host network + NET_RAW/NET_ADMIN)
docker compose -f docker/docker-compose.yml run --rm monitor

# Build only
docker build -f docker/Dockerfile -t dns-monitor:local .
```

Reports and event stores are written to `docker/out/`, mounted from the container's `/app/out`.

> Host networking and raw sockets are Linux-only. On macOS/Windows, run `dns-monitor run --simulate 600` locally or analyse a pre-captured PCAP with `dns-monitor analyze file.pcap`.
