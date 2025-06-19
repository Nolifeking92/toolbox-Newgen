FROM debian:stable-slim
RUN apt-get update && apt-get install -y hydra && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/usr/bin/hydra", "-h"] 