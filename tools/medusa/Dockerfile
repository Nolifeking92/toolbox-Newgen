FROM debian:stable-slim
RUN apt-get update && apt-get install -y medusa && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["medusa"] 