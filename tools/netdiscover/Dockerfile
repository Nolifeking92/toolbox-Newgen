FROM debian:stable-slim
RUN apt-get update && apt-get install -y netdiscover && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["netdiscover"] 