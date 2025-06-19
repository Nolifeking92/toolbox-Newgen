FROM debian:stable-slim
RUN apt-get update && apt-get install -y masscan && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["masscan"] 