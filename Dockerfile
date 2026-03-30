FROM php:8.3-cli

WORKDIR /app

# Пакеты для composer (unzip) и типовых зависимостей
RUN apt-get update \
  && apt-get install -y --no-install-recommends git unzip ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

# Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

CMD ["php", "-v"]

