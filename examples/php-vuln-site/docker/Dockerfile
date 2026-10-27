# PHP 8.5.11 for the nr-authz-radar local demo. Local use only; never deploy this image.
FROM php:8.5.11-cli

# git + unzip for Composer, SQLite PDO for the demo database.
RUN apt-get update >/dev/null && apt-get install -y --no-install-recommends git unzip >/dev/null \
    && rm -rf /var/lib/apt/lists/* && docker-php-ext-install pdo_sqlite >/dev/null

# Composer, for installing the app's PHP dependencies on first run.
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# New Relic PHP agent (optional). Build with --build-arg NR_AGENT=1 to include it; it only reports
# anything when NEW_RELIC_LICENSE_KEY is set at runtime. Pinned to a version that supports PHP 8.5.
ARG NR_AGENT=0
ARG NR_AGENT_VERSION=12.12.0.18
RUN if [ "$NR_AGENT" = "1" ]; then \
      curl -fsSL "https://download.newrelic.com/php_agent/release/newrelic-php5-${NR_AGENT_VERSION}-linux.tar.gz" -o /tmp/nr.tar.gz && \
      mkdir /tmp/nr && tar -C /tmp/nr -xzf /tmp/nr.tar.gz --strip-components=1 && \
      NR_INSTALL_SILENT=1 NR_INSTALL_USE_CP_NOT_LN=1 /tmp/nr/newrelic-install install && \
      rm -rf /tmp/nr /tmp/nr.tar.gz ; \
    fi

WORKDIR /app
EXPOSE 8000
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
CMD ["entrypoint.sh"]
