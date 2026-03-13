#!/usr/bin/with-contenv bashio
export INTERFACE=$(bashio::config 'interface')
export ES_HOST=$(bashio::config 'es_host')
export ES_INDEX=$(bashio::config 'es_index')
export ES_USERNAME=$(bashio::config 'es_username')
export ES_PASSWORD=$(bashio::config 'es_password')
export BATCH_SIZE=$(bashio::config 'batch_size')
bashio::log.info "Starting sniffer on: ${INTERFACE}"
exec python3 /sniffer.py
