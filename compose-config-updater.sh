#!/usr/bin/env bash

set -eo pipefail

log() {
    local level="$1"
    shift
    # check if the shell supports coloring output
    if [[ -t 1 ]]; then

        if [[ "$level" == "ERROR" ]]; then
            local color="31" # red
        elif [[ "$level" == "WARNING" ]]; then
            local color="33" # yellow
        elif [[ "$level" == "INFO" ]]; then
            local color="32" # green
        else
            local color="34" # blue, default
        fi

        # shell supports coloring output, print log messages with color
        echo -e "[$(date +"%Y-%m-%dT%H:%M:%S")]\033[${color}m [$level] $*\033[0m" >&2
    else
        # shell does not support coloring output, print log messages without color
        echo "[$(date +"%Y-%m-%dT%H:%M:%S")] [$level] $*" >&2
    fi
}

config_errors=0
if [[ -z "${NTSPOOL_CONFIG_UPDATER_SECRET}" ]]; then
  log "ERROR" "Please set NTSPOOL_CONFIG_UPDATER_SECRET environment variable"
  config_errors=1
fi

if [[ -z "${NTSPOOL_CONFIG_UPDATER_SERVERS_URL}" ]]; then
  log "ERROR" "Please set NTSPOOL_CONFIG_UPDATER_SERVERS_URL environment variable"
  config_errors=1
fi

if [[ -z "${NTSPOOL_CONFIG_UPDATER_SERVERS_OUTPUT_FILES}" ]]; then
  log "ERROR" "Please set NTSPOOL_CONFIG_UPDATER_SERVERS_OUTPUT_FILES environment variable"
  config_errors=1
fi

if [[ -z "${NTSPOOL_CONFIG_UPDATER_MONITOR_KEYS_URL}" ]]; then
  log "ERROR" "Please set NTSPOOL_CONFIG_UPDATER_MONITOR_KEYS_URL environment variable"
  config_errors=1
fi

if [[ -z "${NTSPOOL_CONFIG_UPDATER_MONITOR_KEYS_OUTPUT_FILES}" ]]; then
  log "ERROR" "Please set NTSPOOL_CONFIG_UPDATER_MONITOR_KEYS_OUTPUT_FILES environment variable"
  config_errors=1
fi

if [[ -z "${NTSPOOL_CONFIG_UPDATER_INTERVAL_SECONDS}" ]]; then
  log "ERROR" "Please set NTSPOOL_CONFIG_UPDATER_INTERVAL_SECONDS environment variable"
  config_errors=1
fi

if [[ $config_errors -ne 0 ]]; then
  log "ERROR" "Config updater cannot run due to missing configuration, exiting"
  exit 1
fi

# Split the output files by comma and trim whitespace
IFS=',' read -ra SERVERS_OUTPUT_FILES <<< "${NTSPOOL_CONFIG_UPDATER_SERVERS_OUTPUT_FILES}"
IFS=',' read -ra MONITOR_KEYS_OUTPUT_FILES <<< "${NTSPOOL_CONFIG_UPDATER_MONITOR_KEYS_OUTPUT_FILES}"


while true; do
  # First fetch the updated servers config and write it to the requested output file
  log "INFO" "Fetching servers config from ${NTSPOOL_CONFIG_UPDATER_SERVERS_URL}"
  if ! data=$(curl --fail -H "Authorization: Bearer ${NTSPOOL_CONFIG_UPDATER_SECRET}" "${NTSPOOL_CONFIG_UPDATER_SERVERS_URL}"); then
    log "ERROR" "Failed to fetch servers config from ${NTSPOOL_CONFIG_UPDATER_SERVERS_URL}"
  else
    log "INFO" "Fetched servers config from ${NTSPOOL_CONFIG_UPDATER_SERVERS_URL}"
    for output_file in "${SERVERS_OUTPUT_FILES[@]}"; do
      log "INFO" "Writing servers config to ${output_file}"
      if echo "$data" > "${output_file}"; then
        log "INFO" "Successfully wrote servers config to ${output_file}"
      else
        log "ERROR" "Failed to write servers config to ${output_file}"
      fi
    done
  fi

  # Next attempt to do the same for the monitor keys config
  log "INFO" "Fetching monitor keys config from ${NTSPOOL_CONFIG_UPDATER_MONITOR_KEYS_URL}"
  if ! data=$(curl --fail -H "Authorization: Bearer ${NTSPOOL_CONFIG_UPDATER_SECRET}" "${NTSPOOL_CONFIG_UPDATER_MONITOR_KEYS_URL}"); then
    log "ERROR" "Failed to fetch monitor keys config from ${NTSPOOL_CONFIG_UPDATER_MONITOR_KEYS_URL}"
  else
    log "INFO" "Fetched monitor keys config from ${NTSPOOL_CONFIG_UPDATER_MONITOR_KEYS_URL}"
    for output_file in "${MONITOR_KEYS_OUTPUT_FILES[@]}"; do
      log "INFO" "Writing monitor keys config to ${output_file}"
      if echo "$data" > "${output_file}"; then
        log "INFO" "Successfully wrote monitor keys config to ${output_file}"
      else
        log "ERROR" "Failed to write monitor keys config to ${output_file}"
      fi
    done
  fi

  log "INFO" "Sleeping for ${NTSPOOL_CONFIG_UPDATER_INTERVAL_SECONDS} seconds before next update"
  sleep "${NTSPOOL_CONFIG_UPDATER_INTERVAL_SECONDS}"
done
