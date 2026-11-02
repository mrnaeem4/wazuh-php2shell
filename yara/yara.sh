#!/bin/bash
# Wazuh - Yara active response
# Copyright (C) 2015-2022, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
#
# PHP2Shell variant: installed as /var/ossec/active-response/bin/yara.sh
# Triggered by FIM rules 111054/111055 (new/modified PHP file in the web root)
# and by 100300/100301 (test directory /tmp/yara/malware).
#
# Extra arguments passed by the manager:
#   -yara_path  <directory containing the yara binary>
#   -yara_rules <absolute path to the .yar ruleset>

#------------------------- Gather parameters -------------------------#

# Extra arguments
read INPUT_JSON
YARA_PATH=$(echo $INPUT_JSON | jq -r .parameters.extra_args[1])
YARA_RULES=$(echo $INPUT_JSON | jq -r .parameters.extra_args[3])
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.syscheck.path)

# Set LOG_FILE path
LOG_FILE="logs/active-responses.log"

if [ ! -f "${FILENAME}" ]; then
    echo "wazuh-yara: INFO - File ${FILENAME} no longer exists, skipping YARA scan." >> ${LOG_FILE}
    exit 0
fi

size=0
actual_size=$(stat -c %s ${FILENAME} 2>/dev/null)
while [ ${size} -ne ${actual_size} ]; do
    sleep 1
    size=${actual_size}
    actual_size=$(stat -c %s ${FILENAME} 2>/dev/null)
done

#----------------------- Analyze parameters -----------------------#

if [[ ! $YARA_PATH ]] || [[ ! $YARA_RULES ]]
then
    echo "wazuh-yara: ERROR - Yara active response error. Yara path and rules parameters are mandatory." >> ${LOG_FILE}
    exit 1
fi

#------------------------- Main workflow --------------------------#

# Execute Yara scan on the specified filename
yara_output="$("${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME" 2>&1)"

if [[ $yara_output != "" ]]
then
    # Iterate every detected rule and append it to the LOG_FILE
    while read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> ${LOG_FILE}
    done <<< "$yara_output"
fi

exit 0;
