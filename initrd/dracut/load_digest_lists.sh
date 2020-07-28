#! /bin/bash

if [ ! -f /sys/kernel/security/ima/digest_list_data ]; then
    exit 0
fi

digests_count=$(cat /sys/kernel/security/ima/digests_count)
if [ "$digests_count" = "0" ]; then
    exit 0
fi

for f in $(find $NEWROOT/etc/ima/digest_lists -type f); do
    if [ ! -f /etc/ima/digest_lists/$(basename $f) ]; then
        process_digest_list=$(getfattr -m - -e hex -d $f \
            2> /dev/null | awk '{ if ($1 ~ /security.evm/) evm=1;
                    if ($1 ~ /security.ima=0x03/) ima=1; }
                    END{ if (evm || ima) print "1" }')
        if [ -z "$process_digest_list" ]; then
            continue
        fi

        format=$(echo $f | cut -d - -f 3)
        if [ "$format" = "compact" ]; then
            echo $f > /sys/kernel/security/ima/digest_list_data
        else
            upload_digest_lists add $f
        fi
    fi
done
