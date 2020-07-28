#! /bin/bash

attr -S -g evm /sysroot/bin/cat &> /dev/null

if [ $? -eq 0 ]; then
    exit 0
fi

manage_digest_lists -p add-meta-digest
