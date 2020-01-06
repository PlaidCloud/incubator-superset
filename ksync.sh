#!/bin/bash

if [ "$1" != "" ]; then
    ksync create -n $1 -l plaid=superset-events --name superset-events --local-read-only --reload=false $(readlink -f ./plaid) /plaid/plaid
    if [ $? -eq 0 ]; then 
        echo "ksync spec created successfully for superset-events."
    fi
else
    echo "No valid namespace specified."
    echo "Usage: ksync.sh <namespace-name>"
fi
