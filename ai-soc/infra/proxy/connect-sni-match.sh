#!/bin/sh
# Squid supplies the CONNECT URI and the actual ClientHello SNI as separate,
# URL-escaped helper fields. Only plain DNS names with the same identity pass.
while IFS=' ' read -r uri sni allowlist; do
    case "$uri" in
        http://*) authority=${uri#http://} ;;
        https://*) authority=${uri#https://} ;;
        *) authority=$uri ;;
    esac
    authority=${authority%%/*}
    case "$authority" in
        *:*) connect_host=${authority%:*} ;;
        *) connect_host= ;;
    esac
    connect_host=$(printf '%s' "$connect_host" | tr '[:upper:]' '[:lower:]')
    normalized_sni=$(printf '%s' "$sni" | tr '[:upper:]' '[:lower:]')
    allowed=false
    # The external ACL appends each configured host as a separate argument.
    # Disable pathname expansion before splitting the trusted host list.
    set -f
    for allowedlist_host in $allowlist; do
        allowedlist_host=$(printf '%s' "$allowedlist_host" | tr '[:upper:]' '[:lower:]')
        if [ "$connect_host" = "$allowedlist_host" ]; then
            allowed=true
            break
        fi
    done
    if [ -n "$connect_host" ] && [ "$normalized_sni" != "-" ] \
        && [ "$connect_host" = "$normalized_sni" ] \
        && [ "$allowed" = true ]; then
        printf 'OK\n'
    else
        printf 'ERR\n'
    fi
done
