# is-tls-expiring

Returns with exit code `0` if the certificate of the given hostname will be valid in the given distance from now, exits `2` if not. On any other error, the exit code will be `1`.

This is intended for auto-refreshing [Tailscale certificates](https://tailscale.com/kb/1153/enabling-https) in a script like this:

```command
is-tls-expiring --in 7d example.com

if [[ $? == 2 ]]; then
  tailscale cert --cert-file - --key-file - example.tailnet-1234.ts.net > /etc/ssl/example.pem && haproxy restart
fi
```
