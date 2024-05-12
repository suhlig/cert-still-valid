# cert-still-valid

Returns with exit code

* `0` if the certificate of the given hostname will be valid in the given distance from now, or
* `1` if the certificate will not be valid anymore, or
* `2` if the certificate will not be valid yet.

On any other error, the exit code will be `3`.

This is intended for auto-refreshing [Tailscale certificates](https://tailscale.com/kb/1153/enabling-https) in a script like this:

```command
cert-still-valid --in 7d example.com

if [[ $? == 1 ]]; then
  tailscale cert --cert-file - --key-file - example.tailnet-1234.ts.net > /etc/ssl/example.pem && haproxy restart
fi
```
