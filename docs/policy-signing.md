# Signed policies

The policy decides what reaches your LLM provider, so whoever can change the policy file can switch the firewall off. With signing on, a proxy only uses a policy that was signed with your private key: a file changed on the disk, in a ConfigMap or on the way from a management server is rejected, and the proxy keeps the policy it has.

## Set up

```sh
promptwall keygen ops                       # writes ops.key (private) and ops.pub (public)
promptwall sign --key ops.key policy.yaml   # writes policy.yaml.sig
promptwall --policy policy.yaml --policy-public-key ops.pub
```

- Keep `ops.key` where policies are approved: a CI pipeline secret, a vault, or the management server. Proxies only get `ops.pub`.
- `promptwall sign` refuses a policy that does not load, so nothing invalid gets signed.
- Signatures are Ed25519 over the exact bytes of the file, stored as base64 in `<policy file>.sig`. Any whitespace change needs a new signature.

## What is checked

| When | Without a valid signature |
| --- | --- |
| Start, `validate`, `test`, `scan` with `--policy-public-key` | The command fails |
| Reload after the file or its signature changes | Logged as an error, counted in `promptwall_policy_reloads_total{result="error"}`; the previous policy stays in force |

When you replace both files, the proxy may see the new policy before the new signature and log one rejected reload; it loads the policy as soon as the signature matches. Write the signature first, or swap both at once (as a Kubernetes ConfigMap does), to avoid that.

Signing is optional and off by default: for one person editing a file on their own server it adds nothing.
