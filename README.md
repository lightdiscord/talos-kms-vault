# talos-kms-vault

Proxy between a Talos node and a Hashicorp Vault instance to enable KMS disk encryption.
This project is a proof of concept.

## Usage

The Vault client uses the environment variables to configure itself, `VAULT_ADDR` and `VAULT_TOKEN` should be used.
The token needs to use a policy that allows the `update` capability to `:transit-path/encrypt/+` and `:transit-path/decrypt/+`.

## TODOs

* Talos Node's ID seems to be a UUID, if that's always the case implement a validation on the `Seal`/`Unseal` methods.
* Dynamic vault authentication (don't use a static token and try to use the right method for the current context) 
* Maybe transform this into a Vault plugin.

## References

* KMS client and server example - https://github.com/siderolabs/kms-client