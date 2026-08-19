# Short-lived service-principal testing

Verification must run as the represented principal. Databricks does not provide a safe arbitrary-user impersonation switch for Statement Execution. Create a representative service principal, add it to the exact account group being tested, and authenticate as that service principal.

A workspace administrator can create a short-lived on-behalf-of token when token management is enabled:

```bash
scripts/create_obo_token_file.sh \
  '<administrator-profile>' \
  '<service-principal-application-id>' \
  "$HOME/.cache/abac-test/obo-token.json"
```

The helper refuses paths inside the repository, uses restrictive permissions, and never prints the token. The output JSON is sensitive. Extract the token only into a short-lived process environment or protected Databricks profile; never pass it on a command line, paste it into logs, or store it in desired state.

If on-behalf-of token creation is disabled, use OAuth M2M instead. A workspace administrator can create a short-lived secret for a service principal already assigned to the workspace:

```bash
databricks service-principal-secrets-proxy create \
  '<service-principal-id>' --lifetime 3600s --profile '<administrator-profile>'
```

Capture the JSON directly into a protected temporary file (`umask 077`); do not print it. Configure a temporary Databricks profile with the service principal application ID as `client_id` and the returned secret as `client_secret`. Delete the credential immediately after testing:

```bash
databricks service-principal-secrets-proxy delete \
  '<service-principal-id>' '<secret-id>' --profile '<administrator-profile>'
```

Run `abac-system-tables verify` with a scenario profile that authenticates as this service principal. Confirm the profile's `current_user()`/`session_user()` result through the tool's identity preflight. After testing, revoke the OBO token or OAuth secret and securely delete the local file.

Also remove temporary service principals and group memberships unless they are retained as controlled regression-test identities. Record only pass/fail evidence; do not record tokens, application IDs, principal IDs, workspace IDs, hosts, or query rows.
