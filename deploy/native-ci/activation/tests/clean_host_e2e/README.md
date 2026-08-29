# Disposable clean-host activation acceptance

This harness runs the capacity-one acceptance path only inside a disposable,
privileged systemd container. It never invokes host `systemctl`, never reads the
host credential store, and never accepts an unpinned candidate, image, package,
scenario, or fixture.

The workflow has two phases because the keyholder package and activation
package bind public keys, while the corresponding test credentials must be
fresh for every run:

```bash
HARNESS=deploy/native-ci/activation/tests/clean_host_e2e/harness.py
STATE="$PWD/.clean-host-e2e-state"
RESULTS="$PWD/.clean-host-e2e-results"

python3 "$HARNESS" prepare --state "$STATE" \
  --controld-uid 1201 --controld-gid 1201
# Freeze the component and activation packages using only
# $STATE/public-binding.json. Never read $STATE/private/.

python3 "$HARNESS" preflight --contract /protected/e2e-contract.json
python3 "$HARNESS" run --contract /protected/e2e-contract.json --results "$RESULTS"
```

`prepare` creates four independent raw secp256k1 test keys, a private local CA,
and a server certificate for `relay.test.invalid`. Private files are mode
`0400` below a mode-`0700` directory. `run` encrypts the keys with the
container's `systemd-creds`, installs only the public CA, and removes the raw
key files during cleanup. No key bytes, credential paths, request bodies, or
authorization headers are printed.

The supplied image must already exist locally and its image ID must equal the
contract. It must boot `/sbin/init` and provide Python 3, OpenSSL,
`systemd-creds`, `systemd-sysusers`, `systemd-tmpfiles`, `systemctl`, and
`update-ca-certificates`. The harness does not pull images or use a network
relay. The loopback TLS relay implements only `POST /events`,
`GET /ci/control/accepted`, and bounded `PUT /ci/logs/...` and
`PUT /ci/artifacts/...` object storage.

The in-container order is:

1. boot real systemd and install the generated test CA;
2. encrypt the four ephemeral credentials and start the relay as a real unit;
3. create the package-declared principals and install exact component packages;
4. snapshot the dormant config/unit state;
5. controller `check`, `stage`, and `activate` (qualified closed);
6. invoke the installed canary with the exact scenario;
7. invoke the installed strict receipt verifier and retain its JSON line;
8. controller `rollback`, stop the relay, and compare the independent dormant
   snapshot, unit states, processes, sockets, and activation-managed paths.

Every failure takes the same cleanup path. A run is a pass only if the canary,
installed verifier, rollback, and independent residue proof all pass.

Current integration dependency: the candidate must provide
`deploy/native-ci/execd/install.py` and a frozen execd package. The authoritative
base `c37841169fa3b7b84dc6475cbf97b06b2d9282d1` does not, so `preflight` is
expected to fail closed until the concurrent execd/package work lands.
