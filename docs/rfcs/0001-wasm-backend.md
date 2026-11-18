# WASM backend (v0.2 sketch)

v0.1 interprets the typed tree and hashes a canonical IR. v0.2 should lower that IR with `wasm-encoder` and run it under Wasmtime.

Constraints worth writing down before anyone starts:

- Secret values lower only to a subset that has no secret-dependent branch, in the spirit of CT-Wasm. The checker already rejects those branches; the backend must not reintroduce them with `select` implemented as a real branch.
- Capability calls stay imports. The host still re-checks scopes.
- The artifact hash remains a hash of the canonical IR, not of the Wasm bytes, so a seal from v0.1 still names the same program. A second hash of the Wasm can be added. It must not silently replace the IR hash.
