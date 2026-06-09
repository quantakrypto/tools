# qScan examples

## `vulnerable-app/`

A deliberately quantum-vulnerable sample project:

- `package.json` depends on `node-forge` and `elliptic` (both ship classical
  asymmetric crypto).
- `src/crypto.js` uses RSA key generation, ECDH key exchange, and ECDSA signing.

### Scan it

From the repository root, after building the package:

```bash
# Human banner (default)
qscan packages/qscan/examples/vulnerable-app

# Machine-readable SARIF, written to a file (e.g. for code scanning upload)
qscan packages/qscan/examples/vulnerable-app --format sarif -o qscan.sarif

# Fail only on critical findings
qscan packages/qscan/examples/vulnerable-app --severity-threshold critical

# Accept the current findings as a baseline, then scan against it
qscan packages/qscan/examples/vulnerable-app --write-baseline baseline.json
qscan packages/qscan/examples/vulnerable-app --baseline baseline.json
```

Running without building, via the workspace:

```bash
npm run build -w @qproof/qscan
node packages/qscan/dist/cli.js packages/qscan/examples/vulnerable-app
```
