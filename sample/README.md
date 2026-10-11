# Curve25519 Sample

See the source code in `src/` for usage.

Build instructions (to adapt to your system):
```sh
export JAVA_HOME=/usr/lib/jvm/jdk-17.0.20-oracle-x64
export PATH="/usr/lib/jvm/jdk-17.0.20-oracle-x64/bin:$PATH"
ant
```

Installation instructions:
```sh
gp --install Curve25519Test.cap
```

## Applet APDU usage

All the keys are generated once on applet installation.

Get the Ed25519 public key:
```
00 10 00 00 00
```

Get the X25519 public key:
```
00 10 01 00 00
```

Compute a Ed25519 signature:
```
00 20 00 00 40 <sha512 hash> 00
```

Verify a Ed25519 signature:
```
00 40 00 00 80 <sha512 hash> <signature>
```

Perform a X25519 key exchange:
```
00 30 00 00 20 <remote public key> 00
```
