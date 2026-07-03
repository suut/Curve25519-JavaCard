# Ed25519 and X25510 on NXP JCOP 4.5 / J3R452 smartcards

This is a **hardware** implementation for the J3R452 JavaCard. This package is a lightweight wrapper
around the private NXP APIs for Ed25519 and X25519 which allow you to actually fully do what your
J3R452 is capable of without selling your soul to NXP.

This package also hides the peculiarities of the NXP APIs which has its public keys and signatures
in big-endian format. Thus this package uses the regular little-endian format used everywhere else.

## Installation and usage

Install the package with [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro):

```sh
java -jar gp.jar --load Curve25519.cap
```

Then use the export files by adding the `<import jar="curve25519.jar" />` directive in the `<cap />` tag in your `build.xml`
when building with [ant-javacard](https://github.com/martinpaljak/ant-javacard).

## API

```java
public interface Curve25519Key {
    public byte getKeyMemoryType();
}

public interface Curve25519PrivateKey extends PrivateKey, Curve25519Key {
    public short getS(byte[] buffer, short offset);
    public void setS(byte[] buffer, short offset, short length);
}

public interface Curve25519PublicKey extends PublicKey, Curve25519Key {
    public short getW(byte[] buffer, short offset);
    public void setW(byte[] buffer, short offset, short length);
}

public final class Curve25519KeyBuilder {
    public static final byte ALG_TYPE_EDDSA_PRIVATE = -127;
    public static final byte ALG_TYPE_EDDSA_PUBLIC = -128;
    public static final byte ALG_TYPE_X25519_PRIVATE = -125;
    public static final byte ALG_TYPE_X25519_PUBLIC = -126;

    private Curve25519KeyBuilder();

    public static Key buildKey(byte algo, byte memoryType) throws CryptoException;

    public static void genKeyPair(PrivateKey privateKey, PublicKey publicKey) throws CryptoException;
}

public final class Curve25519Signature {
    public Curve25519Signature();

    public short sign(PrivateKey privateKey, byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset);

    public boolean verify(PublicKey publicKey, byte[] inBuff, short inOffset, short inLength, byte[] signatureBuff, short signatureOffset, short signatureLength);
}

public final class Curve25519KeyAgreement {
    public Curve25519KeyAgreement();

    public short keyExchange(PrivateKey privateKey, PublicKey publicKey, byte[] outBuff, short outOffset) throws CryptoException;
}
```

Objects need to be allocated with `new` for `Curve25519Signature` and `Curve25519KeyAgreement`. Once you have the objects they
can be used with any arbitrary key.

An EdDSA signature takes about 220 ms while a X25519 key exchange takes about 50 ms.

## Security

Again this is not a software implementation, it is as secure as the underlying hardware implementation is.

The full source code is not provided for legal reasons, but anyone is free to disassemble the .cap file to ensure no funny business is going on.

You can contact me at the email address attached to the PGP key for any question or clarification.

### Hashes

The hashes are signed with the same key `F3A9F6CC8376D25400A271FB1BA818DB332833E4` used for commits to this repo:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mJMEakbsehMJKyQDAwIIAQENBAMEcEdS57x6G3rnb6W4eCzML8pMEvVOldUrTolC
hCvh2/ENSaJDEdPYh3zo7Qon+Zisilyvhg+/5T33V0tISESFAINpnO7QZF6YmEGd
aD7WHE9jJtjPZrvT3m8TACui3NTouS04OhDjrj08FmGudDDlrcmw0dBEko2xP/dK
sQ+U6Fe0FnN1dXQgPGNvbnRhY3RAc3V1dC5pbj6I0AQTEwoAOAULCQgHAgYVCgkI
CwIEFgIDAQIeAQIXgBYhBPOp9syDdtJUAKJx+xuoGNszKDPkBQJqRu4jAhsjAAoJ
EBuoGNszKDPkmA8B/REn4aGWw52AqLi7S6MYl2p0IpjrGTmzcFkMzqFRGKXs+NY0
ziOnYLnsvOSvFNRRPhBpgUkxaEJq9IHbhSxjkbICAJuTnGLkwdtEYS/QHC446jGI
3F92JjdxejlxB6kCnLTSJD619NzwzvlYocUuB/2F7Wk3r54pmKsMfmBYxBgaT724
lwRqRux6EgkrJAMDAggBAQ0EAwSjbEbzl4+I8WU5oM31phzOiAFQHztbD2WJOOss
/l2uJLeMGC5BdisJWwSng3gNUqsYRV9fx/iEssZZxXdLbdU7pfcZEh2U9Xmo+IoH
iqORr7dB/Nhhuaoxhe6BmJ5qhe0KyysD23upuleEQEZGJTH5RaVR7JtdrQanxJxq
XwZxoQMBCgmIuAQYEwoAIBYhBPOp9syDdtJUAKJx+xuoGNszKDPkBQJqRu7/AhsM
AAoJEBuoGNszKDPkxYAB/AvHbO+IqY5h0wjNimmeLmDksl27pfO1A2iRJ3BHYI+Y
3ecBXoQmPAY2iCFMW2xaEib9lWF8t6O6UaYu2BaSqFQB/A99fYb4L1NO9MRlGthl
yXoxFrRfkurIl7vwv0q+UIwciCRqf2IBdZNbnvQSw44FvioVO8VGPI4MffOrseHe
uj+4lwRqRux6EgkrJAMDAggBAQ0EAwSjeuaiJ/xsiMMMo78NHxhpNVOLUzWWgoG+
V97L2Fd52l9nRwz//leVesw1rACbdaH7TPqRI4S8LcjtwLT/zwEZR2PYsnuer43r
WBIBopsjY+gK1//IAtUPfdomyOJf05gQ+k6YcTQhYyuUTI/nx6y71CeQ4Y8HRbj7
TVvmqv8DugMBCgmIuAQYEwoAIBYhBPOp9syDdtJUAKJx+xuoGNszKDPkBQJqRu4z
AhsMAAoJEBuoGNszKDPklhkB/iNP3a9Pu3E1vlyRQUFM31FJm0Zu+jFw8LJf+dtp
TxvAz03cYj/COyKfHV6lmMiM3Ya1XsvgC4W+nBeD5SRI0UUB/iABB6/4+7a5Tqra
QKORAuuSffz1zwx7VkQYcc8dmCJ027yHe6MB7g8h6xva6aWPA0DXvApVP4FoY3cQ
n7BSsog=
=l2Qo
-----END PGP PUBLIC KEY BLOCK-----
```

```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

| Hash type      | Hash value                                                       |
| -------------- | ---------------------------------------------------------------- |
| LFDB SHA-1     | b14d9ba58a7026dd83a1d4cde83c9e95f25575e3                         |
| LFDB SHA-256   | 165a2191f071ad6d9c766a142a33a1f7c9e8b4331c6d2e362df17eb9a4ba9736 |
| .cap SHA-256   | bd6bd5fb0d007666877d47e423ceda8c28e61fc0f7f402e2fe98384af51682a5 |
| .jar SHA-256   | ab20a1065b15c556f37616984c3e279398fc42dbf1104b58d42973f9ed59ee71 |
-----BEGIN PGP SIGNATURE-----

iLUEARMKAB0WIQTzqfbMg3bSVACicfsbqBjbMygz5AUCakcEpwAKCRAbqBjbMygz
5E6GAf4rekU/3Y3oxsl7JBVuQK+tpylI76/nmDOSsOdch7tBPWgMl9JWJj2swNDs
yFOfNZi1SUe3UNRBiAoKwRcsdUwAAfsF3SX3DqhMd4kuKOdRu6tUzRDUScYiwgxs
lEtn9yTuY2QiY0pREDoe/NQq39bPGD7zV6QKG0zncatPEGOJmqeO
=dfkS
-----END PGP SIGNATURE-----
```
