# simcrypt

Symmetric encryption library covering all JDK SunJCE + BouncyCastle symmetric ciphers (~300 configurations). Picks a random cipher per operation so there's no way to guess which algorithm was used.

## Dependency

```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk18on</artifactId>
    <version>1.79</version>
</dependency>
```

## Quickstart

```java
// Step 1 — generate your master key once and store it in env / secrets vault:
String masterKey = EncryptionService.generateMasterKey();

// Step 2 — use it:
Encryptor sc = new EncryptionService(System.getenv("ENCRYPTION_KEY"));

// Encrypt — picks a random strong cipher, embeds cipher metadata in the token
String token = sc.seal("my API key");

// Decrypt — fully self-contained, no need to track which cipher was used
String plain = sc.open(token);
```

## Advanced usage

```java
// Pick a cipher explicitly
CryptoKey key = EncryptionService.randomKey();        // any of ~400 ciphers
CryptoKey key = EncryptionService.randomStrongKey();  // AEAD / modern stream only

String enc = sc.encrypt("data", key);
String dec = sc.decrypt(enc, key);

// Seal with a specific cipher (both overloads available via Encryptor interface)
String token = sc.seal("data", key);

// Persist the cipher choice alongside the ciphertext (e.g. in a DB column)
String    serial   = key.serialize();
CryptoKey restored = CryptoKey.deserialize(serial);
```

## Key tiers

```java
EncryptionService.getAllCryptoKeys();  // all ~300 configurations
EncryptionService.getStrongKeys();    // AEAD + modern stream (recommended)
EncryptionService.getLegacyKeys();    // DES, RC2, ARCFOUR, TEA, GOST, ...

key.isAead()    // GCM, Poly1305, EAX, CCM, OCB
key.isStrong()  // AEAD + ChaCha20 / Salsa20 family
key.isLegacy()  // weak / deprecated ciphers
```

## Covered algorithms by family

**JDK — AES** : CBC, CTR, CTS, CFB, CFB8, OFB, OFB8, PCBC · keys 128/192/256

**JDK — AES-GCM** : tags 96/104/112/120/128 bits · keys 128/192/256

**JDK — Legacy** : Blowfish, DES, DESede, RC2, ARCFOUR

**JDK — Stream** : ChaCha20, ChaCha20-Poly1305

**BC — 128-bit block** : Twofish, Serpent, Camellia, CAST6, ARIA, SEED, SM4, RC6, Noekeon, DSTU7624/Kalyna

**BC — 64-bit block** : CAST5, IDEA, TEA, XTEA, SKIPJACK, GOST28147

	**BC — Stream** : HC-128, HC-256, Salsa20, XSalsa20, Grain-128

## Security note

`seal()` always picks from `getStrongKeys()` (AEAD only). `getLegacyKeys()` exists for interoperability with legacy systems — avoid it for new data.