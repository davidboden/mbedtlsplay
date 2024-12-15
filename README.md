Demonstration of PSA layer implemented by mbedtls.

We'll generate an ECDSA 256 keypair on MacOS using openssl and then use the private key to sign `signme.txt`.

Then we'll run some C code using the mbedtls library to import the public key, read the message and validate the signature.

This is a prototype, to be ported onto the Nordic nfr5340 embedded target. It's easier to play with mbedtls on MacOS.

# Initial setup

Use conan to pull down mbedtls:
`conan install .`

This produces a presets file (probably `CMakeUserPresets.json`).

Tell VSCode (using menu options with Command-Shift-P) to use CMake and to use the "preset".
Change the VSCode C/C++ configuration provider.

Sometimes, VSCode needs a "reload window" to get these changes to kick in.

Look in `main.c` and change `SIGFILES_DIRECTORY` to reflect the absolute directory of `signme.txt`,
and where the keys and signatures that we're going to produce will live.

`brew install openssl` if you don't already have an up-to-date version of openssl.

# MacOS openssl commands

We can see the ECDSA curves supported on the Nordic nrf5430:
https://docs.nordicsemi.com/bundle/ps_nrf5340/page/cryptocell.html#cc_standards

The curves supported by openssl are listed using:
`openssl ecparam -list_curves`

We'll choose secp256r1, which has a 256-bit key. The 521-bit curve isn't working with the PSA library yet, even though
it's supported by the Cryptocell-312 on the ARM-M33 chip.

Generate a keypair and separate out the public key:
```
cd sigfiles
openssl ecparam -name secp256r1 -genkey -noout -out my256.key.pem
openssl ec -in my256.key.pem -pubout -out public256.pem
```

Sign an example file `signme.txt`, thereby producing `signature256.bin`:
```
openssl dgst -sign my256.key.pem -out signature256.bin signme.txt
```

Have a look inside `signature.bin` with:
```
openssl asn1parse -inform der -in signature256.bin
```

We can see that it's a DER formatted (ASN1) file with two 32-byte integer values. The PSA library just wants those keys
as a signature, as a 64-byte array.
We currently use an mbedtls utility in the C code to transform the DER structure into what the PSA library wants, but
we probably want to take care of that transformation when creating the signature.

Let's just verify the signature we've produced to make sure everything checks out:
```
openssl dgst -verify public256.pem -signature signature256.bin signme.txt
```

Let's also print out the hash of the original message, so that we can check later that it matches what's printed by the C program:
```
openssl dgst signme.txt
```

# C program to verify signature

The PSA layer doesn't (yet) have functions to conveniently read PEM-formatted keys from disk. This document tells us how to
use the existing mbedtls functions to read the keys and then convert them into PSA key structures:
https://github.com/Mbed-TLS/mbedtls/blob/development/docs/psa-transition.md

Run the code in `main.c` and see that the signature is validated by mbedtls.
