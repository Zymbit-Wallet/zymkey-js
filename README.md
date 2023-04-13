This repository is a Node.js wrapper of Zymbit's C++ API, intended to facilitate interactions between Node.js applications and Zymbit's hardware wallet.

This is not an official Zymbit API, so it has not been robustly tested, and does not have a thorough documentation.

Here is the list of currently supported functions:

1. **getTime** - Retrieve the current time from the secure RTC (Real-Time Clock) module.
2. **exportPubKey** - Export the public key of a previously generated key pair.
3. **storeForeignPubKey** - Store a foreign public key on the device.
4. **genKeyPair** - Generate an asymmetric key pair (ECC or RSA) in the specified slot.
5. **genEphemeralKeyPair** - Generate an ephemeral asymmetric key pair (ECC or RSA) in a specified slot.
6. **removeKey** - Remove a key or key pair from the specified slot.
7. **invalidateEphemeralKey** - Invalidate an ephemeral key pair, making it unusable.
8. **genECDSASigFromDigest** - Generate an ECDSA signature for a given message digest using the specified private key.
9. **verifyECDSASigFromDigest** - Verify an ECDSA signature for a given message digest using the specified public key.
10. **genWalletMasterSeedWithBIP39** - Generate a hierarchical deterministic wallet master seed using the BIP39 mnemonic scheme.
11. **genWalletMasterSeedWithSLIP39** - Generate a hierarchical deterministic wallet master seed using the SLIP39 mnemonic scheme.
12. **setGenSLIP39GroupInfo** - Set the group information for generating SLIP39 mnemonics.
13. **addGenSLIP39Member** - Add a member to a group for generating SLIP39 mnemonics.
14. **cancelSLIP39Session** - Cancel an ongoing SLIP39 generation or restoration session.
15. **genOverSightWallet** - Generate an oversight wallet for monitoring and controlling wallet functions.
16. **genWalletChildKey** - Derive a child key from the wallet master seed using a specified derivation path.
17. **restoreWalletMasterSeedFromBIP39** - Restore a hierarchical deterministic wallet master seed from a BIP39 mnemonic.
18. **restoreWalletMasterSeedFromSLIP39** - Restore a hierarchical deterministic wallet master seed from a SLIP39 mnemonic.
19. **addRestoreSLIP39Mnemonic** - Add a mnemonic to the restoration session for SLIP39-based wallets.
20. **getWalletNodeAddrFromKeySlot** - Retrieve the wallet node address associated with a specific key slot.
21. **getWalletKeySlotFromNodeAddr** - Retrieve the key slot associated with a specific wallet node address.
22. **getAllocSlotsList** - Get a list of allocated key slots, showing their types and attributes.

In order to understand how to call these functions and the return values of each function, refer to [Zymbit's C++ Documentation](https://docs.zymbit.com/api/cpp_api/).