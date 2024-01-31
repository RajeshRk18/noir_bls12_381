This library is ported from Onurinanc's [BLS12_381 Field Ops](https://github.com/onurinanc/noir-bigint-bls12_381) and [BLS Signature Verification](https://github.com/onurinanc/noir-bls-signature) and merged into a single library after fixing some issues.


## Installation

Add this in your Nargo.toml
```rust
bls12_381 = { tag = "v0.1.0". git = "https://github.com/RajeshRk18/noir_bls12_381" }
```

## Testing

To run tests:

```
nargo test
```

## Acknowledgements
Onurinanc's [noir-bigint_bls12_381](https://github.com/onurinanc/noir-bigint-bls12_381), [noir-bls-sig](https://github.com/onurinanc/noir-bls-signature)

## Disclaimer
This is experimental software and is provided on an "as is" and "as available" basis. We do not give any warranties and will not be liable for any losses incurred through any use of this code base.