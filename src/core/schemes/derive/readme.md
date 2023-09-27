## Procedural Macros for ThetaCrypt Schemes

This crate provides procedural macros that automate the implementation of elliptic curves and big integer wrappers. These wrappers provide an abstraction for the concrete underlying elliptic curve, such that schemes can be implemented in a curve-agnostic way. To reduce the amount of repeated code one has to write to add a new Miracl Core curve, this crate was created.

## Usage
To create ECP and big integer implementations for a new curve, simply add the `#[derive()]` flag with the right macro identifier.

    #[derive(AsnType, Debug, EcGroupImpl)]
    pub struct Curve {
        value: ECP
    }

    #[derive(AsnType, Debug, BigIntegerImpl)]
    pub struct BigInt {
        value: BIG
    }