use dep::std::println;

use crate::field::prime_field::PrimeField as Fp;

use crate::curve::swcurve::Point;
use crate::curve::fp12::Fp12;
use crate::curve::fp6::Fp6;
use crate::curve::fp2::Fp2;
use crate::curve::g2::G2Point;
use crate::curve::pairing;
use crate::curve;

fn verify_bls_signature(signature: G2Point, public_key: Point, message_hash: G2Point) {
    let g1: curve::BLS12_381 = curve::bls12_381();
    let lhs = pairing::pair(signature, g1.curve.gen);
    let rhs = pairing::pair(message_hash, public_key);
    assert(lhs.eq(rhs));
}
