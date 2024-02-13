use dep::std::println;
use crate::field::{BigUint56, NUM_LIMBS, BITS_PER_LIMB, MAX_BITS, MAX_BYTES, utils};

// Prime field element
struct PrimeField {
    val: BigUint56
}

// Represents a prime field element in Montgomery form
// Montgomery form is a representation of a field element `a` as
// `a.R mod p`, where `R = 2^{MAX_BITS}`.
impl PrimeField {
    ///////////////////////////////////////////////////////////////////////////
    // FIELD SPECIFIC CONSTANTS: BLS12-381
    ///////////////////////////////////////////////////////////////////////////

    // Prime field modulus
    // 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
    fn modulus() -> Self {
        let val = BigUint56 { limbs: [0xfeffffffffaaab, 0xfffeb153ffffb9, 0xa0f6b0f6241eab, 0xf38512bf6730d2, 0x4bacd764774b84, 0xe69a4b1ba7b643, 0x1a0111ea397f] };
        Self { val }    
    }

    // R = 2^{BITS_PER_LIMB*NUM_LIMBS} mod p
    //   = 2^392 mod p
    // hex(R) = 0x577a659fcfa012ca7c515d98f1297bb09b09b42da0f73e037669f83a2090c7212e00cde6d2002b119d800000347fcb8
    fn R() -> Self {
        let val = BigUint56 { limbs: [0xd800000347fcb8, 0x0cde6d2002b119, 0x83a2090c7212e0, 0xda0f73e037669f, 0x1297bb09b09b42, 0x012ca7c515d98f, 0x0577a659fcfa] };
        Self { val }
    }

    // R^2 mod p
    // hex(R**2) = 0xc8d4cc8a759fd5cd507320a75865d118c10ea725d74088b4f36a0093317d3b1d65aec45c53e243d626d1c34510370ed
    fn R2() -> Self {
        let val = BigUint56 { limbs: [0x6d1c34510370ed, 0xec45c53e243d62, 0x093317d3b1d65a, 0x5d74088b4f36a0, 0x865d118c10ea72, 0xfd5cd507320a75, 0x0c8d4cc8a759] };
        Self { val }
    }

    // INV = -p^{-1} mod 2^{BITS_PER_LIMB}
    //     = -p^{-1} mod 2^56
    // hex(P_INV) = 0xf3fffcfffcfffd
    fn P_INV() -> u56 {
        0xf3fffcfffcfffd
    }

    ///////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////

    // No montgomery mul here.
    pub fn from_raw_limbs(limbs: [u56; NUM_LIMBS]) -> Self {
        Self { val: BigUint56{ limbs } }
    }

    pub fn from_limbs(limbs: [u56; NUM_LIMBS]) -> Self {
        let tmp = Self { val: BigUint56{ limbs } };

        tmp.mul(PrimeField::R2())
    }

    pub fn from_u56(val: u56) -> Self {
        let tmp = Self { val: BigUint56::from_u56(val) };

        // Convert to Montgomery form by computing
        // (a.R^0 * R^2) / R = a.R
        tmp.mul(PrimeField::R2())
    }

    pub fn from_biguint56(val: BigUint56) -> Self {
        let tmp = Self { val };

        // Convert to Montgomery form by computing
        // (a.R^0 * R^2) / R = a.R
        tmp.mul(PrimeField::R2())
    }

    pub fn from_bytes(bytes: [u8]) -> Self {
        let tmp = Self { val: BigUint56::from_bytes(bytes) };

        // TODO: Do I need to check this?
        // Check that tmp < p
        let modulus = PrimeField::modulus();
        assert(tmp.val.lt(modulus.val));

        // Convert to Montgomery form by computing
        // (a.R^0 * R^2) / R = a.R
        tmp.mul(PrimeField::R2())
    }

    pub fn to_biguint56(self: Self) -> BigUint56 {
        // Turn into canonical form by computing
        // (a.R) / R = a
        let tmp = PrimeField::montgomery_reduce(self.val, BigUint56::zero());
        tmp.val
    }

    // Converts a field element into a byte representation in
    // little-endian byte order.
    pub fn to_bytes(self: Self) -> [u8; MAX_BYTES] {
        // Turn into canonical form by computing
        // (a.R) / R = a
        let tmp = PrimeField::montgomery_reduce(self.val, BigUint56::zero());
        tmp.val.to_bytes()
    }

    // Converts a field element into a bit representation
    pub fn to_bits(self: Self) -> [u1; MAX_BITS] {
        // Turn into canonical form by computing
        // (a.R) / R = a
        let tmp = PrimeField::montgomery_reduce(self.val, BigUint56::zero());
        tmp.val.to_bits()
    }

    // Returns zero, the additive identity.
    pub fn zero() -> Self {
        let val: BigUint56 = BigUint56::zero();
        Self { val }
    }

    // Returns one, the multiplicative identity.
    pub fn one() -> Self {
        PrimeField::R()
    }

    // Negates `self`.
    pub fn neg(self: Self) -> Self {
        if self.is_zero() {
            self
        } else {
            // Subtract `self` from `MODULUS` to negate
            let modulus = PrimeField::modulus().val;
            Self { val: modulus.sub(self.val) }
        }
    }

    // Adds `rhs` to `self`, returning the result.
    pub fn add(self: Self, rhs: Self) -> Self {
        let (sum, carry) = self.val.adc(rhs.val);

        let modulus = PrimeField::modulus().val;
        if ((carry == 0) & sum.lt(modulus)) {
            Self { val: sum }
        } else {
            Self { val: sum.sub(modulus) }
        }
    }

    // Subtracts `rhs` from `self`, returning the result.
    pub fn sub(self: Self, rhs: Self) -> Self {
        let (diff, borrow) = self.val.sbb(rhs.val);
        // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
        // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the modulus.
        if borrow == 0 {
            Self { val: diff }
        } else {
            let modulus = PrimeField::modulus().val;
            Self { val: diff.add(modulus) }
        }
    }

    // Doubles this field element.
    pub fn double(self: Self) -> Self {
        self.add(self)
    }

    // Multiplies `rhs` by `self`, returning the result.
    pub fn mul(self: Self, other: Self) -> Self {
        let (lo, hi) = self.val.mul(other.val);

        PrimeField::montgomery_reduce(lo, hi)
    }

    // Squares this element.
    // TODO: See if more efficient squaring is possible.
    pub fn square(self: Self) -> Self {
        self.mul(self)
    }

    fn montgomery_reduce(lo: BigUint56, hi: BigUint56) -> Self {
        let mut tmp = [0 as u56; 2*NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            tmp[i] = lo.limbs[i];
            tmp[i + NUM_LIMBS] = hi.limbs[i];
        }

        let modulus = PrimeField::modulus().val;

        let mut carry2 = 0;
        for i in 0..NUM_LIMBS {
            let k: u112 = tmp[i] as u112 * PrimeField::P_INV() as u112;
            let mut carry = 0;
            for j in 0..NUM_LIMBS {
                let (prod, c) = utils::mac(tmp[i + j], k as u56, modulus.limbs[j], carry);
                tmp[i + j] = prod;
                carry = c;
            }

            let (sum, c) = utils::adc(tmp[i + NUM_LIMBS], carry2, carry);
            tmp[i + NUM_LIMBS] = sum;
            carry2 = c;
        }

        let mut limbs = [0; NUM_LIMBS];
        for i in 0..NUM_LIMBS {
            limbs[i] = tmp[i + NUM_LIMBS];
        }

        let val = BigUint56{ limbs };
        if val.gte(modulus) {
            Self { val: val.sub(modulus) }
        } else {
            Self { val }
        }
    }

    // Exponentiates `self` by `by`.
    // Double-and-add algorithm
    pub fn pow(self: Self, by: BigUint56) -> Self {
        let mut res = PrimeField::one();
        for i in 0..NUM_LIMBS {
            for j in 0..BITS_PER_LIMB {
                res = res.square();
                
                if ((by.limbs[NUM_LIMBS - i - 1] >> ((BITS_PER_LIMB - j - 1) as u56)) & 1) == 1 {
                    res = res.mul(self);
                }
            }
        }
        res
    }

    unconstrained fn pow_unc(self: Self, by: BigUint56) -> Self {
        self.pow(by)
    }

    // Computes the multiplicative inverse of this element,
    // failing if the element is zero.
    pub fn invert(self: Self) -> Self {
        assert(!self.is_zero());

        let inv = self.pow_unc(PrimeField::modulus().val.sub(BigUint56{ limbs: [2, 0, 0, 0, 0, 0, 0] }));
        assert(self.mul(inv).eq(PrimeField::one()));

        inv
    }

    // Checks if the field element is zero.
    pub fn is_zero(self: Self) -> bool {
        self.val.is_zero()
    }

    // Checks if the field element is one.
    pub fn is_one(self: Self) -> bool {
        self.eq(PrimeField::one())
    }

    // Checks if self == other.
    pub fn eq(self: Self, other: Self) -> bool {
        self.val.eq(other.val)
    }

    // Print as bytes
    pub fn println(self: Self) {
        let bytes = self.to_bytes();
        println(bytes);
    }
}

#[test]
fn test1_to_bytes1() {
    let a = PrimeField::zero();
    assert(a.to_bytes() == [0 as u8; MAX_BYTES]);
}

#[test]
fn test1_to_bytes2() {
    let a = PrimeField::one();

    let mut bytes = [0 as u8; MAX_BYTES];
    bytes[0] = 1;
    assert(a.to_bytes() == bytes);
}

#[test]
fn test1_sub1() {
    let a = PrimeField::from_limbs([5, 0, 0, 0, 0, 0, 0]);
    let b = PrimeField::from_limbs([3, 0, 0, 0, 0, 0, 0]);

    let c = a.sub(b);
    assert(c.eq(PrimeField::from_limbs([2, 0, 0, 0, 0, 0, 0])));
}

#[test]
fn test1_sub2() {
    let a = PrimeField::one();
    let b = PrimeField::one().double();

    let c = a.sub(b);
    assert(c.eq(PrimeField::neg(PrimeField::one())));
}

#[test]
fn test1_sub3() {
    let a = PrimeField::one();
    let b = PrimeField::one();

    let c = a.sub(b);
    assert(c.eq(PrimeField::zero()));
}

#[test]
fn test1_sub4() {
    let a = PrimeField::zero();
    let b = PrimeField::zero();

    let c = a.sub(b);
    assert(c.eq(PrimeField::zero()));
}

#[test]
fn test1_add1() {
    let a = PrimeField::from_limbs([5, 0, 0, 0, 0, 0, 0]);
    let b = PrimeField::from_limbs([3, 0, 0, 0, 0, 0, 0]);

    let c = a.add(b);
    assert(c.eq(PrimeField::from_limbs([8, 0, 0, 0, 0, 0, 0])));
}

#[test]
fn test1_add2() {
    let a = PrimeField::neg(PrimeField::one());
    let b = PrimeField::one();

    let c = a.add(b);
    assert(c.eq(PrimeField::zero()));
}

#[test]
fn test1_add3() {
    let a = PrimeField::neg(PrimeField::one());
    let b = PrimeField::one().double();

    let c = a.add(b);
    assert(c.eq(PrimeField::one()));
}

#[test]
fn test1_add4() {
    let a = PrimeField::neg(PrimeField::one());
    let b = PrimeField::neg(PrimeField::one());

    let c = a.add(b);
    assert(c.eq(PrimeField::neg(PrimeField::one().double())));
}

#[test]
fn test1_double() {
    let a = PrimeField::from_limbs([3, 0, 0, 0, 0, 0, 0]);
    let c = a.double();
    assert(c.eq(PrimeField::from_limbs([6, 0, 0, 0, 0, 0, 0])));
}

#[test]
fn test1_mul1() {
    let a = PrimeField::from_bytes([2]);
    let b = PrimeField::from_bytes([3]);

    let c = a.mul(b);

    assert(c.eq(PrimeField::from_bytes([6])));
}

#[test]
fn test1_mul2() {
    // p - 1
    let a = PrimeField::neg(PrimeField::one());
    let b = PrimeField::from_bytes([2]);

    // 2*p - 2
    let c = a.mul(b);
    assert(c.eq(PrimeField::neg(PrimeField::from_bytes([2]))));
}

#[test]
fn test1_pow1() {
    let a = PrimeField::zero();
    let b = BigUint56::from_bytes([8]);

    let c = a.pow(b);
    assert(c.eq(PrimeField::zero()));
}

#[test]
fn test1_pow2() {
    let a = PrimeField::one();
    let b = BigUint56::from_bytes([8]);

    let c = a.pow(b);
    assert(c.eq(PrimeField::one()));
}

#[test]
fn test1_pow3() {
    let a = PrimeField::from_bytes([7]);
    let b = BigUint56::from_bytes([0]);

    let c = a.pow(b);
    assert(c.eq(PrimeField::one()));
}

#[test]
fn test1_pow4() {
    let a = PrimeField::from_bytes([7]);
    let b = BigUint56::from_bytes([1]);

    let c = a.pow(b);
    assert(c.eq(a));
}

#[test]
fn test1_pow5() {
    let a = PrimeField::from_bytes([7]);
    let b = BigUint56::from_bytes([2]);

    let c = a.pow(b);
    assert(c.eq(PrimeField::from_bytes([49])));
}

#[test]
fn test1_invert1() {
    let a = PrimeField::from_bytes([7]);
    let b = a.invert();

    let c = a.mul(b);
    assert(c.eq(PrimeField::one()));
}
