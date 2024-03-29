use dep::std::println;
use crate::field::prime_field::PrimeField as Fp;
use crate::curve::fp2::Fp2;

// Point representation for G2 in Affine Coordinates
struct G2Point {
    x: Fp2,
    y: Fp2,
    z: Fp2, // z = Fp2::zero() corresponds to point at infinity.
}

// Curve specification
struct G2Curve { // Short Weierstrass curve
    // Coefficients in defining equation y^2 = x^3 + ax + b
    a: Fp2,
    b: Fp2,
    // Generator as point in the affine coordinates
    gen: G2Point,
}

impl G2Point {
    pub fn from_affine(x: Fp2, y: Fp2) -> Self {
        Self {x: x, y: y, z: Fp2::one()}
    }

    // Additive identity
    pub fn zero() -> Self {
        Self {x: Fp2::zero(), y: Fp2::zero(), z:Fp2::zero()}
    }


    // Check for equality
    pub fn eq(self, p: G2Point) -> bool {
        let Self {x: x1, y: y1, z: z1} = self;
        let Self {x: x2, y: y2, z: z2} = p;

        let z1_is_zero = z1.is_zero();
        let z2_is_zero = z2.is_zero();

        if (!z1_is_zero & !z2_is_zero) {
            let z1sq = z1.square();
            let z2sq = z2.square();
            
            let z1cb = z1sq.mul(z1);
            let z2cb = z2sq.mul(z2);

            (x1.mul(z2sq).eq(x2.mul(z1sq))) & (y1.mul(z2cb).eq(y2.mul(z1cb)))
        } else {
            z1_is_zero & z2_is_zero

        }
    }

    //Check if zero
    pub fn is_zero(self) -> bool {
        let Self {x: _x, y: _y, z} = self;

        z.is_zero()
    }

    // Negation
    pub fn negate(self) -> Self {
        let Self {x, y, z} = self;

        Self { x, y: y.neg(), z }
    }
}

impl G2Curve {
    // Curve constructor
    pub fn new(a: Fp2, b: Fp2, gen: G2Point) -> G2Curve {
        let curve = G2Curve { a, b, gen };

        // gen should be on the curve
        assert(curve.contains(gen));

        curve
    }

    // Membership check
    pub fn contains(self, p: G2Point) -> bool {
        let G2Point {x, y, z} = p;
        
        let xx = x.square();
        let zz = z.square();
        let zzzz = zz.square();

        let lhs = y.square();
        let mut rhs = xx.mul(x).add(self.a.mul(x).mul(zzzz));
        rhs = rhs.add(self.b.mul(zzzz.mul(zz)));
        
        lhs.eq(rhs)
    }

    // Point addition
    pub fn add(self, p1: G2Point, p2: G2Point) -> G2Point {
        if p1.is_zero() {
            p2
        } else if p2.is_zero() {
            p1
        } else {
            let G2Point {x: x1, y: y1, z: z1} = p1;
            let G2Point {x: x2, y: y2, z: z2} = p2;
            
            let z1z1 = z1.square();
            let z2z2 = z2.square();
            
            let you1 = x1.mul(z2z2);
            let you2 = x2.mul(z1z1);
            
            let s1 = y1.mul(z2z2.mul(z2));
            let s2 = y2.mul(z1z1.mul(z1));
            
            if you1.eq(you2) {
                if !s1.eq(s2) {
                    G2Point::zero()
                } else {
                    self.double(p1)
                }
            } else {
                let h = you2.sub(you1);
                let r = s2.sub(s1);

                let hh = h.square();
                let hhh = hh.mul(h);
                let mut x3 = r.square().sub(hhh);
                x3 = x3.sub(you1.mul(hh).double());
                let mut y3 = r.mul(you1.mul(hh).sub(x3));
                y3 = y3.sub(s1.mul(hhh));
                let z3 = h.mul(z1).mul(z2);
                
                G2Point { x: x3, y: y3, z: z3 }
            }
        }
    }

    // Point subtraction
    pub fn sub(self, p1: G2Point, p2: G2Point) -> G2Point {
        self.add(p1, p2.negate())
    }

    // Point doubling
    pub fn double(self, p: G2Point) -> G2Point {
        let G2Point {x, y, z} = p;
        
        if p.is_zero() {
            p
        } else if y.is_zero() {
            G2Point::zero()
        } else {
            let xx = x.square();
            let yy = y.square();
            let yyyy = yy.square();
            
            let zzzz = z.square().square();

            let s = Fp2::new(Fp::from_u56(4), Fp::zero()).mul(x.mul(yy));
            let m = Fp2::new(Fp::from_u56(3), Fp::zero()).mul(xx).add(self.a.mul(zzzz));

            let x0 = m.square().sub(s.double());
            let y0 = m.mul(s.sub(x0)).sub(Fp2::new(Fp::from_u56(8), Fp::zero()).mul(yyyy));
            let z0 = y.mul(z).double();

            G2Point{ x: x0, y: y0, z: z0 }
        }
    }
 
    pub fn mul_Field(self, n: Field, p: G2Point) -> G2Point {
        let n_as_bits = n.to_le_bits(2);
        let mut out = G2Point::zero();

        for i in 0..2 {
            out = self.double(out);
            if n_as_bits[i] == 1 {
                out = self.add(out, p);
            }
        }

        out
    }
}
