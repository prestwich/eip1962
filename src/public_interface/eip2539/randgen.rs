use rand::{Rng};

use num_bigint::BigUint;
use num_traits::Num;
use crate::fp::Fp;
use crate::public_interface::decode_fp;

use crate::traits::{ZeroAndOne, FieldElement};
use crate::square_root::*;
use crate::public_interface::eip2539::*;

type Scalar = crate::integers::MaxGroupSizeUint;

type FpElement = crate::fp::Fp<'static, crate::field::U384Repr, crate::field::PrimeField<crate::field::U384Repr>>;
type Fp2Element = crate::extension_towers::fp2::Fp2<'static, crate::field::U384Repr, crate::field::PrimeField<crate::field::U384Repr>>;

type G1 = crate::weierstrass::curve::CurvePoint<'static, crate::weierstrass::CurveOverFpParameters<'static, crate::field::U384Repr, crate::field::PrimeField<crate::field::U384Repr>>>;
type G2 = crate::weierstrass::curve::CurvePoint<'static, crate::weierstrass::CurveOverFp2Parameters<'static, crate::field::U384Repr, crate::field::PrimeField<crate::field::U384Repr>>>;


pub fn make_random_fp_with_encoding<R: Rng>(rng: &mut R, modulus: &BigUint) -> (FpElement, Vec<u8>) {
    let mut buff = vec![0u8; 48*3];
    rng.fill_bytes(&mut buff);

    let num = BigUint::from_bytes_be(&buff);
    let num = num % modulus.clone();

    let x = Fp::from_be_bytes(&bls12_377::BLS12_377_FIELD, &num.to_bytes_be(), true).unwrap();

    let as_vec = decode_fp::serialize_fp_fixed_len(SERIALIZED_FP_BYTE_LENGTH, &x).unwrap();

    assert!(as_vec.len() == SERIALIZED_FP_BYTE_LENGTH);
    assert_eq!(&as_vec[..16], &[0u8; 16]);

    (x, as_vec)
}

pub fn make_invalid_encoding_fp<R: Rng>(rng: &mut R, modulus: &BigUint, use_overflow: bool) -> Vec<u8> {
    let mut buff = vec![0u8; 48*3];
    rng.fill_bytes(&mut buff);

    let num = BigUint::from_bytes_be(&buff);
    let mut num = num % modulus.clone();

    if use_overflow {
        num += modulus;
    }

    let as_be = num.to_bytes_be();
    let mut encoding = vec![0u8; 64 - as_be.len()]; 

    if !use_overflow {
        rng.fill_bytes(&mut encoding);
    }

    encoding.extend(as_be);

    encoding
}

pub fn make_random_fp2_with_encoding<R: Rng>(rng: &mut R, modulus: &BigUint) -> (Fp2Element, Vec<u8>) {
    let mut encoding = Vec::with_capacity(SERIALIZED_FP2_BYTE_LENGTH);

    let (c0, c0_encoding) = make_random_fp_with_encoding(rng, &modulus);
    let (c1, c1_encoding) = make_random_fp_with_encoding(rng, &modulus);

    encoding.extend(c0_encoding);
    encoding.extend(c1_encoding);

    assert!(encoding.len() == SERIALIZED_FP2_BYTE_LENGTH);

    let mut fe = bls12_377::BLS12_377_FP2_ZERO.clone();
    fe.c0 = c0;
    fe.c1 = c1;

    (fe, encoding)
}

pub fn make_invalid_encoding_fp2<R: Rng>(rng: &mut R, modulus: &BigUint, use_overflow: bool) -> Vec<u8> {
    let mut encoding = Vec::with_capacity(SERIALIZED_FP2_BYTE_LENGTH);
    encoding.extend(make_invalid_encoding_fp(rng, modulus, use_overflow));
    encoding.extend(make_invalid_encoding_fp(rng, modulus, use_overflow));

    encoding
}

pub fn encode_g1(point: &G1) -> Vec<u8> {
    let as_vec = decode_g1::serialize_g1_point(SERIALIZED_FP_BYTE_LENGTH, &point).unwrap();

    assert!(as_vec.len() == SERIALIZED_G1_POINT_BYTE_LENGTH);
    assert_eq!(&as_vec[..16], &[0u8; 16]);
    assert_eq!(&as_vec[64..80], &[0u8; 16]);

    as_vec
}

pub fn encode_g2(point: &G2) -> Vec<u8> {
    let as_vec = decode_g2::serialize_g2_point_in_fp2(SERIALIZED_FP_BYTE_LENGTH, &point).unwrap();

    assert!(as_vec.len() == SERIALIZED_G2_POINT_BYTE_LENGTH);

    as_vec
}

pub fn make_random_g1_with_encoding<R: Rng>(rng: &mut R) -> (G1, Vec<u8>) {
    let (scalar, _) = make_random_scalar_with_encoding(rng);

    let mut p = bls12_377::BLS12_377_G1_GENERATOR.mul(&scalar);
    p.normalize();
    let as_vec = encode_g1(&p);
    (p, as_vec)
}

pub fn make_random_g2_with_encoding<R: Rng>(rng: &mut R) -> (G2, Vec<u8>) {
    let (scalar, _) = make_random_scalar_with_encoding(rng);

    let mut p = bls12_377::BLS12_377_G2_GENERATOR.mul(&scalar);
    p.normalize();

    let as_vec = encode_g2(&p);

    (p, as_vec)
}

pub fn make_random_scalar_with_encoding<R: Rng>(rng: &mut R) -> (Scalar, Vec<u8>) {
    let mut buff = vec![0u8; SCALAR_BYTE_LENGTH];
    rng.fill_bytes(&mut buff);

    let (scalar, _) = decode_g1::decode_scalar_representation(&buff, SCALAR_BYTE_LENGTH).unwrap();

    (scalar, buff)
}

pub fn make_random_g1_and_negated_with_encoding<R: Rng>(rng: &mut R) -> ((G1, G1), (Vec<u8>, Vec<u8>)) {
    let (scalar, _) = make_random_scalar_with_encoding(rng);
    let p = bls12_377::BLS12_377_G1_GENERATOR.mul(&scalar);

    let mut minus_p = p.clone();
    minus_p.negate();

    let as_vec = decode_g1::serialize_g1_point(SERIALIZED_FP_BYTE_LENGTH, &p).unwrap();

    assert!(as_vec.len() == SERIALIZED_G1_POINT_BYTE_LENGTH);
    assert_eq!(&as_vec[..16], &[0u8; 16]);
    assert_eq!(&as_vec[64..80], &[0u8; 16]);

    let as_vec_negated = decode_g1::serialize_g1_point(SERIALIZED_FP_BYTE_LENGTH, &minus_p).unwrap();

    assert!(as_vec_negated.len() == SERIALIZED_G1_POINT_BYTE_LENGTH);
    assert_eq!(&as_vec_negated[..16], &[0u8; 16]);
    assert_eq!(&as_vec_negated[64..80], &[0u8; 16]);

    ((p, minus_p), (as_vec, as_vec_negated))
}

pub fn make_random_g2_and_negated_with_encoding<R: Rng>(rng: &mut R) -> ((G2, G2), (Vec<u8>, Vec<u8>)) {
    let (scalar, _) = make_random_scalar_with_encoding(rng);
    let p = bls12_377::BLS12_377_G2_GENERATOR.mul(&scalar);

    let mut minus_p = p.clone();
    minus_p.negate();

    let as_vec = decode_g2::serialize_g2_point_in_fp2(SERIALIZED_FP_BYTE_LENGTH, &p).unwrap();

    assert!(as_vec.len() == SERIALIZED_G2_POINT_BYTE_LENGTH);

    let as_vec_negated = decode_g2::serialize_g2_point_in_fp2(SERIALIZED_FP_BYTE_LENGTH, &minus_p).unwrap();

    assert!(as_vec_negated.len() == SERIALIZED_G2_POINT_BYTE_LENGTH);

    ((p, minus_p), (as_vec, as_vec_negated))
}

pub fn make_point_not_on_curve_g1(p: &mut G1) {
    let one = FpElement::one(&bls12_377::BLS12_377_FIELD);
    loop {
        p.y.add_assign(&one);

        if p.is_on_curve() == false {
            break;
        }
    }   
}

pub fn make_point_not_on_curve_g2(p: &mut G2) {
    let one = Fp2Element::one(&bls12_377::BLS12_377_EXTENSION_2_FIELD);
    loop {
        p.y.add_assign(&one);

        if p.is_on_curve() == false {
            break;
        }
    }   
}

pub fn make_g1_in_invalid_subgroup<R: Rng>(rng: &mut R) -> G1 {
    let modulus = BigUint::from_str_radix("258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177", 10).unwrap();
    let (fp, _) = make_random_fp_with_encoding(rng, &modulus);
    let one = FpElement::one(&bls12_377::BLS12_377_FIELD);

    let mut fp_candidate = fp;

    loop {
        let mut rhs = fp_candidate.clone();
        rhs.square();
        rhs.mul_assign(&fp_candidate);
        rhs.add_assign(&bls12_377::BLS12_377_B_FOR_G1);

        let leg = legendre_symbol_fp(&rhs);
        if leg == LegendreSymbol::QuadraticResidue {
            let y = sqrt_for_three_mod_four(&rhs).unwrap();
            let point = G1::point_from_xy(&bls12_377::BLS12_377_G1_CURVE, fp_candidate.clone(), y);

            if point.wnaf_mul_with_window_size(&bls12_377::BLS12_377_SUBGROUP_ORDER[..], 5).is_zero() == false {
                return point;
            }
        } else {
            fp_candidate.add_assign(&one);
        }
    }
}  

pub fn make_g2_in_invalid_subgroup<R: Rng>(rng: &mut R) -> G2 {
    let modulus = BigUint::from_str_radix("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787", 10).unwrap();
    let (fp, _) = make_random_fp2_with_encoding(rng, &modulus);
    let one = Fp2Element::one(&bls12_377::BLS12_377_EXTENSION_2_FIELD);

    let mut fp_candidate = fp;

    loop {
        let mut rhs = fp_candidate.clone();
        rhs.square();
        rhs.mul_assign(&fp_candidate);
        rhs.add_assign(&bls12_377::BLS12_377_B_FOR_G2);

        let leg = legendre_symbol_fp2(&rhs);
        if leg == LegendreSymbol::QuadraticResidue {
            let y = sqrt_for_three_mod_four_ext2(&rhs).unwrap();
            let point = G2::point_from_xy(&bls12_377::BLS12_377_G2_CURVE, fp_candidate.clone(), y);

            if point.wnaf_mul_with_window_size(&bls12_377::BLS12_377_SUBGROUP_ORDER[..], 5).is_zero() == false {
                return point;
            }
        } else {
            fp_candidate.add_assign(&one);
        }
    }
}  