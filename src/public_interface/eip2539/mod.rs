pub struct EIP2539Executor;

use crate::engines::bls12_377;
use crate::public_interface::ApiError;

pub const SCALAR_BYTE_LENGTH: usize = 32;

pub const SERIALIZED_FP_BYTE_LENGTH: usize = 64;
pub const SERIALIZED_G1_POINT_BYTE_LENGTH: usize = SERIALIZED_FP_BYTE_LENGTH * 2;

pub const SERIALIZED_FP2_BYTE_LENGTH: usize = SERIALIZED_FP_BYTE_LENGTH * 2;
pub const SERIALIZED_G2_POINT_BYTE_LENGTH: usize = SERIALIZED_FP2_BYTE_LENGTH * 2;

pub const SERIALIZED_PAIRING_RESULT_BYTE_LENGTH: usize = 32;

// use crate::public_interface::decode_fp;
use crate::public_interface::decode_g1;
use crate::public_interface::decode_g2;

use crate::weierstrass::Group;
use crate::multiexp::peppinger;
use crate::pairings::PairingEngine;

#[cfg(feature = "eip_2359_c_api")]
pub mod c_api;

#[cfg(any(feature = "randgen", test))]
pub mod randgen;

fn pairing_result_false() -> [u8; SERIALIZED_PAIRING_RESULT_BYTE_LENGTH] {
    [0u8; SERIALIZED_PAIRING_RESULT_BYTE_LENGTH]
}

fn pairing_result_true() -> [u8; SERIALIZED_PAIRING_RESULT_BYTE_LENGTH] {
    let mut res = [0u8; SERIALIZED_PAIRING_RESULT_BYTE_LENGTH];
    res[31] = 1u8;

    res
}

impl EIP2539Executor {
    pub fn g1_add<'a>(input: &'a [u8]) -> Result<[u8; SERIALIZED_G1_POINT_BYTE_LENGTH], ApiError> {
        if input.len() != SERIALIZED_G1_POINT_BYTE_LENGTH * 2 {
            return Err(ApiError::InputError("invalid input length for G1 addition".to_owned()));
        }

        let (mut p_0, rest) = decode_g1::decode_g1_point_from_xy_oversized(input, SERIALIZED_FP_BYTE_LENGTH, &bls12_377::BLS12_377_G1_CURVE)?;
        let (p_1, _) = decode_g1::decode_g1_point_from_xy_oversized(rest, SERIALIZED_FP_BYTE_LENGTH, &bls12_377::BLS12_377_G1_CURVE)?;

        if !p_0.is_on_curve() {
            if !crate::features::in_fuzzing_or_gas_metering() {
                return Err(ApiError::InputError(format!("Point 0 is not on curve, file {}, line {}", file!(), line!())));
            }
        }
        if !p_1.is_on_curve() {
            if !crate::features::in_fuzzing_or_gas_metering() {
                return Err(ApiError::InputError(format!("Point 1 is not on curve, file {}, line {}", file!(), line!())));
            }
        }

        p_0.add_assign(&p_1);

        let mut output = [0u8; SERIALIZED_G1_POINT_BYTE_LENGTH];

        let as_vec = decode_g1::serialize_g1_point(SERIALIZED_FP_BYTE_LENGTH, &p_0)?;

        output.copy_from_slice(&as_vec[..]);

        Ok(output)
    }

    pub fn g1_mul<'a>(input: &'a [u8]) -> Result<[u8; SERIALIZED_G1_POINT_BYTE_LENGTH], ApiError> {
        if input.len() != SERIALIZED_G1_POINT_BYTE_LENGTH + SCALAR_BYTE_LENGTH {
            return Err(ApiError::InputError("invalid input length for G1 multiplication".to_owned()));
        }

        let (p_0, rest) = decode_g1::decode_g1_point_from_xy_oversized(input, SERIALIZED_FP_BYTE_LENGTH, &bls12_377::BLS12_377_G1_CURVE)?;
        let (scalar, _) = decode_g1::decode_scalar_representation(rest, SCALAR_BYTE_LENGTH)?;

        if !p_0.is_on_curve() {
            if !crate::features::in_fuzzing_or_gas_metering() {
                return Err(ApiError::InputError(format!("Point is not on curve, file {}, line {}", file!(), line!())));
            }
        }

        let p = p_0.mul(&scalar);

        let mut output = [0u8; SERIALIZED_G1_POINT_BYTE_LENGTH];

        let as_vec = decode_g1::serialize_g1_point(SERIALIZED_FP_BYTE_LENGTH, &p)?;

        output.copy_from_slice(&as_vec[..]);

        Ok(output)
    }

    pub fn g1_multiexp<'a>(input: &'a [u8]) -> Result<[u8; SERIALIZED_G1_POINT_BYTE_LENGTH], ApiError> {
        if input.len() % (SERIALIZED_G1_POINT_BYTE_LENGTH + SCALAR_BYTE_LENGTH) != 0 {
            return Err(ApiError::InputError("invalid input length for G1 multiplication".to_owned()));
        }
        let num_pairs = input.len() / (SERIALIZED_G1_POINT_BYTE_LENGTH + SCALAR_BYTE_LENGTH);

        if num_pairs == 0 {
            return Err(ApiError::InputError("Invalid number of pairs".to_owned()));
        }

        let mut global_rest = input;
        let mut bases = Vec::with_capacity(num_pairs);
        let mut scalars = Vec::with_capacity(num_pairs);

        for _ in 0..num_pairs {
            let (p, local_rest) = decode_g1::decode_g1_point_from_xy_oversized(global_rest, SERIALIZED_FP_BYTE_LENGTH, &bls12_377::BLS12_377_G1_CURVE)?;
            let (scalar, local_rest) = decode_g1::decode_scalar_representation(local_rest, SCALAR_BYTE_LENGTH)?;
            if !p.is_on_curve() {
                if !crate::features::in_fuzzing_or_gas_metering() {
                    return Err(ApiError::InputError(format!("Point is not on curve, file {}, line {}", file!(), line!())));
                }
            }
            bases.push(p);
            scalars.push(scalar);
            global_rest = local_rest;
        }

        if bases.len() != scalars.len() || bases.len() == 0 {
            return Err(ApiError::InputError(format!("Multiexp with empty input pairs, file {}, line {}", file!(), line!())));
        } 

        let result = peppinger(&bases, scalars);

        let mut output = [0u8; SERIALIZED_G1_POINT_BYTE_LENGTH];

        let as_vec = decode_g1::serialize_g1_point(SERIALIZED_FP_BYTE_LENGTH, &result)?;

        output.copy_from_slice(&as_vec[..]);

        Ok(output)
    }

    pub fn g2_add<'a>(input: &'a [u8]) -> Result<[u8; SERIALIZED_G2_POINT_BYTE_LENGTH], ApiError> {
        if input.len() != SERIALIZED_G2_POINT_BYTE_LENGTH * 2 {
            return Err(ApiError::InputError("invalid input length for G2 addition".to_owned()));
        }

        let (mut p_0, rest) = decode_g2::decode_g2_point_from_xy_in_fp2_oversized(input, SERIALIZED_FP_BYTE_LENGTH, &bls12_377::BLS12_377_G2_CURVE)?;
        let (p_1, _) = decode_g2::decode_g2_point_from_xy_in_fp2_oversized(rest, SERIALIZED_FP_BYTE_LENGTH, &bls12_377::BLS12_377_G2_CURVE)?;

        if !p_0.is_on_curve() {
            if !crate::features::in_fuzzing_or_gas_metering() {
                return Err(ApiError::InputError(format!("Point 0 is not on curve, file {}, line {}", file!(), line!())));
            }
        }
        if !p_1.is_on_curve() {
            if !crate::features::in_fuzzing_or_gas_metering() {
                return Err(ApiError::InputError(format!("Point 1 is not on curve, file {}, line {}", file!(), line!())));
            }
        }

        p_0.add_assign(&p_1);

        let mut output = [0u8; SERIALIZED_G2_POINT_BYTE_LENGTH];

        let as_vec = decode_g2::serialize_g2_point_in_fp2(SERIALIZED_FP_BYTE_LENGTH, &p_0)?;

        output.copy_from_slice(&as_vec[..]);

        Ok(output)
    }

    pub fn g2_mul<'a>(input: &'a [u8]) -> Result<[u8; SERIALIZED_G2_POINT_BYTE_LENGTH], ApiError> {
        if input.len() != SERIALIZED_G2_POINT_BYTE_LENGTH + SCALAR_BYTE_LENGTH {
            return Err(ApiError::InputError("invalid input length for G1 multiplication".to_owned()));
        }

        let (p_0, rest) = decode_g2::decode_g2_point_from_xy_in_fp2_oversized(input, SERIALIZED_FP_BYTE_LENGTH, &bls12_377::BLS12_377_G2_CURVE)?;
        let (scalar, _) = decode_g1::decode_scalar_representation(rest, SCALAR_BYTE_LENGTH)?;

        if !p_0.is_on_curve() {
            if !crate::features::in_fuzzing_or_gas_metering() {
                return Err(ApiError::InputError(format!("Point is not on curve, file {}, line {}", file!(), line!())));
            }
        }

        let p = p_0.mul(&scalar);

        let mut output = [0u8; SERIALIZED_G2_POINT_BYTE_LENGTH];

        let as_vec = decode_g2::serialize_g2_point_in_fp2(SERIALIZED_FP_BYTE_LENGTH, &p)?;

        output.copy_from_slice(&as_vec[..]);

        Ok(output)
    }

    pub fn g2_multiexp<'a>(input: &'a [u8]) -> Result<[u8; SERIALIZED_G2_POINT_BYTE_LENGTH], ApiError> {
        if input.len() % (SERIALIZED_G2_POINT_BYTE_LENGTH + SCALAR_BYTE_LENGTH) != 0 {
            return Err(ApiError::InputError("invalid input length for G1 multiplication".to_owned()));
        }
        let num_pairs = input.len() / (SERIALIZED_G2_POINT_BYTE_LENGTH + SCALAR_BYTE_LENGTH);

        if num_pairs == 0 {
            return Err(ApiError::InputError("Invalid number of pairs".to_owned()));
        }

        let mut global_rest = input;
        let mut bases = Vec::with_capacity(num_pairs);
        let mut scalars = Vec::with_capacity(num_pairs);

        for _ in 0..num_pairs {
            let (p, local_rest) = decode_g2::decode_g2_point_from_xy_in_fp2_oversized(global_rest, SERIALIZED_FP_BYTE_LENGTH, &bls12_377::BLS12_377_G2_CURVE)?;
            let (scalar, local_rest) = decode_g1::decode_scalar_representation(local_rest, SCALAR_BYTE_LENGTH)?;
            if !p.is_on_curve() {
                if !crate::features::in_fuzzing_or_gas_metering() {
                    return Err(ApiError::InputError(format!("Point is not on curve, file {}, line {}", file!(), line!())));
                }
            }
            bases.push(p);
            scalars.push(scalar);
            global_rest = local_rest;
        }

        if bases.len() != scalars.len() || bases.len() == 0 {
            return Err(ApiError::InputError(format!("Multiexp with empty input pairs, file {}, line {}", file!(), line!())));
        } 

        let result = peppinger(&bases, scalars);

        let mut output = [0u8; SERIALIZED_G2_POINT_BYTE_LENGTH];

        let as_vec = decode_g2::serialize_g2_point_in_fp2(SERIALIZED_FP_BYTE_LENGTH, &result)?;

        output.copy_from_slice(&as_vec[..]);

        Ok(output)
    }

    pub fn pair<'a>(input: &'a [u8]) -> Result<[u8; SERIALIZED_PAIRING_RESULT_BYTE_LENGTH], ApiError> {
        if input.len() % (SERIALIZED_G2_POINT_BYTE_LENGTH + SERIALIZED_G1_POINT_BYTE_LENGTH) != 0 {
            return Err(ApiError::InputError("invalid input length for pairing".to_owned()));
        }
        let num_pairs = input.len() / (SERIALIZED_G2_POINT_BYTE_LENGTH + SERIALIZED_G1_POINT_BYTE_LENGTH);

        if num_pairs == 0 {
            return Err(ApiError::InputError("Invalid number of pairs".to_owned()));
        }

        let mut global_rest = input;

        let mut g1_points = Vec::with_capacity(num_pairs);
        let mut g2_points = Vec::with_capacity(num_pairs);

        for _ in 0..num_pairs {
            let (g1, rest) = decode_g1::decode_g1_point_from_xy_oversized(global_rest, SERIALIZED_FP_BYTE_LENGTH, &bls12_377::BLS12_377_G1_CURVE)?;
            let (g2, rest) = decode_g2::decode_g2_point_from_xy_in_fp2_oversized(rest, SERIALIZED_FP_BYTE_LENGTH, &bls12_377::BLS12_377_G2_CURVE)?;

            global_rest = rest;

            if !g1.is_on_curve() {
                if !crate::features::in_fuzzing_or_gas_metering() {
                    return Err(ApiError::InputError("G1 point is not on curve".to_owned()));
                }
            }

            if !g2.is_on_curve() {
                if !crate::features::in_fuzzing_or_gas_metering() {
                    return Err(ApiError::InputError("G2 point is not on curve".to_owned()));
                }
            }
            // "fast" subgroup checks using empirical data
            if g1.wnaf_mul_with_window_size(&bls12_377::BLS12_377_SUBGROUP_ORDER[..], 5).is_zero() == false {
                if !crate::features::in_fuzzing_or_gas_metering() {
                    return Err(ApiError::InputError("G1 point is not in the expected subgroup".to_owned()));
                }
            }

            if g2.wnaf_mul_with_window_size(&bls12_377::BLS12_377_SUBGROUP_ORDER[..], 5).is_zero() == false {
                if !crate::features::in_fuzzing_or_gas_metering() {
                    return Err(ApiError::InputError("G2 point is not in the expected subgroup".to_owned()));
                }
            }

            if !g1.is_zero() && !g2.is_zero() {
                g1_points.push(g1);
                g2_points.push(g2);
            }
        }

        debug_assert!(g1_points.len() == g2_points.len());

        if g1_points.len() == 0 {
            return Ok(pairing_result_true());
        }

        let engine = &bls12_377::BLS12_377_PAIRING_ENGINE;

        let pairing_result = engine.pair(&g1_points, &g2_points);

        if pairing_result.is_none() {
            return Err(ApiError::UnknownParameter("Pairing engine returned no value".to_owned()));
        }

        use crate::extension_towers::fp12_as_2_over3_over_2::Fp12;
        use crate::traits::ZeroAndOne;

        let one_fp12 = Fp12::one(&bls12_377::BLS12_377_EXTENSION_12_FIELD);
        let pairing_result = pairing_result.unwrap();
        let result = if pairing_result == one_fp12 {
            pairing_result_true()
        } else {
            pairing_result_false()
        };

        Ok(result)
    }

    // pub fn map_fp_to_g1<'a>(input: &'a [u8]) -> Result<[u8; SERIALIZED_G1_POINT_BYTE_LENGTH], ApiError> {
    //     if input.len() != SERIALIZED_FP_BYTE_LENGTH {
    //         return Err(ApiError::InputError("invalid input length for Fp to G1 to curve mapping".to_owned()));
    //     }
    //     let (fe, _) = decode_fp::decode_fp_oversized(input, SERIALIZED_FP_BYTE_LENGTH, &bls12_377::BLS12_377_FIELD)?;
    //     let point = mapping::fp_to_g1(&fe)?;

    //     let mut output = [0u8; SERIALIZED_G1_POINT_BYTE_LENGTH];
    //     let as_vec = decode_g1::serialize_g1_point(SERIALIZED_FP_BYTE_LENGTH, &point)?;

    //     output.copy_from_slice(&as_vec[..]);

    //     Ok(output)
    // }

    // pub fn map_fp2_to_g2<'a>(input: &'a [u8]) -> Result<[u8; SERIALIZED_G2_POINT_BYTE_LENGTH], ApiError> {
    //     if input.len() != SERIALIZED_FP2_BYTE_LENGTH {
    //         return Err(ApiError::InputError("invalid input length for Fp2 to G2 to curve mapping".to_owned()));
    //     }
    //     let (fe, _) = decode_fp::decode_fp2_oversized(input, SERIALIZED_FP_BYTE_LENGTH, &bls12_377::BLS12_377_EXTENSION_2_FIELD)?;
    //     let point = mapping::fp2_to_g2(&fe)?;

    //     let mut output = [0u8; SERIALIZED_G2_POINT_BYTE_LENGTH];
    //     let as_vec = decode_g2::serialize_g2_point_in_fp2(SERIALIZED_FP_BYTE_LENGTH, &point)?;

    //     output.copy_from_slice(&as_vec[..]);

    //     Ok(output)
    // }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{Rng};
    use rand::{SeedableRng};
    use rand_xorshift::XorShiftRng;

    use indicatif::{ProgressBar, ProgressStyle};

    use csv::Writer;
    use hex;

    use num_bigint::BigUint;
    use num_traits::Num;
    use crate::fp::Fp;
    use crate::public_interface::{decode_fp, eip2539::randgen::*};

    use crate::traits::{ZeroAndOne, FieldElement};
    use crate::square_root::*;

    type Scalar = crate::integers::MaxGroupSizeUint;

    type FpElement = crate::fp::Fp<'static, crate::field::U384Repr, crate::field::PrimeField<crate::field::U384Repr>>;
    type Fp2Element = crate::extension_towers::fp2::Fp2<'static, crate::field::U384Repr, crate::field::PrimeField<crate::field::U384Repr>>;

    type G1 = crate::weierstrass::curve::CurvePoint<'static, crate::weierstrass::CurveOverFpParameters<'static, crate::field::U384Repr, crate::field::PrimeField<crate::field::U384Repr>>>;
    type G2 = crate::weierstrass::curve::CurvePoint<'static, crate::weierstrass::CurveOverFp2Parameters<'static, crate::field::U384Repr, crate::field::PrimeField<crate::field::U384Repr>>>;

    fn make_csv_writer(path: &str) -> Option<Writer<std::fs::File>> {
        if WRITE_VECTORS {
            let mut writer = Writer::from_path(path).expect("must open a test file");
            writer.write_record(&["input", "result"]).expect("must write header");

            Some(writer)
        } else {
            None
        }
    }

    const NUM_TESTS: usize = 100;
    const MULTIEXP_INPUT: usize = 16;
    const WRITE_VECTORS: bool = true;

    #[test]
    fn test_g1_add() {
        let mut rng = XorShiftRng::from_seed([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        let pb = ProgressBar::new(1u64);

        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}|{eta_precise}] {bar:50} {pos:>7}/{len:7} {msg}")
            .progress_chars("##-"));

        pb.set_length(NUM_TESTS as u64);

        let mut writer = make_csv_writer("src/test/test_vectors/eip2539/g1_add.csv");

        for _ in 0..NUM_TESTS {
            let mut encoding = Vec::with_capacity(SERIALIZED_G1_POINT_BYTE_LENGTH * 2);

            let (mut p0, e) = make_random_g1_with_encoding(&mut rng);
            encoding.extend(e);

            let (p1, e) = make_random_g1_with_encoding(&mut rng);
            encoding.extend(e);

            p0.add_assign(&p1);

            let expected = decode_g1::serialize_g1_point(SERIALIZED_FP_BYTE_LENGTH, &p0).unwrap();
            assert!(expected.len() == SERIALIZED_G1_POINT_BYTE_LENGTH);

            let api_result = EIP2539Executor::g1_add(&encoding).unwrap();

            assert_eq!(&expected[..], &api_result[..]);

            if let Some(writer) = writer.as_mut() {
                writer.write_record(
                    &[
                        &hex::encode(&encoding[..]), 
                        &hex::encode(&api_result[..])
                    ],
                ).expect("must write a test vector");
            }

            pb.inc(1);
        }

        pb.finish_with_message("Completed");
    }

    #[test]
    fn test_g1_point_mul() {
        let mut rng = XorShiftRng::from_seed([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        let pb = ProgressBar::new(1u64);

        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}|{eta_precise}] {bar:50} {pos:>7}/{len:7} {msg}")
            .progress_chars("##-"));

        pb.set_length(NUM_TESTS as u64);

        let mut writer = make_csv_writer("src/test/test_vectors/eip2539/g1_mul.csv");

        for _ in 0..NUM_TESTS {
            let mut encoding = Vec::with_capacity(SERIALIZED_G1_POINT_BYTE_LENGTH + SCALAR_BYTE_LENGTH);

            let (p0, e) = make_random_g1_with_encoding(&mut rng);
            encoding.extend(e);

            let (scalar, e) = make_random_scalar_with_encoding(&mut rng);
            encoding.extend(e);

            let p = p0.mul(&scalar);

            let expected = decode_g1::serialize_g1_point(SERIALIZED_FP_BYTE_LENGTH, &p).unwrap();
            assert!(expected.len() == SERIALIZED_G1_POINT_BYTE_LENGTH);

            let api_result = EIP2539Executor::g1_mul(&encoding).unwrap();

            assert_eq!(&expected[..], &api_result[..]);

            if let Some(writer) = writer.as_mut() {
                writer.write_record(
                    &[
                        &hex::encode(&encoding[..]), 
                        &hex::encode(&api_result[..])
                    ],
                ).expect("must write a test vector");
            }

            pb.inc(1);
        }

        pb.finish_with_message("Completed");
    }

    #[test]
    fn test_g1_multiexp() {
        let mut rng = XorShiftRng::from_seed([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        let pb = ProgressBar::new(1u64);

        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}|{eta_precise}] {bar:50} {pos:>7}/{len:7} {msg}")
            .progress_chars("##-"));

        pb.set_length(NUM_TESTS as u64);

        let mut writer = make_csv_writer("src/test/test_vectors/eip2539/g1_multiexp.csv");

        for _ in 0..NUM_TESTS {
            let mut encoding = Vec::with_capacity((SERIALIZED_G1_POINT_BYTE_LENGTH + SCALAR_BYTE_LENGTH) * MULTIEXP_INPUT);
            let mut points = Vec::with_capacity(MULTIEXP_INPUT);
            let mut scalars = Vec::with_capacity(MULTIEXP_INPUT);
            for _ in 0..MULTIEXP_INPUT {
                let (p0, e) = make_random_g1_with_encoding(&mut rng);
                encoding.extend(e);

                let (scalar, e) = make_random_scalar_with_encoding(&mut rng);
                encoding.extend(e);

                points.push(p0);
                scalars.push(scalar);
            }

            let p = peppinger(&points, scalars);

            let expected = decode_g1::serialize_g1_point(SERIALIZED_FP_BYTE_LENGTH, &p).unwrap();
            assert!(expected.len() == SERIALIZED_G1_POINT_BYTE_LENGTH);

            let api_result = EIP2539Executor::g1_multiexp(&encoding).unwrap();

            assert_eq!(&expected[..], &api_result[..]);

            if let Some(writer) = writer.as_mut() {
                writer.write_record(
                    &[
                        &hex::encode(&encoding[..]), 
                        &hex::encode(&api_result[..])
                    ],
                ).expect("must write a test vector");
            }

            pb.inc(1);
        }

        pb.finish_with_message("Completed");
    }

    #[test]
    fn test_g2_add() {
        let mut rng = XorShiftRng::from_seed([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        let pb = ProgressBar::new(1u64);

        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}|{eta_precise}] {bar:50} {pos:>7}/{len:7} {msg}")
            .progress_chars("##-"));

        pb.set_length(NUM_TESTS as u64);

        let mut writer = make_csv_writer("src/test/test_vectors/eip2539/g2_add.csv");

        for _ in 0..NUM_TESTS {
            let mut encoding = Vec::with_capacity(SERIALIZED_G2_POINT_BYTE_LENGTH * 2);

            let (mut p0, e) = make_random_g2_with_encoding(&mut rng);
            encoding.extend(e);

            let (p1, e) = make_random_g2_with_encoding(&mut rng);
            encoding.extend(e);

            p0.add_assign(&p1);

            let expected = decode_g2::serialize_g2_point_in_fp2(SERIALIZED_FP_BYTE_LENGTH, &p0).unwrap();
            assert!(expected.len() == SERIALIZED_G2_POINT_BYTE_LENGTH);

            let api_result = EIP2539Executor::g2_add(&encoding).unwrap();

            assert_eq!(&expected[..], &api_result[..]);

            if let Some(writer) = writer.as_mut() {
                writer.write_record(
                    &[
                        &hex::encode(&encoding[..]), 
                        &hex::encode(&api_result[..])
                    ],
                ).expect("must write a test vector");
            }

            pb.inc(1);
        }

        pb.finish_with_message("Completed");
    }

    #[test]
    fn test_g2_point_mul() {
        let mut rng = XorShiftRng::from_seed([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        let pb = ProgressBar::new(1u64);

        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}|{eta_precise}] {bar:50} {pos:>7}/{len:7} {msg}")
            .progress_chars("##-"));

        pb.set_length(NUM_TESTS as u64);

        let mut writer = make_csv_writer("src/test/test_vectors/eip2539/g2_mul.csv");

        for _ in 0..NUM_TESTS {
            let mut encoding = Vec::with_capacity(SERIALIZED_G2_POINT_BYTE_LENGTH + SCALAR_BYTE_LENGTH);

            let (p0, e) = make_random_g2_with_encoding(&mut rng);
            encoding.extend(e);

            let (scalar, e) = make_random_scalar_with_encoding(&mut rng);
            encoding.extend(e);

            let p = p0.mul(&scalar);

            let expected = decode_g2::serialize_g2_point_in_fp2(SERIALIZED_FP_BYTE_LENGTH, &p).unwrap();
            assert!(expected.len() == SERIALIZED_G2_POINT_BYTE_LENGTH);

            let api_result = EIP2539Executor::g2_mul(&encoding).unwrap();

            assert_eq!(&expected[..], &api_result[..]);

            if let Some(writer) = writer.as_mut() {
                writer.write_record(
                    &[
                        &hex::encode(&encoding[..]), 
                        &hex::encode(&api_result[..])
                    ],
                ).expect("must write a test vector");
            }

            pb.inc(1);
        }

        pb.finish_with_message("Completed");
    }

    #[test]
    fn test_g2_multiexp() {
        let mut rng = XorShiftRng::from_seed([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        let pb = ProgressBar::new(1u64);

        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}|{eta_precise}] {bar:50} {pos:>7}/{len:7} {msg}")
            .progress_chars("##-"));

        pb.set_length(NUM_TESTS as u64);

        let mut writer = make_csv_writer("src/test/test_vectors/eip2539/g2_multiexp.csv");

        for _ in 0..NUM_TESTS {
            let mut encoding = Vec::with_capacity((SERIALIZED_G2_POINT_BYTE_LENGTH + SCALAR_BYTE_LENGTH) * MULTIEXP_INPUT);
            let mut points = Vec::with_capacity(MULTIEXP_INPUT);
            let mut scalars = Vec::with_capacity(MULTIEXP_INPUT);
            for _ in 0..MULTIEXP_INPUT {
                let (p0, e) = make_random_g2_with_encoding(&mut rng);
                encoding.extend(e);

                let (scalar, e) = make_random_scalar_with_encoding(&mut rng);
                encoding.extend(e);

                points.push(p0);
                scalars.push(scalar);
            }

            let p = peppinger(&points, scalars);

            let expected = decode_g2::serialize_g2_point_in_fp2(SERIALIZED_FP_BYTE_LENGTH, &p).unwrap();
            assert!(expected.len() == SERIALIZED_G2_POINT_BYTE_LENGTH);

            let api_result = EIP2539Executor::g2_multiexp(&encoding).unwrap();

            assert_eq!(&expected[..], &api_result[..]);

            if let Some(writer) = writer.as_mut() {
                writer.write_record(
                    &[
                        &hex::encode(&encoding[..]), 
                        &hex::encode(&api_result[..])
                    ],
                ).expect("must write a test vector");
            }

            pb.inc(1);
        }

        pb.finish_with_message("Completed");
    }

    #[test]
    fn generate_pairing_vectors() {
        let mut rng = XorShiftRng::from_seed([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        let pb = ProgressBar::new(1u64);

        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}|{eta_precise}] {bar:50} {pos:>7}/{len:7} {msg}")
            .progress_chars("##-"));

        pb.set_length(NUM_TESTS as u64);

        let mut writer = make_csv_writer("src/test/test_vectors/eip2539/pairing.csv");
        assert!(writer.is_some());

        let num_pairs = vec![1, 2, 3, 4, 5, 8];
        let len = num_pairs.len();

        for pairs in num_pairs.into_iter() {
            for _ in 0..(NUM_TESTS/len) {
                let (_, (g1_enc, minus_g1_enc)) = make_random_g1_and_negated_with_encoding(&mut rng);
                let (_, (g2_enc, minus_g2_enc)) = make_random_g2_and_negated_with_encoding(&mut rng);

                let mut input = vec![];
                let expect_identity = pairs % 2 == 0;
                for i in 0..pairs {
                    if i & 3 == 0 {
                        input.extend(g1_enc.clone());
                        input.extend(g2_enc.clone());
                    } else if i & 3 == 1 {
                        input.extend(minus_g1_enc.clone());
                        input.extend(g2_enc.clone());
                    } else if i & 3 == 2 {
                        input.extend(g1_enc.clone());
                        input.extend(minus_g2_enc.clone());
                    } else {
                        input.extend(minus_g1_enc.clone());
                        input.extend(minus_g2_enc.clone());
                    }
                }

                let api_result = EIP2539Executor::pair(&input).unwrap();
                assert!(api_result.len() == SERIALIZED_PAIRING_RESULT_BYTE_LENGTH);

                if expect_identity {
                    assert!(api_result[31] == 1u8);
                }

                if let Some(writer) = writer.as_mut() {
                    writer.write_record(
                        &[
                            &hex::encode(&input[..]), 
                            &hex::encode(&api_result[..])
                        ],
                    ).expect("must write a test vector");
                }

                pb.inc(1);
            }
        }

        pb.finish_with_message("Completed");
    }

    #[test]
    fn generate_negative_test_pairing_invalid_subgroup() {
        let mut rng = XorShiftRng::from_seed([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        let pb = ProgressBar::new(1u64);

        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}|{eta_precise}] {bar:50} {pos:>7}/{len:7} {msg}")
            .progress_chars("##-"));

        pb.set_length(NUM_TESTS as u64);

        let mut writer = make_csv_writer("src/test/test_vectors/eip2539/negative/invalid_subgroup_for_pairing.csv");
        assert!(writer.is_some());

        for j in 0..NUM_TESTS {
            let (_, (g1_enc, _)) = make_random_g1_and_negated_with_encoding(&mut rng);
            let (_, (g2_enc, _)) = make_random_g2_and_negated_with_encoding(&mut rng);

            let invalid_g1 = make_g1_in_invalid_subgroup(&mut rng);
            let invalid_g2 = make_g2_in_invalid_subgroup(&mut rng);

            let invalid_g1_encoding = encode_g1(&invalid_g1);
            let invalid_g2_encoding = encode_g2(&invalid_g2);

            let mut input = vec![];
            if j & 1 == 0 {
                input.extend(invalid_g1_encoding.clone());
                input.extend(g2_enc.clone());
                input.extend(g1_enc.clone());
                input.extend(g2_enc.clone());
            } else {
                input.extend(g1_enc.clone());
                input.extend(invalid_g2_encoding.clone());
                input.extend(g1_enc.clone());
                input.extend(g2_enc.clone());
            }

            let api_result = EIP2539Executor::pair(&input);
            assert!(api_result.is_err());
            let description = api_result.err().unwrap().to_string();

            if let Some(writer) = writer.as_mut() {
                writer.write_record(
                    &[
                        &hex::encode(&input[..]), 
                        &description
                    ],
                ).expect("must write a test vector");
            }

            pb.inc(1);
        }

        pb.finish_with_message("Completed");
    }

    #[test]
    fn test_not_on_curve_g1() {
        let mut rng = XorShiftRng::from_seed([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        let pb = ProgressBar::new(1u64);

        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}|{eta_precise}] {bar:50} {pos:>7}/{len:7} {msg}")
            .progress_chars("##-"));

        pb.set_length(NUM_TESTS as u64);

        let mut writer = make_csv_writer("src/test/test_vectors/eip2539/negative/g1_not_on_curve.csv");

        for _ in 0..NUM_TESTS {
            let mut encoding = Vec::with_capacity(SERIALIZED_G1_POINT_BYTE_LENGTH + SCALAR_BYTE_LENGTH);

            let (mut p0, _) = make_random_g1_with_encoding(&mut rng);
            make_point_not_on_curve_g1(&mut p0);
            encoding.extend(encode_g1(&p0));

            let (_, e) = make_random_scalar_with_encoding(&mut rng);
            encoding.extend(e);

            let api_result = EIP2539Executor::g1_mul(&encoding).err().unwrap().to_string();

            if let Some(writer) = writer.as_mut() {
                writer.write_record(
                    &[
                        &hex::encode(&encoding[..]), 
                        &api_result
                    ],
                ).expect("must write a test vector");
            }

            pb.inc(1);
        }

        pb.finish_with_message("Completed");
    }

    #[test]
    fn test_not_on_curve_g2() {
        let mut rng = XorShiftRng::from_seed([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        let pb = ProgressBar::new(1u64);

        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}|{eta_precise}] {bar:50} {pos:>7}/{len:7} {msg}")
            .progress_chars("##-"));

        pb.set_length(NUM_TESTS as u64);

        let mut writer = make_csv_writer("src/test/test_vectors/eip2539/negative/g2_not_on_curve.csv");

        for _ in 0..NUM_TESTS {
            let mut encoding = Vec::with_capacity(SERIALIZED_G2_POINT_BYTE_LENGTH + SCALAR_BYTE_LENGTH);

            let (mut p0, _) = make_random_g2_with_encoding(&mut rng);
            make_point_not_on_curve_g2(&mut p0);
            encoding.extend(encode_g2(&p0));

            let (_, e) = make_random_scalar_with_encoding(&mut rng);
            encoding.extend(e);

            let api_result = EIP2539Executor::g2_mul(&encoding).err().unwrap().to_string();

            if let Some(writer) = writer.as_mut() {
                writer.write_record(
                    &[
                        &hex::encode(&encoding[..]), 
                        &api_result
                    ],
                ).expect("must write a test vector");
            }

            pb.inc(1);
        }

        pb.finish_with_message("Completed");
    }

    #[test]
    fn dump_vectors_into_fuzzing_corpus() {
        let byte_idx: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let file_paths = vec![
            "g1_add.csv",
            "g1_mul.csv",
            "g1_multiexp.csv",
            "g2_add.csv",
            "g2_mul.csv",
            "g2_multiexp.csv",
            "pairing.csv",
        ];

        let mut counter = 0;

        for (b, f) in byte_idx.into_iter().zip(file_paths.into_iter()) {
            let mut reader = csv::Reader::from_path(&format!("src/test/test_vectors/eip2539/{}", f)).expect(&format!("failed to open {}", f));
            for r in reader.records() {
                let r = r.unwrap();
                let input = hex::decode(r.get(0).unwrap()).unwrap();
                let mut output = vec![b];
                output.extend(input);
                let name = format!("vector_{}", counter);
                std::fs::write(&format!("src/test/test_vectors/eip2539/fuzzing/{}", name), &output).unwrap();

                counter += 1;
            }
        }
    }

    fn run_on_test_inputs<F: Fn(&[u8]) -> Result<Vec<u8>, ApiError>>(
        file_path: &str,
        expect_success: bool,
        test_function: F 
    ) -> bool {
        let mut reader = csv::Reader::from_path(file_path).expect(&format!("failed to open {}", file_path));
        for r in reader.records() {
            let r = r.unwrap();
            let input_str = r.get(0).unwrap();
            let input = hex::decode(input_str).unwrap();
            let expected_output = if let Some(s) = r.get(1) {
                hex::decode(s).unwrap()
            } else {
                vec![]
            };

            let value = test_function(&input);
            match value {
                Ok(result) => {
                    if expected_output != result {
                        return false;
                    }
                },
                Err(..) => {
                    if expect_success == true {
                        return false;
                    }
                }
            }
        }

        true
    }

    #[test]
    fn run_g1_add_on_vector() {
        let p = "src/test/test_vectors/eip2539/g1_add.csv";
        
        let f = |input: &[u8]| EIP2539Executor::g1_add(input).map(|r| r.to_vec());

        let success = run_on_test_inputs(p, true, f);

        assert!(success);
    }

    #[test]
    fn test_external_g2_multiexp_vectors() {
        let p = "src/test/test_vectors/eip2539/extras/g2_multiexp.csv";
        
        let f = |input: &[u8]| EIP2539Executor::g2_multiexp(input).map(|r| r.to_vec());

        let success = run_on_test_inputs(p, true, f);

        assert!(success);
    }


    #[test]
    fn dump_extra_vectors_into_fuzzing_corpus() {
        let byte_idx: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let file_paths = vec![
            "g2_multiexp.csv",
        ];

        let mut counter = 0;

        for (b, f) in byte_idx.into_iter().zip(file_paths.into_iter()) {
            let mut reader = csv::Reader::from_path(&format!("src/test/test_vectors/eip2539/extras/{}", f)).unwrap();
            for r in reader.records() {
                let r = r.unwrap();
                let input = hex::decode(r.get(0).unwrap()).unwrap();
                let mut output = vec![b];
                output.extend(input);
                let name = format!("extra_vector_{}", counter);
                std::fs::write(&format!("src/test/test_vectors/eip2539/fuzzing/{}", name), &output).unwrap();

                counter += 1;
            }
        }
    }
}