//Used for the names of cryptographic variables.
#![allow(non_snake_case)]

use std::slice;
use std::convert::TryInto;

use blake2::{Digest, Blake2b};
use curve25519_dalek::{constants, scalar::Scalar, ristretto};

#[no_mangle]
pub unsafe extern "C" fn reduce_to_scalar(
  scalar: *const u8,
  res: *mut u8
) {
  slice::from_raw_parts_mut(res, 32).copy_from_slice(
    &Scalar::from_bytes_mod_order(
      slice::from_raw_parts(scalar, 32).try_into().unwrap()
    ).to_bytes()
  )
}

#[no_mangle]
pub unsafe extern "C" fn reduce_to_scalar_wide(
  scalar: *const u8,
  res: *mut u8
) {
  slice::from_raw_parts_mut(res, 32).copy_from_slice(
    &Scalar::from_bytes_mod_order_wide(
      slice::from_raw_parts(scalar, 64).try_into().unwrap()
    ).to_bytes()
  )
}

#[no_mangle]
pub unsafe extern "C" fn verify_point(
  point: *const u8
) -> bool {
  ristretto::CompressedRistretto::from_slice(
    slice::from_raw_parts(point, 32).try_into().unwrap()
  ).decompress().is_some()
}

#[no_mangle]
pub unsafe extern "C" fn add_scalar(
  x: *const u8,
  y: *const u8,
  res: *mut u8
) {
  slice::from_raw_parts_mut(res, 32).copy_from_slice(
    &(
      Scalar::from_canonical_bytes(
        slice::from_raw_parts(x, 32).try_into().unwrap()
      ).unwrap() + Scalar::from_canonical_bytes(
        slice::from_raw_parts(y, 32).try_into().unwrap()
      ).unwrap()
    ).to_bytes()
  )
}

#[no_mangle]
pub unsafe extern "C" fn mul_scalar(
  x: *const u8,
  y: *const u8,
  res: *mut u8
) {
  slice::from_raw_parts_mut(res, 32).copy_from_slice(
    &(
      Scalar::from_canonical_bytes(
        slice::from_raw_parts(x, 32).try_into().unwrap()
      ).unwrap() * Scalar::from_canonical_bytes(
        slice::from_raw_parts(y, 32).try_into().unwrap()
      ).unwrap()
    ).to_bytes()
  )
}

#[no_mangle]
pub unsafe extern "C" fn add_point(
  x: *const u8,
  y: *const u8,
  res: *mut u8
) {
  slice::from_raw_parts_mut(res, 32).copy_from_slice(
    &(
      ristretto::CompressedRistretto::from_slice(
        slice::from_raw_parts(x, 32).try_into().unwrap()
      ).decompress().unwrap() + ristretto::CompressedRistretto::from_slice(
        slice::from_raw_parts(y, 32).try_into().unwrap()
      ).decompress().unwrap()
    ).compress().to_bytes()
  )
}

#[no_mangle]
pub unsafe extern "C" fn mul_point_by_scalar(
  x: *const u8,
  y: *const u8,
  res: *mut u8
) {
  slice::from_raw_parts_mut(res, 32).copy_from_slice(
    &(
      &Scalar::from_canonical_bytes(
        slice::from_raw_parts(x, 32).try_into().unwrap()
      ).unwrap() * &ristretto::CompressedRistretto::from_slice(
        slice::from_raw_parts(y, 32).try_into().unwrap()
      ).decompress().unwrap()
    ).compress().to_bytes()
  )
}

#[no_mangle]
pub unsafe extern "C" fn to_point(
  scalar: *const u8,
  res: *mut u8
) {
  slice::from_raw_parts_mut(res, 32).copy_from_slice(
    &(
      &Scalar::from_canonical_bytes(
        slice::from_raw_parts(scalar, 32).try_into().unwrap()
      ).unwrap() * &constants::RISTRETTO_BASEPOINT_TABLE
    ).compress().to_bytes()
  )
}

fn sign_safe(
  scalar: Scalar,
  msg: &[u8]
) -> Vec<u8> {
  let r: Scalar = Scalar::from_hash(Blake2b::new().chain(scalar.to_bytes()).chain(msg));
  let R: [u8; 32] = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();
  let A: [u8; 32] = (&scalar * &constants::RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();
  let HRAM: Scalar = Scalar::from_hash(Blake2b::new().chain(&R).chain(&A).chain(msg));
  let s: [u8; 32] = (r + (HRAM * scalar)).to_bytes();
  [R, s].concat()
}

#[no_mangle]
pub unsafe extern "C" fn sign(
  scalar: *const u8,
  msg: *const u8,
  msg_len: u32,
  res: *mut u8
) {
  slice::from_raw_parts_mut(res, 64).copy_from_slice(
    &sign_safe(
      Scalar::from_canonical_bytes(slice::from_raw_parts(scalar, 32).try_into().unwrap()).unwrap(),
      //Unfortunately will not work on 8 and 16-bit platforms.
      //Won't fix.
      slice::from_raw_parts(msg, msg_len.try_into().unwrap())
    )
  );
}

fn verify_safe(
  A: ristretto::RistrettoPoint,
  A_bytes: &[u8],
  msg: &[u8],
  R: ristretto::RistrettoPoint,
  R_bytes: &[u8],
  s: Scalar
) -> bool {
  let HRAM: Scalar = Scalar::from_hash(Blake2b::new().chain(R_bytes).chain(A_bytes).chain(msg));
  R == ristretto::RistrettoPoint::vartime_double_scalar_mul_basepoint(&HRAM, &-A, &s)
}

#[no_mangle]
pub unsafe extern "C" fn verify(
  point: *const u8,
  msg: *const u8,
  msg_len: u32,
  sig: *const u8
) -> bool {
  let A_bytes = slice::from_raw_parts(point, 32);
  let A: Option<ristretto::RistrettoPoint> = ristretto::CompressedRistretto::from_slice(A_bytes).decompress();

  let sig: &[u8] = slice::from_raw_parts(sig, 64);
  let R_bytes: &[u8] = &sig[..32];
  let R: Option<ristretto::RistrettoPoint> = ristretto::CompressedRistretto::from_slice(R_bytes).decompress();
  let s: Option<Scalar> = Scalar::from_canonical_bytes(sig[32..].try_into().unwrap());

  if let (Some(A), Some(R), Some(s)) = (A, R, s) {
    verify_safe(
      A,
      A_bytes,
      slice::from_raw_parts(msg, msg_len.try_into().unwrap()),
      R,
      R_bytes,
      s
    )
  } else {
    false
  }
}
