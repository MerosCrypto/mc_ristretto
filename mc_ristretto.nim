import strutils

#Include and link against dalek and our wrapper for it.
const currentFolder = currentSourcePath().substr(0, currentSourcePath().len - 17)

{.passC: "-I" & currentFolder & "src/".}
{.passL: "-L" & currentFolder & "target/release/".}
when not defined(Windows):
  {.passL: "-lpthread".}
{.passL: "-lmc_ristretto".}

{.push header: "mc_ristretto.h".}

func reduceToScalar(
  scalar: ptr uint8,
  res: ptr uint8
) {.importc: "reduce_to_scalar".}

func reduceToScalarWide(
  scalar: ptr uint8,
  res: ptr uint8
) {.importc: "reduce_to_scalar_wide".}

func verifyPoint(
  point: ptr uint8
): bool {.importc: "verify_point".}

func addScalar(
  x: ptr uint8,
  y: ptr uint8,
  res: ptr uint8
) {.importc: "add_scalar".}

func mulScalar(
  x: ptr uint8,
  y: ptr uint8,
  res: ptr uint8
) {.importc: "mul_scalar".}

func addPoint(
  x: ptr uint8,
  y: ptr uint8,
  res: ptr uint8
) {.importc: "add_point".}

func mulPoint(
  x: ptr uint8,
  y: ptr uint8,
  res: ptr uint8
) {.importc: "mul_point_by_scalar".}

func toPoint(
  x: ptr uint8,
  res: ptr uint8
) {.importc: "to_point".}

#EdDSA sign using Blake2b-512.
func sign(
  scalar: ptr uint8,
  nonce: ptr uint8,
  msg: ptr uint8,
  msgLen: uint32,
  res: ptr uint8
) {.importc: "sign".}

func verify(
  point: ptr uint8,
  msg: ptr uint8,
  msgLen: uint32,
  sig: ptr uint8
): bool {.importc: "verify".}

{.pop.}

type
  Scalar* = object
    data: array[32, uint8]
  PrivateKey* = object
    scalar: Scalar
    nonce: array[32, uint8]
  PublicKey* = object
    data: array[32, uint8]

func newScalar*(
  scalar: seq[byte]
): Scalar {.raises: [
  ValueError
].} =
  if scalar.len == 32:
    reduceToScalar(unsafeAddr scalar[0], addr result.data[0])
  elif scalar.len == 64:
    reduceToScalarWide(unsafeAddr scalar[0], addr result.data[0])
  else:
    raise newException(ValueError, "Invalid scalar length.")

func newPrivateKey*(
  key: seq[byte]
): PrivateKey {.raises: [
  ValueError
].} =
  if key.len != 64:
    raise newException(ValueError, "Invalid private key length.")
  result.scalar = newScalar(key[0 ..< 32])
  copyMem(addr result.nonce[0], unsafeAddr key[32], 32)

converter toScalar*(
  key: PrivateKey
): Scalar {.inline, raises: [].} =
  key.scalar

#Does not validate the public key.
func newPublicKey*(
  key: seq[byte]
): PublicKey {.raises: [
  ValueError
].} =
  if key.len != 32:
    raise newException(ValueError, "Invalid public key length.")
  copyMem(addr result.data[0], unsafeAddr key[0], 32)

#Does validate the public key.
#The reason for this split is because signature verification runs its own public key check.
#Therefore, doing one when we construct the data type is redundant.
func valid*(
  key: PublicKey
): bool {.raises: [].} =
  verifyPoint(unsafeAddr key.data[0])

func toPublicKey*(
  key: PrivateKey
): PublicKey {.inline, raises: [].} =
  toPoint(unsafeAddr key.scalar.data[0], addr result.data[0])

func toPoint*(
  scalar: Scalar
): PublicKey {.inline, raises: [].} =
  toPoint(unsafeAddr scalar.data[0], addr result.data[0])

func `+`*(
  x: Scalar,
  y: Scalar
): Scalar {.inline, raises: [].} =
  addScalar(unsafeAddr x.data[0], unsafeAddr y.data[0], addr result.data[0])

func `*`*(
  x: Scalar,
  y: Scalar
): Scalar {.inline, raises: [].} =
  mulScalar(unsafeAddr x.data[0], unsafeAddr y.data[0], addr result.data[0])

func `*`*(
  x: Scalar,
  y: PublicKey
): PublicKey {.inline, raises: [].} =
  mulPoint(unsafeAddr x.data[0], unsafeAddr y.data[0], addr result.data[0])

func `*`*(
  x: PublicKey,
  y: Scalar
): PublicKey {.inline, raises: [].} =
  y * x

func `+`*(
  x: PublicKey,
  y: PublicKey
): PublicKey {.inline, raises: [].} =
  addPoint(unsafeAddr x.data[0], unsafeAddr y.data[0], addr result.data[0])

func sign*(
  key: PrivateKey,
  msg: string
): seq[byte] {.raises: [].} =
  result = newSeq[byte](64)
  let msgPtr: ptr uint8 = cast[ptr uint8](if msg.len == 0: nil else: unsafeAddr msg[0])
  sign(unsafeAddr key.scalar.data[0], unsafeAddr key.nonce[0], msgPtr, uint32(msg.len), addr result[0])

func verify*(
  key: PublicKey,
  msg: string,
  sig: seq[byte]
): bool {.raises: [
  ValueError
].} =
  if sig.len != 64:
    raise newException(ValueError, "Invalid length signature passed to verify.")

  #Reject signatures for the identity point, as this generally denotes a blank value not meant to be used.
  #In Meros, the identity point is meant to be a singular burn address, though any invalid point would work.
  #Technically breaks from EdDSA by adding this extra condition, yet this is targeted for Meros.
  #If anyone has a valid reason to EdDSA off of the identity, this arguably should be in Meros anyways. Let me know.
  #As one other side note, this arguably should be implemented on the Rust side of things.
  #Then we could do an actual equality, yet this encoding based check is fully secure given our canonicity requirements.
  #It's likely also faster as it involves no mathematical ops.
  #-- Kayaba
  if @(key.data) == newSeq[byte](32):
    return false

  let msgPtr: ptr uint8 = cast[ptr uint8](if msg.len == 0: nil else: unsafeAddr msg[0])
  verify(unsafeAddr key.data[0], msgPtr, uint32(msg.len), unsafeAddr sig[0])

func serialize*(
  key: Scalar or PublicKey
): seq[byte] {.inline, raises: [].} =
  @(key.data)

func serialize*(
  key: PrivateKey
): seq[byte] {.inline, raises: [].} =
  @(key.scalar.data) & @(key.nonce)

func `$`*(
  key: PublicKey
): string {.raises: [].} =
  #Doesn't use a string cast as such strings are not usable over the C FFI (no null terminator).
  #This should not make any assumptions about how the string will be used after this.
  result = newString(32)
  copyMem(addr result[0], unsafeAddr key.data[0], 32)
  result = result.toHex()

func `==`*(
  x: Scalar,
  y: Scalar
): bool {.inline, raises: [].} =
  x.data == y.data

func `!=`*(
  x: Scalar,
  y: Scalar
): bool {.inline, raises: [].} =
  not (x == y)

func `==`*(
  x: PrivateKey,
  y: PrivateKey
): bool {.inline, raises: [].} =
  #Only check the scalar portion.
  x.scalar == y.scalar

func `!=`*(
  x: PrivateKey,
  y: PrivateKey
): bool {.inline, raises: [].} =
  not (x == y)

func `==`*(
  x: PublicKey,
  y: PublicKey
): bool {.inline, raises: [].} =
  x.data == y.data

func `!=`*(
  x: PublicKey,
  y: PublicKey
): bool {.inline, raises: [].} =
  not (x == y)
