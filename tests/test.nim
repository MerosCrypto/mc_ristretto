import strutils

#Dev dependency of stint.
import stint

import ../mc_ristretto

const
  BASEPOINT: string = parseHexStr("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76")
  l: StUInt[256] = "7237005577332262213973186563042994240857116359379907606001950938285454250989".parse(StUInt[256])

#Parse and serialize back the base point.
let base = newPublicKey(cast[seq[byte]](cast[seq[byte]](BASEPOINT)))
if not base.valid:
  raise newException(Exception, "Basepoint wasn't valid.")
if base.serialize() != cast[seq[byte]](BASEPOINT):
  raise newException(Exception, "Failed to serialize parsed point.")

#Check invalid points appear as invalid.
let invalid: PublicKey = newPublicKey(cast[seq[byte]](cast[seq[byte]](BASEPOINT)[0 ..< 31]) & @[byte(0)])
if invalid.valid:
  raise newException(Exception, "Invalid point considered valid.")

#Check equality.
if base != base:
  raise newException(Exception, "Point wasn't equal to self.")
if base == (base + base):
  raise newException(Exception, "Point was equal to a different point or add is broken.")

#Check scalar math.
var
  #Uses 64-bytes because we don't differentiate between Scalars and PrivateKeys which are extended.
  #Just 0s out the nonce.
  oneBytes: seq[byte] = newSeq[byte](64)
  twoBytes: seq[byte] = newSeq[byte](64)
oneBytes[0] = 1
twoBytes[0] = 2
var
  one: PrivateKey = newPrivateKey(oneBytes)
  two: PrivateKey = newPrivateKey(twoBytes)
if one.serialize() != oneBytes:
  raise newException(Exception, "Failed to serialize parsed private key.")
if (one + one) != two:
  raise newException(Exception, "Scalar addition failed.")
#This check will pass even if scalar multiplication == scalar addition.
if (two + two) != (two * two):
  raise newException(Exception, "Scalar multiplication failed.")
#This won't.
if two != (two * one):
  raise newException(Exception, "Scalar multiplication failed due to being addition.")

#Check point multiplication.
if (newPrivateKey(newSeq[byte](64)) * base).serialize() != newSeq[byte](32):
  raise newException(Exception, "Multiplication against 0 didn't return the identity point.")
if (two * base) != (base + base):
  raise newException(Exception, "Point addition or multiplication was invalid.")
if (base * two) != (base + base):
  raise newException(Exception, "Point multiplication when written as y * x failed.")

#Check serialization of calculated points.
if (base + base).serialize() != cast[seq[byte]](parseHexStr("6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919")):
  raise newException(Exception, "Couldn't serialize a calulcated point/addition AND multiplication are wrong.")

#Sign and verify a signature.
const msg: string = "Hello, World!"
let sig: seq[byte] = two.sign(msg)
if not two.toPublicKey().verify(msg, sig):
  raise newException(Exception, "Sign/verify didn't work.")

#Different message.
if two.toPublicKey().verify(msg & "\0", sig):
  raise newException(Exception, "Signature verified for a different message; it may not support null bytes in the middle of the string.")

#Invalid public key.
if invalid.verify(msg, sig):
  raise newException(Exception, "Invalid public key verified for a signature.")
#Different public key.
if one.toPublicKey().verify(msg, sig):
  raise newException(Exception, "Different public key verified for a signature.")
#Invalid point in signature.
if two.toPublicKey().verify(msg, sig[0 ..< 31] & @[byte(0)] & sig[32 ..< 64]):
  raise newException(Exception, "Invalid R verified for a signature.")
#Different point in signature.
if two.toPublicKey().verify(msg, cast[seq[byte]](BASEPOINT) & sig[32 ..< 64]):
  raise newException(Exception, "Different R verified for a signature.")
#Unreduced scalar in signature.
let unreduced: seq[byte] = @((StUInt[256].fromBytesLE(sig[32 ..< 64]) + l).toBytesLE())
#Check this was properly modified. newPrivateKey should reduce it back to itself. Also tests reduction (enabling using raw urandom for keys).
if newPrivateKey(unreduced & newSeq[byte](32)) != newPrivateKey(sig[32 ..< 64] & newSeq[byte](32)):
  raise newException(Exception, "newPrivateKey didn't reduce a scalar/failed to add the modulus to a scalar.")
if two.toPublicKey().verify(msg, sig[0 ..< 32] & unreduced):
  raise newException(Exception, "Unreduced S verified for a signature.")
#Different scalar in signature.
if two.toPublicKey().verify(msg, sig[0 ..< 32] & one.serialize()[0 ..< 32]):
  raise newException(Exception, "Different S verified for a signature.")

#Sign/verify an empty message.
if not two.toPublicKey().verify("", two.sign("")):
  raise newException(Exception, "Couldn't sign and verify an empty message.")

#Test signatures for the identity point fail. A 0 bytestring generally denotes something never meant to be used.
let zero: PrivateKey = newPrivateKey(newSeq[byte](64))
if zero.toPublicKey().verify(msg, zero.sign(msg)):
  raise newException(Exception, "Signature for the identity point was accepted.")

echo "Test passed."
