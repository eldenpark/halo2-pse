use ff::PrimeField;
use group::{Curve, GroupEncoding};
use pasta_curves::{Ep, EpAffine, Eq, EqAffine, Fp, Fq};
use serde::{de::Error as DeserializeError, Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Deref, DerefMut};

pub struct FpExt(pub Fp);
pub struct FqExt(pub Fq);
pub struct EpAffineExt(pub EpAffine);
pub struct EqAffineExt(pub EqAffine);
pub struct EpExt(pub Ep);
pub struct EqExt(pub Eq);

impl Serialize for FpExt {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_bytes(self.0.to_repr(), s)
    }
}

impl<'de> Deserialize<'de> for FpExt {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = deserialize_bytes(d)?;

        match Fp::from_repr(bytes).into() {
            Some(fq) => Ok(FpExt(fq)),
            None => Err(D::Error::custom(
                "deserialized bytes don't encode a Pallas field element",
            )),
        }
    }
}

impl Deref for FpExt {
    type Target = Fp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for FqExt {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_bytes(self.0.to_repr(), s)
    }
}

impl<'de> Deserialize<'de> for FqExt {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = deserialize_bytes(d)?;

        match Fq::from_repr(bytes).into() {
            Some(fq) => Ok(FqExt(fq)),
            None => Err(D::Error::custom(
                "deserialized bytes don't encode a Vesta field element",
            )),
        }
    }
}

impl Deref for FqExt {
    type Target = Fq;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for EpAffineExt {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_bytes(self.0.to_bytes(), s)
    }
}

impl<'de> Deserialize<'de> for EpAffineExt {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = deserialize_bytes(d)?;
        match EpAffine::from_bytes(&bytes).into() {
            Some(ep_affine) => Ok(EpAffineExt(ep_affine)),
            None => Err(D::Error::custom(
                "deserialized bytes don't encode a Pallas curve point",
            )),
        }
    }
}

impl Deref for EpAffineExt {
    type Target = EpAffine;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for EqAffineExt {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_bytes(self.0.to_bytes(), s)
    }
}

impl<'de> Deserialize<'de> for EqAffineExt {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = deserialize_bytes(d)?;
        match EqAffine::from_bytes(&bytes).into() {
            Some(eq_affine) => Ok(EqAffineExt(eq_affine)),
            None => Err(D::Error::custom(
                "deserialized bytes don't encode a Vesta curve point",
            )),
        }
    }
}

impl Deref for EqAffineExt {
    type Target = EqAffine;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for EpExt {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // EpAffine::serialize(&self.0.to_affine(), s)
        serialize_bytes(self.0.to_bytes(), s)
    }
}

impl<'de> Deserialize<'de> for EpExt {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let ep_affine = EpAffineExt::deserialize(d)?.0;
        let ep = Ep::from(ep_affine);
        Ok(EpExt(ep))
    }
}

impl Deref for EpExt {
    type Target = Ep;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for EqExt {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_bytes(self.0.to_bytes(), s)
    }
}

impl<'de> Deserialize<'de> for EqExt {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let eq_affine = EqAffineExt::deserialize(d)?.0;
        let eq = Eq::from(eq_affine);
        Ok(EqExt(eq))
    }
}

impl Deref for EqExt {
    type Target = Eq;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Serializes bytes to human readable or compact representation.
///
/// Depending on whether the serializer is a human readable one or not, the bytes are either
/// encoded as a hex string or a list of bytes.
fn serialize_bytes<S: Serializer>(bytes: [u8; 32], s: S) -> Result<S::Ok, S::Error> {
    if s.is_human_readable() {
        hex::serde::serialize(bytes, s)
    } else {
        bytes.serialize(s)
    }
}

/// Deserialize bytes from human readable or compact representation.
///
/// Depending on whether the deserializer is a human readable one or not, the bytes are either
/// decoded from a hex string or a list of bytes.
fn deserialize_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    if d.is_human_readable() {
        hex::serde::deserialize(d)
    } else {
        <[u8; 32]>::deserialize(d)
    }
}
