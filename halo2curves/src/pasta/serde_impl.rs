use super::curve_ext::EqAffineExt;
use crate::{
    pasta::curve_ext::{FpExt, FqExt},
    serde::SerdeObject,
};
use pasta_curves::{EqAffine, Fp, Fq};

impl crate::serde::SerdeObject for EqAffine {
    fn from_raw_bytes_unchecked(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), 64);

        let obj = serde_json::from_slice::<EqAffineExt>(bytes).unwrap();
        obj.0
    }

    fn from_raw_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }

        let a = serde_json::from_slice::<EqAffineExt>(bytes)
            .ok()
            .map(|obj| obj.0);
        a
    }

    fn to_raw_bytes(&self) -> Vec<u8> {
        let obj = EqAffineExt(*self);

        serde_json::to_vec(&obj).unwrap()
    }

    fn read_raw_unchecked<R: std::io::Read>(reader: &mut R) -> Self {
        let obj: EqAffineExt = serde_json::from_reader(reader).unwrap();
        obj.0
    }

    fn read_raw<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        match serde_json::from_reader::<_, EqAffineExt>(reader) {
            Ok(o) => Ok(o.0),
            Err(err) => Err(err.into()),
        }
    }

    fn write_raw<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match serde_json::to_writer(writer, &EqAffineExt(*self)) {
            Ok(_) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

impl crate::serde::SerdeObject for Fp {
    fn from_raw_bytes_unchecked(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), 64);

        let obj = serde_json::from_slice::<FpExt>(bytes).unwrap();
        obj.0
    }

    fn from_raw_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }

        let a = serde_json::from_slice::<FpExt>(bytes).ok().map(|obj| obj.0);
        a
    }

    fn to_raw_bytes(&self) -> Vec<u8> {
        let obj = FpExt(*self);

        serde_json::to_vec(&obj).unwrap()
    }

    fn read_raw_unchecked<R: std::io::Read>(reader: &mut R) -> Self {
        let obj: FpExt = serde_json::from_reader(reader).unwrap();
        obj.0
    }

    fn read_raw<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        match serde_json::from_reader::<_, FpExt>(reader) {
            Ok(o) => Ok(o.0),
            Err(err) => Err(err.into()),
        }
    }

    fn write_raw<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match serde_json::to_writer(writer, &FpExt(*self)) {
            Ok(_) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

impl crate::serde::SerdeObject for Fq {
    fn from_raw_bytes_unchecked(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), 64);

        let obj = serde_json::from_slice::<FqExt>(bytes).unwrap();
        obj.0
    }

    fn from_raw_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }

        let a = serde_json::from_slice::<FqExt>(bytes).ok().map(|obj| obj.0);
        a
    }

    fn to_raw_bytes(&self) -> Vec<u8> {
        let obj = FqExt(*self);

        serde_json::to_vec(&obj).unwrap()
    }

    fn read_raw_unchecked<R: std::io::Read>(reader: &mut R) -> Self {
        let obj: FqExt = serde_json::from_reader(reader).unwrap();
        obj.0
    }

    fn read_raw<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        match serde_json::from_reader::<_, FqExt>(reader) {
            Ok(o) => Ok(o.0),
            Err(err) => Err(err.into()),
        }
    }

    fn write_raw<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match serde_json::to_writer(writer, &FqExt(*self)) {
            Ok(_) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}
