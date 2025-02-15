use core::{cmp::Ordering, convert::Infallible, fmt::Debug};

use super::{
    env::internal::{Env as _, EnvBase as _, I256Small, I256Val, U256Small, U256Val},
    ConversionError, Env, TryFromVal, TryIntoVal, Val,
};

#[cfg(not(target_family = "wasm"))]
use crate::env::internal::xdr::ScVal;
use crate::{env::MaybeEnv, unwrap::UnwrapInfallible};

macro_rules! impl_num_wrapping_val_type {
    (#[doc = $doc:expr] $wrapper:ident, $val:ty, $small:ty) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $wrapper {
            env: MaybeEnv,
            val: $val,
        }

        impl Debug for $wrapper {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                // FIXME: properly print it when we have the conversion functions
                write!(f, "{:?}", self.val.as_val())
            }
        }

        impl Eq for $wrapper {}

        impl PartialEq for $wrapper {
            fn eq(&self, other: &Self) -> bool {
                self.partial_cmp(other) == Some(Ordering::Equal)
            }
        }

        impl PartialOrd for $wrapper {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(Ord::cmp(self, other))
            }
        }

        impl Ord for $wrapper {
            fn cmp(&self, other: &Self) -> Ordering {
                let self_raw = self.val.to_val();
                let other_raw = other.val.to_val();

                match (<$small>::try_from(self_raw), <$small>::try_from(other_raw)) {
                    // Compare small numbers.
                    (Ok(self_num), Ok(other_num)) => self_num.cmp(&other_num),
                    // The object-to-small number comparisons are handled by `obj_cmp`,
                    // so it's safe to handle all the other cases using it.
                    _ => {
                        let env: Option<Env> =
                            match (self.env.clone().try_into(), other.env.clone().try_into()) {
                                (Err(_), Err(_)) => None,
                                (Err(_), Ok(e)) => Some(e),
                                (Ok(e), Err(_)) => Some(e),
                                (Ok(e1), Ok(e2)) => {
                                    e1.check_same_env(&e2);
                                    Some(e1)
                                }
                            };
                        if let Some(env) = env {
                            let v = env.obj_cmp(self_raw, other_raw).unwrap_infallible();
                            v.cmp(&0)
                        } else {
                            panic!("$wrapper object is missing the env reference");
                        }
                    }
                }
            }
        }

        impl TryFromVal<Env, $val> for $wrapper {
            type Error = Infallible;

            fn try_from_val(env: &Env, val: &$val) -> Result<Self, Self::Error> {
                Ok(unsafe { $wrapper::unchecked_new(env.clone(), *val) })
            }
        }

        impl TryFromVal<Env, Val> for $wrapper {
            type Error = ConversionError;

            fn try_from_val(env: &Env, val: &Val) -> Result<Self, Self::Error> {
                Ok(<$val>::try_from_val(env, val)?
                    .try_into_val(env)
                    .unwrap_infallible())
            }
        }

        impl TryFromVal<Env, $wrapper> for Val {
            type Error = ConversionError;

            fn try_from_val(_env: &Env, v: &$wrapper) -> Result<Self, Self::Error> {
                Ok(v.to_val())
            }
        }

        impl TryFromVal<Env, &$wrapper> for Val {
            type Error = ConversionError;

            fn try_from_val(_env: &Env, v: &&$wrapper) -> Result<Self, Self::Error> {
                Ok(v.to_val())
            }
        }

        #[cfg(not(target_family = "wasm"))]
        impl TryFrom<&$wrapper> for ScVal {
            type Error = ConversionError;
            fn try_from(v: &$wrapper) -> Result<Self, ConversionError> {
                if let Ok(ss) = <$small>::try_from(v.val) {
                    ScVal::try_from(ss)
                } else {
                    let e: Env = v.env.clone().try_into()?;
                    ScVal::try_from_val(&e, &v.to_val())
                }
            }
        }

        #[cfg(not(target_family = "wasm"))]
        impl TryFrom<$wrapper> for ScVal {
            type Error = ConversionError;
            fn try_from(v: $wrapper) -> Result<Self, ConversionError> {
                (&v).try_into()
            }
        }

        #[cfg(not(target_family = "wasm"))]
        impl TryFromVal<Env, ScVal> for $wrapper {
            type Error = ConversionError;
            fn try_from_val(env: &Env, val: &ScVal) -> Result<Self, Self::Error> {
                Ok(<$val>::try_from_val(env, &Val::try_from_val(env, val)?)?
                    .try_into_val(env)
                    .unwrap_infallible())
            }
        }

        impl $wrapper {
            #[inline(always)]
            pub(crate) unsafe fn unchecked_new(env: Env, val: $val) -> Self {
                Self {
                    env: env.into(),
                    val,
                }
            }

            pub fn as_val(&self) -> &Val {
                self.val.as_val()
            }

            pub fn to_val(&self) -> Val {
                self.val.to_val()
            }

            pub fn to_val_type(&self) -> $val {
                self.val
            }
        }
    };
}

impl_num_wrapping_val_type!(
    /// U256 holds a 256-bit unsigned integer.
    U256,
    U256Val,
    U256Small
);

impl_num_wrapping_val_type!(
    /// I256 holds a 256-bit signed integer.
    I256,
    I256Val,
    I256Small
);
