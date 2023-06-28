//! Crypto contains functions for cryptographic functions.
use crate::{
    env::internal, unwrap::UnwrapInfallible, Bytes, BytesN, Env, EnvBase, IntoVal, TryIntoVal, Val,
    Vec,
};

/// Crypto provides access to cryptographic functions.
pub struct Crypto {
    env: Env,
}

impl Crypto {
    pub(crate) fn new(env: &Env) -> Crypto {
        Crypto { env: env.clone() }
    }

    pub fn env(&self) -> &Env {
        &self.env
    }

    /// Returns the SHA-256 hash of the data.
    pub fn sha256(&self, data: &Bytes) -> BytesN<32> {
        let env = self.env();
        env.check_same_env(data.env());
        let bin = internal::Env::compute_hash_sha256(env, data.into()).unwrap_infallible();
        unsafe { BytesN::unchecked_new(env.clone(), bin) }
    }

    // Reseeds the pseudorandom number generator (PRNG) with the provided `seed` value.
    pub fn prng_reseed(&self, seed: &Bytes) {
        let env = self.env();
        env.check_same_env(seed.env());
        internal::Env::prng_reseed(env, seed.into()).unwrap_infallible();
    }

    // Returns a random u64 in the range between `lower` and `upper` inclusive.
    pub fn u64_in_inclusive_range(&self, lower: u64, upper: u64) -> u64 {
        let env = self.env();
        internal::Env::prng_u64_in_inclusive_range(env, lower.into(), upper.into())
            .unwrap_infallible()
            .into()
    }

    // Shuffles a given vector v using the Fisher-Yates algorithm.
    pub fn vec_shuffle<V>(&self, v: V) -> Vec<Val>
    where
        V: IntoVal<Env, Vec<Val>>,
    {
        let env = self.env();
        let v_val = v.into_val(env);
        env.check_same_env(v_val.env());

        internal::Env::prng_vec_shuffle(env, v_val.to_object())
            .unwrap_infallible()
            .try_into_val(env)
            .unwrap_infallible()
    }
    /// Verifies an ed25519 signature.
    ///
    /// The signature is verified as a valid signature of the message by the
    /// ed25519 public key.
    ///
    /// ### Panics
    ///
    /// If the signature verification fails.
    pub fn ed25519_verify(&self, public_key: &BytesN<32>, message: &Bytes, signature: &BytesN<64>) {
        let env = self.env();
        env.check_same_env(public_key.env());
        env.check_same_env(message.env());
        env.check_same_env(signature.env());
        let _ = internal::Env::verify_sig_ed25519(
            env,
            public_key.to_object(),
            message.to_object(),
            signature.to_object(),
        );
    }
}
