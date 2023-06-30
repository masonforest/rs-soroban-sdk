use crate::{self as soroban_sdk};
use crate::{bytes, bytesn, env::internal::U32Val, vec, Bytes, BytesN, Env, IntoVal, Val, Vec};
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct TestCryptoContract;

#[contractimpl]
impl TestCryptoContract {
    pub fn sha256(env: Env, bytes: Bytes) -> BytesN<32> {
        env.crypto().sha256(&bytes)
    }

    pub fn keccak256(env: Env, bytes: Bytes) -> BytesN<32> {
        env.crypto().keccak256(&bytes)
    }

    pub fn prng_reseed(env: Env, bytes: Bytes) {
        env.crypto().prng_reseed(&bytes);
    }

    pub fn u64_in_inclusive_range(env: Env, min: u64, max: u64) -> u64 {
        env.crypto().u64_in_inclusive_range(min, max)
    }

    pub fn vec_shuffle(env: Env, vec: Vec<u32>) -> Vec<Val> {
        env.crypto()
            .vec_shuffle::<Vec<u32>>(vec.into())
            .into_val(&env)
    }

    pub fn verify_sig_ed25519(
        env: Env,
        public_key: BytesN<32>,
        message: Bytes,
        signature: BytesN<64>,
    ) {
        env.crypto()
            .ed25519_verify(&public_key, &message, &signature);
    }

    pub fn recover_key_ecdsa_secp256k1(
        env: Env,
        message: Bytes,
        signature: BytesN<64>,
        recovery_id: U32Val,
    ) -> Bytes {
        env.crypto()
            .recover_key_ecdsa_secp256k1(&message, &signature, recovery_id)
    }
}

#[test]
fn test_prng_reseed() {
    let env = Env::default();
    let contract_id = env.register_contract(None, TestCryptoContract);
    env.host().set_base_prng_seed([0; 32]);
    let client = TestCryptoContractClient::new(&env, &contract_id);

    let seed = bytes!(
        &env,
        0x0000000000000000000000000000000000000000000000000000000000000001
    );
    assert_eq!(client.u64_in_inclusive_range(&0, &9), 6);

    client.prng_reseed(&seed);

    assert_eq!(client.u64_in_inclusive_range(&0, &9), 8);
}

#[test]
fn test_keccak256() {
    let env = Env::default();
    let contract_id = env.register_contract(None, TestCryptoContract);
    let client = TestCryptoContractClient::new(&env, &contract_id);

    let bytes = b"test vector for soroban".into_val(&env);

    assert_eq!(
        client.keccak256(&bytes),
        bytesn!(
            &env,
            0x352fe2eaddf44eb02eb3eab1f8d6ff4ba426df4f1734b1e3f210d621ee8853d9
        )
    );
}

#[test]
fn test_sha256() {
    let env = Env::default();
    let contract_id = env.register_contract(None, TestCryptoContract);
    let client = TestCryptoContractClient::new(&env, &contract_id);

    let bytes = bytes!(&env, 0x01);

    assert_eq!(
        client.sha256(&bytes),
        bytesn!(
            &env,
            0x4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a
        )
    );
}

#[test]
fn test_vec_shuffle() {
    let env = Env::default();
    env.host().set_base_prng_seed([0; 32]);
    let contract_id = env.register_contract(None, TestCryptoContract);
    let client = TestCryptoContractClient::new(&env, &contract_id);

    let vec = vec![&env, 1, 2, 3];

    assert_eq!(
        client.vec_shuffle(&vec),
        vec![&env, Val::from(2u32), Val::from(3u32), Val::from(1u32)]
    );
}

#[test]
fn test_u64_in_inclusive_range() {
    let env = Env::default();
    env.host().set_base_prng_seed([0; 32]);
    let contract_id = env.register_contract(None, TestCryptoContract);
    let client = TestCryptoContractClient::new(&env, &contract_id);

    assert_eq!(client.u64_in_inclusive_range(&0, &9), 6);
}

#[test]
fn test_verify_sig_ed25519() {
    let env = Env::default();
    env.host().set_base_prng_seed([0; 32]);
    let contract_id = env.register_contract(None, TestCryptoContract);
    let client = TestCryptoContractClient::new(&env, &contract_id);
    // From https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
    let public_key: BytesN<32> = bytes!(
        &env,
        0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
    )
    .try_into()
    .unwrap();
    let signature = bytesn!(
        &env,
        0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
    );
    let message = bytes!(&env, 0x72);

    assert_eq!(
        client.verify_sig_ed25519(&public_key, &message, &signature),
        ()
    );
}

#[test]
#[should_panic]
fn test_verify_sig_ed25519_invalid_sig() {
    let env = Env::default();
    env.host().set_base_prng_seed([0; 32]);
    let contract_id = env.register_contract(None, TestCryptoContract);
    let client = TestCryptoContractClient::new(&env, &contract_id);
    // From https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
    let public_key = bytesn!(
        &env,
        0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
    )
    .try_into()
    .unwrap();
    let signature = bytesn!(
        &env,
        0x92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
    );
    let message = bytes!(&env, 0x73);

    client.verify_sig_ed25519(&public_key, &message, &signature);
}

#[test]
fn test_verify_sig_secp256k1() {
    let env = Env::default();
    env.host().set_base_prng_seed([0; 32]);
    let contract_id = env.register_contract(None, TestCryptoContract);
    let client = TestCryptoContractClient::new(&env, &contract_id);

    // From ethereum: https://github.com/ethereum/go-ethereum/blob/master/crypto/secp256k1/secp256_test.go

    let public_key = bytesn!(
        &env,
        0x04e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652
    )
    .try_into()
    .unwrap();
    let signature = bytesn!(
        &env,
        0x90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc93
    );
    let message_digest = bytes!(
        &env,
        0xce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008
    );
    let recovery_id = Val::from_u32(1);
    assert_eq!(
        client.recover_key_ecdsa_secp256k1(&message_digest, &signature, &recovery_id),
        public_key
    );
}
