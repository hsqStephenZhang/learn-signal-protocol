pub use x25519_dalek::{PublicKey, StaticSecret};

pub type IdentityKey = PublicKey;
pub type KeyPair = (StaticSecret, PublicKey);

pub struct AliceSignalProtocolParameters {
    our_identity_key_pair: KeyPair,
    our_ephemeral_key_pair: KeyPair,

    their_identity_key: IdentityKey,
    their_signed_pre_key: PublicKey,
    their_one_time_pre_key: Option<PublicKey>,
}

// perform the X3DH key agreement protocol
pub fn x3dh(parameters: &AliceSignalProtocolParameters) -> Vec<u8> {
    let mut shared_secret = Vec::with_capacity(32 * 5);

    shared_secret.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    shared_secret.extend_from_slice(
        &parameters
            .our_identity_key_pair
            .0
            .diffie_hellman(&parameters.their_signed_pre_key)
            .to_bytes(),
    );

    shared_secret.extend_from_slice(
        &parameters
            .our_ephemeral_key_pair
            .0
            .diffie_hellman(&parameters.their_identity_key)
            .to_bytes(),
    );

    shared_secret.extend_from_slice(
        &parameters
            .our_ephemeral_key_pair
            .0
            .diffie_hellman(&parameters.their_signed_pre_key)
            .to_bytes(),
    );

    if let Some(their_one_time_pre_key) = parameters.their_one_time_pre_key {
        shared_secret.extend_from_slice(
            &parameters
                .our_ephemeral_key_pair
                .0
                .diffie_hellman(&their_one_time_pre_key)
                .to_bytes(),
        );
    }

    shared_secret
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /*
        expected output of shared secret:
        ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff, ff
        34, 6e, f3, ee, f3, b6, 91, d5, 4, 9b, c6, 57, b7, ba, 82, f, f9, e8, 91, b8, 2, b4, b7, 85, d8, f9, 3d, ad, 31, 2b, f7, 11
        41, c2, 55, 59, 57, 39, 6b, a1, 91, 9a, 92, 1b, ed, 4c, f4, 89, 52, 11, 62, 4b, ed, eb, 99, 3d, 64, c5, 3a, 4e, 3e, e5, 0, 31
        9, b2, 29, 47, 74, 48, 1, 58, f8, 41, 2a, e9, 38, 20, 2, 2a, cc, 2c, ae, 64, 5, 32, 81, 83, eb, 34, 20, 31, d7, 63, f9, 21
    */
    #[test]
    fn test_generate_shared_secret() {
        let bob_identity_public =
            hex!("f1f43874f6966956c2dd473f8fa15adeb71d1cb991b2341692324cefb1c5e626");

        let alice_ephemeral_public =
            hex!("472d1fb1a9862c3af6beaca8920277e2b26f4a79213ec7c906aeb35e03cf8950");

        let alice_ephemeral_private =
            hex!("11ae7c64d1e61cd596b76a0db5012673391cae66edbfcf073b4da80516a47449");

        let bob_signed_prekey_public =
            hex!("ac248a8f263be6863576eb0362e28c828f0107a3379d34bab1586bf8c770cd67");

        let alice_identity_public =
            hex!("b4a8455660ada65b401007f615e654041746432e3339c6875149bceefcb42b4a");

        let alice_identity_private =
            hex!("9040f0d4e09cf38f6dc7c13779c908c015a1da4fa78737a080eb0a6f4f5f8f58");

        let parameters = AliceSignalProtocolParameters {
            our_identity_key_pair: (
                StaticSecret::from(alice_identity_private),
                PublicKey::from(alice_identity_public),
            ),
            our_ephemeral_key_pair: (
                StaticSecret::from(alice_ephemeral_private),
                PublicKey::from(alice_ephemeral_public),
            ),
            their_identity_key: PublicKey::from(bob_identity_public),
            their_signed_pre_key: PublicKey::from(bob_signed_prekey_public),
            their_one_time_pre_key: None,
        };
        let shared_secret = x3dh(&parameters);
        assert!(shared_secret.len() == 32 * 4);
        for i in 0..4 {
            println!("{:x?}", &shared_secret[i * 32..(i + 1) * 32]);
        }
    }
}
