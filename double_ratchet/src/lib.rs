use x3dh::{KeyPair, PublicKey, StaticSecret};

mod crypto;

#[derive(Clone)]
pub struct Chain {
    chain_key: ChainKey,
}

impl Chain {
    pub fn new(chain_key: ChainKey) -> Self {
        Self { chain_key }
    }
}

pub struct RootKey {
    key: [u8; 32],
}

impl RootKey {
    fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub(crate) fn create_chain(
        &self,
        their_ratchet_key: &PublicKey,
        our_ratchet_key: &StaticSecret,
    ) -> (RootKey, ChainKey) {
        let shared_secret = our_ratchet_key.diffie_hellman(their_ratchet_key);
        let mut derived_secret_bytes = [0; 64];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&self.key), &shared_secret.as_ref())
            .expand(b"WhisperRatchet", &mut derived_secret_bytes)
            .expect("valid output length");
        let mut root_key = [0; 32];
        let mut chain_key = [0; 32];
        root_key.copy_from_slice(&derived_secret_bytes[..32]);
        chain_key.copy_from_slice(&derived_secret_bytes[32..]);

        (
            RootKey { key: root_key },
            ChainKey {
                key: chain_key,
                index: 0,
            },
        )
    }
}

#[allow(unused)]
#[derive(Clone, Debug)]
pub struct MessageKeys {
    index: u32,
    cipher_key: PublicKey,
    mac_key: PublicKey,
    iv: [u8; 16],
}

impl MessageKeys {
    fn derive_keys(base_material: &[u8; 32], index: u32) -> Self {
        let mut secrets = [0; 80];
        let mut cipher_key = [0; 32];
        let mut mac_key = [0; 32];
        let mut iv = [0; 16];
        hkdf::Hkdf::<sha2::Sha256>::new(None, base_material)
            .expand(&index.to_be_bytes(), &mut secrets)
            .expect("valid length");
        cipher_key.copy_from_slice(&secrets[..32]);
        mac_key.copy_from_slice(&secrets[32..64]);
        iv.copy_from_slice(&secrets[64..]);

        Self {
            index,
            cipher_key: PublicKey::from(cipher_key),
            mac_key: PublicKey::from(mac_key),
            iv,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChainKey {
    key: [u8; 32],
    index: u32,
}

#[allow(unused)]
impl ChainKey {
    const MESSAGE_KEY_SEED: [u8; 1] = [0x01u8];
    const CHAIN_KEY_SEED: [u8; 1] = [0x02u8];

    pub(crate) fn new(key: [u8; 32], index: u32) -> Self {
        Self { key, index }
    }

    #[inline]
    pub(crate) fn key(&self) -> &[u8; 32] {
        &self.key
    }

    #[inline]
    pub(crate) fn index(&self) -> u32 {
        self.index
    }

    pub(crate) fn next_chain_key(&self) -> Self {
        Self {
            key: self.calculate_base_material(Self::CHAIN_KEY_SEED),
            index: self.index + 1,
        }
    }

    pub(crate) fn message_keys(&self) -> MessageKeys {
        MessageKeys::derive_keys(
            &self.calculate_base_material(Self::MESSAGE_KEY_SEED),
            self.index,
        )
    }

    fn calculate_base_material(&self, seed: [u8; 1]) -> [u8; 32] {
        crypto::hmac_sha256(&self.key, &seed)
    }
}

pub struct Ratchet {
    root_key: RootKey,
    our_ratchet_key_pair: KeyPair,
    sending_key_chain: Option<Chain>,
    receiving_key_chains: Vec<(PublicKey, Chain)>,
}

impl Ratchet {
    pub fn get_ratchet_key(&self) -> PublicKey {
        self.our_ratchet_key_pair.1
    }

    pub fn new_slice(secret: &[u8], their_ratchet_key: PublicKey) -> Self {
        let (root_key, chain_key) = crypto::derive_keys(secret);
        let (our_ratchet_priv, our_ratchet_key) = crypto::generate_key_pair();
        let (next_root_key, sending_chain_chain_key) =
            root_key.create_chain(&their_ratchet_key, &our_ratchet_priv);
        Self {
            root_key: next_root_key,
            our_ratchet_key_pair: (our_ratchet_priv, our_ratchet_key),
            sending_key_chain: Some(Chain::new(sending_chain_chain_key)),
            receiving_key_chains: vec![(their_ratchet_key, Chain::new(chain_key))],
        }
    }

    pub fn new_bob(secret: &[u8]) -> Self {
        // TODO: confirm the usage of _chain_key
        let (root_key, _chain_key) = crypto::derive_keys(secret);
        let (our_ratchet_priv, our_ratchet_key) = crypto::generate_key_pair();
        Self {
            root_key: root_key,
            our_ratchet_key_pair: (our_ratchet_priv, our_ratchet_key),
            sending_key_chain: None,
            receiving_key_chains: vec![],
        }
    }

    // move the sending chain key to the next, and return the message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, crypto::EncryptionError> {
        let chain = self.sending_key_chain.as_mut().unwrap();
        let message_keys = chain.chain_key.message_keys();
        println!("sending chain key: {:x?}", chain.chain_key);
        let ciphertext = crypto::aes_256_cbc_encrypt(
            plaintext,
            message_keys.cipher_key.as_ref(),
            &message_keys.iv,
        )?;
        chain.chain_key = chain.chain_key.next_chain_key();
        Ok(ciphertext)
    }

    // generate the next ratchet key pair, and create the new sending chain
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        their_ratchet_key: PublicKey,
    ) -> Result<Vec<u8>, crypto::DecryptionError> {
        let chain_key = self.get_or_create_receiver_key_chain(their_ratchet_key);
        println!("receiving chain key: {:x?}", chain_key);
        let message_keys = chain_key.message_keys();
        let plaintext = crypto::aes_256_cbc_decrypt(
            ciphertext,
            message_keys.cipher_key.as_ref(),
            &message_keys.iv,
        )?;
        self.set_receiver_chain_key(their_ratchet_key, chain_key.next_chain_key());
        return Ok(plaintext);
    }

    fn set_receiver_chain_key(&mut self, their_ratchet_key: PublicKey, chain_key: ChainKey) {
        if let Some((_, chain)) = self
            .receiving_key_chains
            .iter_mut()
            .find(|(key, _)| key == &their_ratchet_key)
        {
            chain.chain_key = chain_key;
        } else {
            self.receiving_key_chains
                .push((their_ratchet_key, Chain::new(chain_key)));
        }
    }

    fn get_or_create_receiver_key_chain(&mut self, their_ratchet_key: PublicKey) -> ChainKey {
        if let Some((_, chain)) = self
            .receiving_key_chains
            .iter_mut()
            .find(|(key, _)| key == &their_ratchet_key)
        {
            chain.chain_key.clone()
        } else {
            let (root_key1, chain_key) = self
                .root_key
                .create_chain(&their_ratchet_key, &self.our_ratchet_key_pair.0);
            self.receiving_key_chains
                .push((their_ratchet_key, Chain::new(chain_key.clone())));
            let new_ratchet_key_pair = crypto::generate_key_pair();
            let (root_key2, sending_chain_key) =
                root_key1.create_chain(&their_ratchet_key, &new_ratchet_key_pair.0);
            self.root_key = root_key2;
            self.sending_key_chain = Some(Chain::new(sending_chain_key));
            self.our_ratchet_key_pair = new_ratchet_key_pair;
            chain_key
        }
    }
}

#[test]
fn test_ping_pong() {
    let mut bob_ratchet = Ratchet::new_bob(&[]);
    let mut alice_ratchet = Ratchet::new_slice(&[], bob_ratchet.get_ratchet_key());

    for _ in 0..10 {
        let plaintext = b"hello";
        let ciphertext = alice_ratchet.encrypt(plaintext).unwrap();

        let decrypted = bob_ratchet
            .decrypt(&ciphertext, alice_ratchet.get_ratchet_key())
            .unwrap();
        assert!(decrypted == plaintext);

        let plaintext = b"world";
        let ciphertext = bob_ratchet.encrypt(plaintext).unwrap();
        let decrypted = alice_ratchet
            .decrypt(&ciphertext, bob_ratchet.get_ratchet_key())
            .unwrap();
        assert!(decrypted == plaintext);
    }
}

#[test]
fn test_ratchet_no_change() {
    let mut bob_ratchet = Ratchet::new_bob(&[]);
    let mut alice_ratchet = Ratchet::new_slice(&[], bob_ratchet.get_ratchet_key());
    let mut bob_ratchet_key = bob_ratchet.get_ratchet_key();
    let slice_ratchet_key = alice_ratchet.get_ratchet_key();

    for i in 0..10 {
        let plaintext = b"hello";
        let ciphertext = alice_ratchet.encrypt(plaintext).unwrap();

        let decrypted = bob_ratchet
            .decrypt(&ciphertext, alice_ratchet.get_ratchet_key())
            .unwrap();
        // slice's ratchet key should not change during the encryption
        assert!(slice_ratchet_key == alice_ratchet.get_ratchet_key());
        let bob_ratchet_key_after = bob_ratchet.get_ratchet_key();
        // bob's ratchet key should change when first seeing slice's current ratchet key
        // after that, bob's ratchet key should not change, till slice change her ratchet key and attach the key to the message
        if i == 0 {
            assert!(bob_ratchet_key != bob_ratchet_key_after);
            bob_ratchet_key = bob_ratchet_key_after;
        } else {
            assert!(bob_ratchet_key == bob_ratchet_key_after);
        }
        assert!(decrypted == plaintext);
    }
}
