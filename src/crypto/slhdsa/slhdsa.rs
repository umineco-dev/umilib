use core::marker::PhantomData;

use super::{SLHDSAAddress, SLHDSAHash, SLHDSALimits, SLHDSAParameters, SLHDSASigningKey, SLHDSAVerifyingKey};
use crate::crypto::random::Random;
use crate::crypto::{CryptoError, PreHash, SignatureScheme};
use crate::secret::{ConstantTimeEq, Zeroize};

/// SLH-DSA with the parameters `P` (FIPS 205): `SLHDSA<SLHDSA_SHA2_128s>`.
///
/// The signing functions take a context of at most 255 bytes and come in
/// the hedged variant (`sign_with_context`, addrnd from a generator) and the
/// deterministic one (`sign_deterministic_with_context`, opt_rand = PK.seed); `_pre_hash`
/// gives HashSLH-DSA with a [`PreHash`] function, and `_internal` the
/// functions of section 9 on M'. [`SignatureScheme`] signs
/// deterministically with the empty context. WOTS+, XMSS, the hypertree and
/// FORS are associated functions too: components of SLH-DSA, not signature
/// schemes on their own (section 3.2). Hashing is on public indices and on
/// secrets alike, in time that depends on the indices alone.
pub struct SLHDSA<P: SLHDSAParameters> {
    parameters: PhantomData<P>,
}

impl<P: SLHDSAParameters> SLHDSA<P> {
    /// base_2b(X, b, out_len) (algorithm 4) into `out` of out_len integers.
    pub fn base_2b(bytes: &[u8], bits: usize, out: &mut [u32]) {
        let (mut input, mut available, mut total) = (0, 0usize, 0u64);
        for value in out.iter_mut() {
            while available < bits {
                total = (total << 8) | bytes[input] as u64;
                input += 1;
                available += 8;
            }
            available -= bits;
            *value = ((total >> available) & ((1 << bits) - 1)) as u32;
        }
    }

    /// chain(X, i, s, PK.seed, ADRS) (algorithm 5), on `node` of n bytes in place.
    pub fn chain(node: &mut [u8], start: u32, steps: u32, hash: &P::Hash, address: &mut SLHDSAAddress) {
        let mut next = [0u8; SLHDSALimits::N];
        for index in start..start + steps {
            address.set_hash_address(index);
            hash.f(address, node, &mut next[..P::N]);
            node.copy_from_slice(&next[..P::N]);
        }
    }

    /// The len base-w integers of a WOTS+ message: its len1 digits and the
    /// len2 digits of its checksum (algorithm 7 lines 1 to 7).
    pub fn wots_digits(message: &[u8], digits: &mut [u32]) {
        SLHDSA::<P>::base_2b(message, P::LG_W, &mut digits[..P::LEN1]);
        let mut checksum: u32 = digits[..P::LEN1].iter().map(|digit| P::W - 1 - digit).sum();
        let shift = (8 - (P::LEN2 * P::LG_W) % 8) % 8;
        checksum <<= shift;
        let bytes = checksum.to_be_bytes();
        let length = (P::LEN2 * P::LG_W).div_ceil(8);
        SLHDSA::<P>::base_2b(&bytes[4 - length..], P::LG_W, &mut digits[P::LEN1..P::LEN]);
    }

    /// The WOTS+ public key of the chain ends `ends` of len n bytes (algorithm 6 lines 10 to 13).
    pub fn wots_compress(ends: &[u8], hash: &P::Hash, address: &SLHDSAAddress) -> [u8; SLHDSALimits::N] {
        let mut key_address = *address;
        key_address.set_type_and_clear(SLHDSAAddress::WOTS_PK);
        key_address.set_key_pair_address(address.key_pair_address());
        let mut out = [0u8; SLHDSALimits::N];
        hash.t(&key_address, ends, &mut out[..P::N]);
        out
    }

    /// The secret value of chain `index` of the WOTS+ key of `address`.
    pub fn wots_secret(sk_seed: &[u8], index: u32, hash: &P::Hash, address: &SLHDSAAddress, out: &mut [u8]) {
        let mut secret_address = *address;
        secret_address.set_type_and_clear(SLHDSAAddress::WOTS_PRF);
        secret_address.set_key_pair_address(address.key_pair_address());
        secret_address.set_chain_address(index);
        hash.prf(&secret_address, sk_seed, out);
    }

    /// wots_pkGen (algorithm 6).
    pub fn wots_pk_gen(sk_seed: &[u8], hash: &P::Hash, address: &mut SLHDSAAddress) -> [u8; SLHDSALimits::N] {
        let mut ends = [0u8; SLHDSALimits::WOTS];
        for (index, end) in ends.chunks_exact_mut(P::N).take(P::LEN).enumerate() {
            SLHDSA::<P>::wots_secret(sk_seed, index as u32, hash, address, end);
            address.set_chain_address(index as u32);
            SLHDSA::<P>::chain(end, 0, P::W - 1, hash, address);
        }
        let key = SLHDSA::<P>::wots_compress(&ends[..P::LEN * P::N], hash, address);
        ends.zeroize();
        key
    }

    /// wots_sign (algorithm 7) of the n-byte `message` into `out` of len n bytes.
    pub fn wots_sign(message: &[u8], sk_seed: &[u8], hash: &P::Hash, address: &mut SLHDSAAddress, out: &mut [u8]) {
        let mut digits = [0u32; SLHDSALimits::LEN];
        SLHDSA::<P>::wots_digits(message, &mut digits);
        for (index, node) in out.chunks_exact_mut(P::N).take(P::LEN).enumerate() {
            SLHDSA::<P>::wots_secret(sk_seed, index as u32, hash, address, node);
            address.set_chain_address(index as u32);
            SLHDSA::<P>::chain(node, 0, digits[index], hash, address);
        }
    }

    /// wots_pkFromSig (algorithm 8).
    pub fn wots_pk_from_sig(
        signature: &[u8],
        message: &[u8],
        hash: &P::Hash,
        address: &mut SLHDSAAddress,
    ) -> [u8; SLHDSALimits::N] {
        let mut digits = [0u32; SLHDSALimits::LEN];
        SLHDSA::<P>::wots_digits(message, &mut digits);
        let mut ends = [0u8; SLHDSALimits::WOTS];
        let pairs = ends.chunks_exact_mut(P::N).zip(signature.chunks_exact(P::N)).take(P::LEN);
        for (index, (end, node)) in pairs.enumerate() {
            end.copy_from_slice(node);
            address.set_chain_address(index as u32);
            SLHDSA::<P>::chain(end, digits[index], P::W - 1 - digits[index], hash, address);
        }
        SLHDSA::<P>::wots_compress(&ends[..P::LEN * P::N], hash, address)
    }

    /// H of the two children `left` and `right` of the node at `height` and `index`.
    pub fn parent(left: &[u8], right: &[u8], hash: &P::Hash, address: &mut SLHDSAAddress) -> [u8; SLHDSALimits::N] {
        let mut pair = [0u8; 2 * SLHDSALimits::N];
        pair[..P::N].copy_from_slice(left);
        pair[P::N..2 * P::N].copy_from_slice(right);
        let mut out = [0u8; SLHDSALimits::N];
        hash.h(address, &pair[..2 * P::N], &mut out[..P::N]);
        out
    }

    /// xmss_node (algorithm 9): the node `index` at `height` of the XMSS tree of `address`.
    pub fn xmss_node(
        sk_seed: &[u8],
        index: u32,
        height: u32,
        hash: &P::Hash,
        address: &mut SLHDSAAddress,
    ) -> [u8; SLHDSALimits::N] {
        if height == 0 {
            address.set_type_and_clear(SLHDSAAddress::WOTS_HASH);
            address.set_key_pair_address(index);
            return SLHDSA::<P>::wots_pk_gen(sk_seed, hash, address);
        }
        let left = SLHDSA::<P>::xmss_node(sk_seed, 2 * index, height - 1, hash, address);
        let right = SLHDSA::<P>::xmss_node(sk_seed, 2 * index + 1, height - 1, hash, address);
        address.set_type_and_clear(SLHDSAAddress::TREE);
        address.set_tree_height(height);
        address.set_tree_index(index);
        SLHDSA::<P>::parent(&left[..P::N], &right[..P::N], hash, address)
    }

    /// xmss_sign (algorithm 10) into `out` of (len + h') n bytes.
    pub fn xmss_sign(
        message: &[u8],
        sk_seed: &[u8],
        index: u32,
        hash: &P::Hash,
        address: &mut SLHDSAAddress,
        out: &mut [u8],
    ) {
        let (wots, authentication) = out.split_at_mut(P::LEN * P::N);
        for (height, node) in authentication.chunks_exact_mut(P::N).take(P::HP).enumerate() {
            let sibling = (index >> height) ^ 1;
            node.copy_from_slice(&SLHDSA::<P>::xmss_node(sk_seed, sibling, height as u32, hash, address)[..P::N]);
        }
        address.set_type_and_clear(SLHDSAAddress::WOTS_HASH);
        address.set_key_pair_address(index);
        SLHDSA::<P>::wots_sign(message, sk_seed, hash, address, wots);
    }

    /// The root of a Merkle tree from the leaf `leaf` of index `index` and
    /// its authentication path (algorithm 11 lines 6 to 18, algorithm 17
    /// lines 8 to 18), with `address` set to the leaf.
    pub fn root_from_path(
        leaf: &[u8],
        index: u32,
        path: &[u8],
        hash: &P::Hash,
        address: &mut SLHDSAAddress,
    ) -> [u8; SLHDSALimits::N] {
        let mut node = [0u8; SLHDSALimits::N];
        node[..P::N].copy_from_slice(leaf);
        for (height, sibling) in path.chunks_exact(P::N).enumerate() {
            address.set_tree_height(height as u32 + 1);
            if (index >> height) & 1 == 0 {
                address.set_tree_index(address.tree_index() / 2);
                node = SLHDSA::<P>::parent(&node[..P::N], sibling, hash, address);
            } else {
                address.set_tree_index((address.tree_index() - 1) / 2);
                node = SLHDSA::<P>::parent(sibling, &node[..P::N], hash, address);
            }
        }
        node
    }

    /// xmss_pkFromSig (algorithm 11).
    pub fn xmss_pk_from_sig(
        index: u32,
        signature: &[u8],
        message: &[u8],
        hash: &P::Hash,
        address: &mut SLHDSAAddress,
    ) -> [u8; SLHDSALimits::N] {
        address.set_type_and_clear(SLHDSAAddress::WOTS_HASH);
        address.set_key_pair_address(index);
        let (wots, authentication) = signature.split_at(P::LEN * P::N);
        let leaf = SLHDSA::<P>::wots_pk_from_sig(wots, message, hash, address);
        address.set_type_and_clear(SLHDSAAddress::TREE);
        address.set_tree_index(index);
        SLHDSA::<P>::root_from_path(&leaf[..P::N], index, authentication, hash, address)
    }

    /// ht_sign (algorithm 12) into `out` of d (h' + len) n bytes.
    pub fn ht_sign(message: &[u8], sk_seed: &[u8], hash: &P::Hash, mut tree: u64, mut leaf: u32, out: &mut [u8]) {
        let mut address = SLHDSAAddress::new();
        let mut root = [0u8; SLHDSALimits::N];
        root[..P::N].copy_from_slice(message);
        for (layer, signature) in out.chunks_exact_mut(P::XMSS_SIGNATURE_SIZE).take(P::D).enumerate() {
            if layer > 0 {
                leaf = (tree & ((1 << P::HP) - 1)) as u32;
                tree >>= P::HP;
            }
            address.set_layer_address(layer as u32);
            address.set_tree_address(tree);
            SLHDSA::<P>::xmss_sign(&root[..P::N], sk_seed, leaf, hash, &mut address, signature);
            if layer + 1 < P::D {
                root = SLHDSA::<P>::xmss_pk_from_sig(leaf, signature, &root[..P::N], hash, &mut address);
            }
        }
    }

    /// ht_verify (algorithm 13).
    pub fn ht_verify(
        message: &[u8],
        signature: &[u8],
        hash: &P::Hash,
        mut tree: u64,
        mut leaf: u32,
        pk_root: &[u8],
    ) -> bool {
        let mut address = SLHDSAAddress::new();
        let mut node = [0u8; SLHDSALimits::N];
        node[..P::N].copy_from_slice(message);
        for (layer, signature) in signature.chunks_exact(P::XMSS_SIGNATURE_SIZE).take(P::D).enumerate() {
            if layer > 0 {
                leaf = (tree & ((1 << P::HP) - 1)) as u32;
                tree >>= P::HP;
            }
            address.set_layer_address(layer as u32);
            address.set_tree_address(tree);
            node = SLHDSA::<P>::xmss_pk_from_sig(leaf, signature, &node[..P::N], hash, &mut address);
        }
        node[..P::N].ct_eq(pk_root).into_bool()
    }

    /// fors_skGen (algorithm 14).
    pub fn fors_sk_gen(sk_seed: &[u8], hash: &P::Hash, address: &SLHDSAAddress, index: u32) -> [u8; SLHDSALimits::N] {
        let mut secret_address = *address;
        secret_address.set_type_and_clear(SLHDSAAddress::FORS_PRF);
        secret_address.set_key_pair_address(address.key_pair_address());
        secret_address.set_tree_index(index);
        let mut out = [0u8; SLHDSALimits::N];
        hash.prf(&secret_address, sk_seed, &mut out[..P::N]);
        out
    }

    /// fors_node (algorithm 15).
    pub fn fors_node(
        sk_seed: &[u8],
        index: u32,
        height: u32,
        hash: &P::Hash,
        address: &mut SLHDSAAddress,
    ) -> [u8; SLHDSALimits::N] {
        if height == 0 {
            let mut secret = SLHDSA::<P>::fors_sk_gen(sk_seed, hash, address, index);
            address.set_tree_height(0);
            address.set_tree_index(index);
            let mut out = [0u8; SLHDSALimits::N];
            hash.f(address, &secret[..P::N], &mut out[..P::N]);
            secret.zeroize();
            return out;
        }
        let left = SLHDSA::<P>::fors_node(sk_seed, 2 * index, height - 1, hash, address);
        let right = SLHDSA::<P>::fors_node(sk_seed, 2 * index + 1, height - 1, hash, address);
        address.set_tree_height(height);
        address.set_tree_index(index);
        SLHDSA::<P>::parent(&left[..P::N], &right[..P::N], hash, address)
    }

    /// fors_sign (algorithm 16) of the digest `md` into `out` of k (1 + a) n bytes.
    pub fn fors_sign(md: &[u8], sk_seed: &[u8], hash: &P::Hash, address: &mut SLHDSAAddress, out: &mut [u8]) {
        let mut indices = [0u32; SLHDSALimits::K];
        SLHDSA::<P>::base_2b(md, P::A, &mut indices[..P::K]);
        for (tree, part) in out.chunks_exact_mut((1 + P::A) * P::N).take(P::K).enumerate() {
            let base = (tree as u32) << P::A;
            let (secret, authentication) = part.split_at_mut(P::N);
            let mut value = SLHDSA::<P>::fors_sk_gen(sk_seed, hash, address, base + indices[tree]);
            secret.copy_from_slice(&value[..P::N]);
            value.zeroize();
            for (height, node) in authentication.chunks_exact_mut(P::N).enumerate() {
                let sibling = (indices[tree] >> height) ^ 1;
                let index = ((tree as u32) << (P::A - height)) + sibling;
                node.copy_from_slice(&SLHDSA::<P>::fors_node(sk_seed, index, height as u32, hash, address)[..P::N]);
            }
        }
    }

    /// fors_pkFromSig (algorithm 17).
    pub fn fors_pk_from_sig(
        signature: &[u8],
        md: &[u8],
        hash: &P::Hash,
        address: &mut SLHDSAAddress,
    ) -> [u8; SLHDSALimits::N] {
        let mut indices = [0u32; SLHDSALimits::K];
        SLHDSA::<P>::base_2b(md, P::A, &mut indices[..P::K]);
        let mut roots = [0u8; SLHDSALimits::FORS_ROOTS];
        let parts = signature.chunks_exact((1 + P::A) * P::N).zip(roots.chunks_exact_mut(P::N)).take(P::K);
        for (tree, (part, root)) in parts.enumerate() {
            let (secret, authentication) = part.split_at(P::N);
            let index = ((tree as u32) << P::A) + indices[tree];
            address.set_tree_height(0);
            address.set_tree_index(index);
            let mut leaf = [0u8; SLHDSALimits::N];
            hash.f(address, secret, &mut leaf[..P::N]);
            let node = SLHDSA::<P>::root_from_path(&leaf[..P::N], indices[tree], authentication, hash, address);
            root.copy_from_slice(&node[..P::N]);
        }
        let mut roots_address = *address;
        roots_address.set_type_and_clear(SLHDSAAddress::FORS_ROOTS);
        roots_address.set_key_pair_address(address.key_pair_address());
        let mut out = [0u8; SLHDSALimits::N];
        hash.t(&roots_address, &roots[..P::K * P::N], &mut out[..P::N]);
        out
    }

    /// slh_keygen_internal (algorithm 18) of SK.seed, SK.prf and PK.seed (n bytes each).
    pub fn key_gen_internal(sk_seed: &[u8], sk_prf: &[u8], pk_seed: &[u8]) -> Result<SLHDSASigningKey<P>, CryptoError> {
        if sk_seed.len() != P::N || sk_prf.len() != P::N || pk_seed.len() != P::N {
            return Err(CryptoError::InvalidKey);
        }
        let hash = P::Hash::new(pk_seed);
        let mut address = SLHDSAAddress::new();
        address.set_layer_address(P::D as u32 - 1);
        let root = SLHDSA::<P>::xmss_node(sk_seed, 0, P::HP as u32, &hash, &mut address);
        Ok(SLHDSASigningKey::new(sk_seed, sk_prf, SLHDSAVerifyingKey::new(pk_seed, &root[..P::N])))
    }

    /// The private key SK.seed || SK.prf || PK.seed || PK.root of 4 n bytes,
    /// checked by regenerating PK.root (FIPS 205 section 3.1); fails with
    /// `InvalidKey` for another length or another root.
    pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SLHDSASigningKey<P>, CryptoError> {
        if bytes.len() != P::PRIVATE_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }
        let n = P::N;
        let key = SLHDSA::<P>::key_gen_internal(&bytes[..n], &bytes[n..2 * n], &bytes[2 * n..3 * n])?;
        if !key.has_root(&bytes[3 * n..]) {
            return Err(CryptoError::InvalidKey);
        }
        Ok(key)
    }

    /// The FORS digest md, the tree and the leaf of H_msg's digest (algorithm 19 lines 6 to 10).
    pub fn split_digest(digest: &[u8]) -> (&[u8], u64, u32) {
        let (md, rest) = digest.split_at(P::MD_SIZE);
        let (tree_bytes, leaf_bytes) = rest.split_at(P::TREE_SIZE);
        let tree_bits = P::H - P::HP;
        let tree = tree_bytes.iter().fold(0u64, |total, byte| (total << 8) | *byte as u64);
        let tree = if tree_bits >= 64 { tree } else { tree & ((1u64 << tree_bits) - 1) };
        let leaf = leaf_bytes.iter().fold(0u32, |total, byte| (total << 8) | *byte as u32) & ((1 << P::HP) - 1);
        (md, tree, leaf)
    }

    /// slh_sign_internal (algorithm 19) of M' = the concatenation of
    /// `message`, with opt_rand = `additional` (n bytes) or PK.seed for the
    /// deterministic variant, into `out` of the bytes of a signature.
    pub fn sign_internal(
        key: &SLHDSASigningKey<P>,
        message: &[&[u8]],
        additional: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        if out.len() != P::SIGNATURE_SIZE {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        let verifying = key.verifying_key();
        let opt_rand = additional.unwrap_or(verifying.pk_seed());
        if opt_rand.len() != P::N {
            return Err(CryptoError::InvalidParameter);
        }
        let hash = P::Hash::new(verifying.pk_seed());
        let (r, rest) = out.split_at_mut(P::N);
        P::Hash::prf_msg(key.sk_prf(), opt_rand, message, r);
        let mut digest = [0u8; SLHDSALimits::M];
        let digest = &mut digest[..P::M];
        P::Hash::h_msg(r, verifying.pk_seed(), verifying.pk_root(), message, digest);
        let (md, tree, leaf) = SLHDSA::<P>::split_digest(digest);
        let mut address = SLHDSAAddress::new();
        address.set_tree_address(tree);
        address.set_type_and_clear(SLHDSAAddress::FORS_TREE);
        address.set_key_pair_address(leaf);
        let (fors, hypertree) = rest.split_at_mut(P::FORS_SIGNATURE_SIZE);
        SLHDSA::<P>::fors_sign(md, key.sk_seed(), &hash, &mut address, fors);
        let fors_key = SLHDSA::<P>::fors_pk_from_sig(fors, md, &hash, &mut address);
        SLHDSA::<P>::ht_sign(&fors_key[..P::N], key.sk_seed(), &hash, tree, leaf, hypertree);
        Ok(())
    }

    /// slh_verify_internal (algorithm 20) of M' = the concatenation of
    /// `message`; fails with `InvalidSignature` for a signature that is not one of M'.
    pub fn verify_internal(
        key: &SLHDSAVerifyingKey<P>,
        message: &[&[u8]],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if signature.len() != P::SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        let hash = P::Hash::new(key.pk_seed());
        let (r, rest) = signature.split_at(P::N);
        let (fors, hypertree) = rest.split_at(P::FORS_SIGNATURE_SIZE);
        let mut digest = [0u8; SLHDSALimits::M];
        let digest = &mut digest[..P::M];
        P::Hash::h_msg(r, key.pk_seed(), key.pk_root(), message, digest);
        let (md, tree, leaf) = SLHDSA::<P>::split_digest(digest);
        let mut address = SLHDSAAddress::new();
        address.set_tree_address(tree);
        address.set_type_and_clear(SLHDSAAddress::FORS_TREE);
        address.set_key_pair_address(leaf);
        let fors_key = SLHDSA::<P>::fors_pk_from_sig(fors, md, &hash, &mut address);
        if !SLHDSA::<P>::ht_verify(&fors_key[..P::N], hypertree, &hash, tree, leaf, key.pk_root()) {
            return Err(CryptoError::InvalidSignature);
        }
        Ok(())
    }

    /// The first bytes of M' for the domain separator (0 for SLH-DSA, 1 for
    /// HashSLH-DSA) and the context; fails with `InvalidParameter` for a
    /// context of more than 255 bytes.
    pub fn prefix(domain: u8, context: &[u8]) -> Result<[u8; 2], CryptoError> {
        let length = u8::try_from(context.len()).map_err(|_| CryptoError::InvalidParameter)?;
        Ok([domain, length])
    }

    /// slh_sign (algorithm 22) of `message` with `context` and addrnd from `random`.
    pub fn sign_with_context<R: Random>(
        key: &SLHDSASigningKey<P>,
        message: &[u8],
        context: &[u8],
        random: &mut R,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let prefix = SLHDSA::<P>::prefix(0, context)?;
        let mut additional = [0u8; SLHDSALimits::N];
        random.fill(&mut additional[..P::N]).map_err(|_| CryptoError::RandomFailed)?;
        let result = SLHDSA::<P>::sign_internal(key, &[&prefix, context, message], Some(&additional[..P::N]), out);
        additional.zeroize();
        result
    }

    /// The deterministic variant of slh_sign: opt_rand = PK.seed.
    pub fn sign_deterministic_with_context(
        key: &SLHDSASigningKey<P>,
        message: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let prefix = SLHDSA::<P>::prefix(0, context)?;
        SLHDSA::<P>::sign_internal(key, &[&prefix, context, message], None, out)
    }

    /// slh_verify (algorithm 24); fails with `InvalidParameter` for a
    /// context of more than 255 bytes and `InvalidSignature` for a
    /// signature that is not one of `message` with `context`.
    pub fn verify_with_context(
        key: &SLHDSAVerifyingKey<P>,
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let prefix = SLHDSA::<P>::prefix(0, context)?;
        SLHDSA::<P>::verify_internal(key, &[&prefix, context, message], signature)
    }

    /// hash_slh_sign (algorithm 23) with the pre-hash `H`, opt_rand =
    /// `additional` (n bytes) or PK.seed for the deterministic variant.
    pub fn sign_pre_hash_with_additional<H: PreHash>(
        key: &SLHDSASigningKey<P>,
        message: &[u8],
        context: &[u8],
        additional: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let prefix = SLHDSA::<P>::prefix(1, context)?;
        let mut digest = [0u8; 64];
        H::pre_hash(message, &mut digest[..H::OUTPUT_SIZE]);
        SLHDSA::<P>::sign_internal(key, &[&prefix, context, H::OID, &digest[..H::OUTPUT_SIZE]], additional, out)
    }

    /// hash_slh_sign (algorithm 23) with the pre-hash `H` and addrnd from `random`.
    pub fn sign_pre_hash<H: PreHash, R: Random>(
        key: &SLHDSASigningKey<P>,
        message: &[u8],
        context: &[u8],
        random: &mut R,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        let mut additional = [0u8; SLHDSALimits::N];
        random.fill(&mut additional[..P::N]).map_err(|_| CryptoError::RandomFailed)?;
        let result =
            SLHDSA::<P>::sign_pre_hash_with_additional::<H>(key, message, context, Some(&additional[..P::N]), out);
        additional.zeroize();
        result
    }

    /// The deterministic variant of hash_slh_sign.
    pub fn sign_pre_hash_deterministic<H: PreHash>(
        key: &SLHDSASigningKey<P>,
        message: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        SLHDSA::<P>::sign_pre_hash_with_additional::<H>(key, message, context, None, out)
    }

    /// hash_slh_verify (algorithm 25) with the pre-hash `H`.
    pub fn verify_pre_hash<H: PreHash>(
        key: &SLHDSAVerifyingKey<P>,
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let prefix = SLHDSA::<P>::prefix(1, context)?;
        let mut digest = [0u8; 64];
        H::pre_hash(message, &mut digest[..H::OUTPUT_SIZE]);
        SLHDSA::<P>::verify_internal(key, &[&prefix, context, H::OID, &digest[..H::OUTPUT_SIZE]], signature)
    }
}

impl<P: SLHDSAParameters> SignatureScheme for SLHDSA<P> {
    type SigningKey = SLHDSASigningKey<P>;
    type VerifyingKey = SLHDSAVerifyingKey<P>;
    const SIGNING_KEY_SIZE: usize = P::PRIVATE_KEY_SIZE;
    const VERIFYING_KEY_SIZE: usize = P::PUBLIC_KEY_SIZE;
    const SIGNATURE_SIZE: usize = P::SIGNATURE_SIZE;

    /// slh_keygen (algorithm 21): SK.seed, SK.prf and PK.seed from `random`.
    fn generate<R: Random>(random: &mut R) -> Result<SLHDSASigningKey<P>, CryptoError> {
        let mut seeds = [0u8; 3 * SLHDSALimits::N];
        let seeds = &mut seeds[..3 * P::N];
        let result = random.fill(seeds).map_err(|_| CryptoError::RandomFailed);
        let key = result
            .and_then(|_| SLHDSA::<P>::key_gen_internal(&seeds[..P::N], &seeds[P::N..2 * P::N], &seeds[2 * P::N..]));
        seeds.zeroize();
        key
    }

    fn signing_key_from_bytes(bytes: &[u8]) -> Result<SLHDSASigningKey<P>, CryptoError> {
        SLHDSA::<P>::signing_key_from_bytes(bytes)
    }

    fn write_signing_key(key: &SLHDSASigningKey<P>, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != P::PRIVATE_KEY_SIZE {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        key.write_bytes(out);
        Ok(())
    }

    fn verifying_key(key: &SLHDSASigningKey<P>) -> SLHDSAVerifyingKey<P> {
        key.verifying_key().clone()
    }

    fn verifying_key_from_bytes(bytes: &[u8]) -> Result<SLHDSAVerifyingKey<P>, CryptoError> {
        SLHDSAVerifyingKey::from_bytes(bytes)
    }

    fn write_verifying_key(key: &SLHDSAVerifyingKey<P>, out: &mut [u8]) -> Result<(), CryptoError> {
        if out.len() != P::PUBLIC_KEY_SIZE {
            return Err(CryptoError::InputLength { length: out.len() });
        }
        key.write_bytes(out);
        Ok(())
    }

    /// The deterministic slh_sign with the empty context.
    fn sign(key: &SLHDSASigningKey<P>, message: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        SLHDSA::<P>::sign_deterministic_with_context(key, message, &[], out)
    }

    /// slh_verify with the empty context.
    fn verify(key: &SLHDSAVerifyingKey<P>, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        SLHDSA::<P>::verify_with_context(key, message, &[], signature)
    }
}
