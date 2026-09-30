use anyhow::{anyhow, bail, Result};

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 96;
pub const MAX_SIGNATURE_LEN: usize = 3_680;
const ERROR_LEN: usize = 256;

unsafe extern "C" {
    fn ssw_shrincs_keygen(
        public_key: *mut u8,
        secret_key: *mut u8,
        q: *mut u32,
        valid: *mut u8,
        error: *mut i8,
        error_len: usize,
    ) -> i32;
    fn ssw_shrincs_sign_stateful(
        message: *const u8,
        message_len: usize,
        secret_key: *const u8,
        q: *mut u32,
        valid: *mut u8,
        signature: *mut u8,
        signature_capacity: usize,
        signature_len: *mut usize,
        error: *mut i8,
        error_len: usize,
    ) -> i32;
    fn ssw_shrincs_sign_stateless(
        message: *const u8,
        message_len: usize,
        secret_key: *const u8,
        signature: *mut u8,
        signature_capacity: usize,
        signature_len: *mut usize,
        error: *mut i8,
        error_len: usize,
    ) -> i32;
    fn ssw_shrincs_verify(
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        public_key: *const u8,
        error: *mut i8,
        error_len: usize,
    ) -> i32;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub public_key: [u8; PUBLIC_KEY_LEN],
    pub secret_key: [u8; SECRET_KEY_LEN],
    pub state: SigningState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningState {
    pub q: u32,
    pub valid: bool,
}

pub fn keygen() -> Result<KeyPair> {
    let mut public_key = [0_u8; PUBLIC_KEY_LEN];
    let mut secret_key = [0_u8; SECRET_KEY_LEN];
    let mut q = 0_u32;
    let mut valid = 0_u8;
    let mut error = [0_i8; ERROR_LEN];
    // SAFETY: Every pointer references a writable buffer of the declared fixed size.
    let status = unsafe {
        ssw_shrincs_keygen(
            public_key.as_mut_ptr(),
            secret_key.as_mut_ptr(),
            &mut q,
            &mut valid,
            error.as_mut_ptr(),
            error.len(),
        )
    };
    check_status(status, &error)?;
    Ok(KeyPair {
        public_key,
        secret_key,
        state: SigningState {
            q,
            valid: valid != 0,
        },
    })
}

pub fn sign_stateful(
    message: &[u8],
    secret_key: &[u8; SECRET_KEY_LEN],
    state: &mut SigningState,
) -> Result<Vec<u8>> {
    let mut signature = vec![0_u8; MAX_SIGNATURE_LEN];
    let mut signature_len = 0_usize;
    let mut valid = u8::from(state.valid);
    let mut error = [0_i8; ERROR_LEN];
    // SAFETY: Inputs are valid for their lengths and all output pointers reference live buffers.
    let status = unsafe {
        ssw_shrincs_sign_stateful(
            message.as_ptr(),
            message.len(),
            secret_key.as_ptr(),
            &mut state.q,
            &mut valid,
            signature.as_mut_ptr(),
            signature.len(),
            &mut signature_len,
            error.as_mut_ptr(),
            error.len(),
        )
    };
    check_status(status, &error)?;
    state.valid = valid != 0;
    signature.truncate(signature_len);
    Ok(signature)
}

pub fn sign_stateless(message: &[u8], secret_key: &[u8; SECRET_KEY_LEN]) -> Result<Vec<u8>> {
    let mut signature = vec![0_u8; MAX_SIGNATURE_LEN];
    let mut signature_len = 0_usize;
    let mut error = [0_i8; ERROR_LEN];
    // SAFETY: Inputs are valid for their lengths and all output pointers reference live buffers.
    let status = unsafe {
        ssw_shrincs_sign_stateless(
            message.as_ptr(),
            message.len(),
            secret_key.as_ptr(),
            signature.as_mut_ptr(),
            signature.len(),
            &mut signature_len,
            error.as_mut_ptr(),
            error.len(),
        )
    };
    check_status(status, &error)?;
    signature.truncate(signature_len);
    Ok(signature)
}

pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8; PUBLIC_KEY_LEN]) -> Result<bool> {
    let mut error = [0_i8; ERROR_LEN];
    // SAFETY: All pointers reference immutable buffers valid for the supplied lengths.
    let status = unsafe {
        ssw_shrincs_verify(
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
            public_key.as_ptr(),
            error.as_mut_ptr(),
            error.len(),
        )
    };
    match status {
        0 => Ok(true),
        2 => Ok(false),
        _ => {
            check_status(status, &error)?;
            unreachable!()
        }
    }
}

fn check_status(status: i32, error: &[i8; ERROR_LEN]) -> Result<()> {
    if status == 0 {
        return Ok(());
    }
    let bytes = error
        .iter()
        .copied()
        .take_while(|byte| *byte != 0)
        .map(|byte| byte as u8)
        .collect::<Vec<_>>();
    if bytes.is_empty() {
        bail!("SHRINCS native operation failed with status {status}");
    }
    Err(anyhow!(String::from_utf8_lossy(&bytes).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stateful_signature_round_trip_and_message_binding() {
        let mut key_pair = keygen().unwrap();
        let signature = sign_stateful(
            b"transaction one",
            &key_pair.secret_key,
            &mut key_pair.state,
        )
        .unwrap();

        assert!(verify(b"transaction one", &signature, &key_pair.public_key).unwrap());
        assert!(!verify(b"transaction two", &signature, &key_pair.public_key).unwrap());
        assert_eq!(key_pair.state.q, 1);
    }

    #[test]
    fn stateless_signature_round_trip() {
        let key_pair = keygen().unwrap();
        let signature = sign_stateless(b"recovery transaction", &key_pair.secret_key).unwrap();

        assert!(verify(b"recovery transaction", &signature, &key_pair.public_key).unwrap());
    }
    #[test]
    fn malformed_signature_lengths_are_rejected() {
        let key_pair = keygen().unwrap();
        for length in [0, 15, 16, 307, 309, MAX_SIGNATURE_LEN - 1] {
            assert!(!verify(b"message", &vec![0; length], &key_pair.public_key).unwrap());
        }
    }
}
