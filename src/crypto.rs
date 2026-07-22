/*Modul kryptograficzny do projektu. Na poczatku pojedyczne atomowe funkcje, a potem funkcje wyzszego poziomu, które lacza te atomowe. 
Sa one juz do uzycia w kodzie sterujacym*/

use rand::rngs::OsRng; //taka akcja ze to korzysta z generatora systemu operacyjnego
use rand::RngCore; 
use argon2::{
    Argon2,
    Algorithm,
    Version,
    Params,
};
use hkdf::Hkdf;
use sha2::Sha256;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;
use zeroize::Zeroizing; // Zeroizing to wrapped, ktory automatycznie zeruje wartosc, gdy wyjdzie poza zakres w porownaniu do zeroize, gdzie trzeba to robic recznie
use subtle::ConstantTimeEq; //do porownywania, zeby uniknac atakow timingowych

/* Ponizszy element zaklada ze moga nastapic ponizsze bledy. derive debug jest po to, by na poziomie testowym sprawdzic, ktory element wywolal blad */
#[derive(Debug)]
pub enum CryptoError {
    InvalidArgon2Params,
    Argon2Failed,
    HkdfExpandFailed,
    AeadEncryptFailed,
    HmacKeyFailed,
    ERR_BAD_PASSWORD_OR_CORRUPTED,
}
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
}
//stale sa po to by wygodnie nazwac info w funkcjach
//const CONTEXT: &[u8] = b"vault-v1";
const HKDF_INFO_WRAP_DEK_KEY: &[u8] = b"vault-v1wrap-dek-key";
const HKDF_INFO_HEADER_MAC: &[u8] = b"vault-v1header-mac";
const AAD_WRAP_DEK: &[u8] = b"vault-v1wrap-dek";

//MINI FUNKCJE//
fn salt_generator() -> [u8; 16] { //zwraca tablicę 16 bajtów (u8 to liczba 0-255)
    let mut salt_a2 = [0u8; 16]; //na razie ustawiamy każdy na 0
    OsRng.fill_bytes(&mut salt_a2); //salt_a2 zostaje nadpisany
    salt_a2
}
//dek zerowany
fn dek_generator() -> Zeroizing<[u8; 32]> { 
    let mut dek = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(dek.as_mut());
    dek
}

fn derive_master_key(password: &[u8], salt_a2: &[u8; 16], kdf_params: &KdfParams) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let params = Params::new(
        kdf_params.memory,
        kdf_params.iterations,
        kdf_params.parallelism,
        Some(32)).map_err(|_| CryptoError::InvalidArgon2Params)?;
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    );
    let mut master_key = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(password, salt_a2, master_key.as_mut()) .map_err(|_| CryptoError::Argon2Failed)?;//mapowanie bledu w tym miejscu na element z CryptoError
    Ok(master_key)
}

fn create_wrap_key(master_key: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut wrap_key = Zeroizing::new([0u8; 32]);

    hkdf.expand(HKDF_INFO_WRAP_DEK_KEY, wrap_key.as_mut()) //czemu as.mut() a nie &mut? expand wymaga &mut [u8], a wrap_key jest Zeroizing<[u8; 32]>, wiec as_mut() zwraca &mut [u8; 32], ktory jest zgodny z wymaganiami expand
        .map_err(|_| CryptoError::HkdfExpandFailed)?;

    Ok(wrap_key)    
}

fn create_header_key(master_key: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut header_mac_key = Zeroizing::new([0u8; 32]);

    hkdf.expand(HKDF_INFO_HEADER_MAC,header_mac_key.as_mut())
        .map_err(|_| CryptoError::HkdfExpandFailed)?;

    Ok(header_mac_key)
}

// funkcja dla nonce_body i nonce_dek
fn nonce_generator() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn wrapped_dek_generator(
    wrap_key: &[u8],
    dek: &[u8],
) -> Result<([u8; 12], Vec<u8>), CryptoError> {
    let nonce_dek = nonce_generator();
   let cipher = ChaCha20Poly1305::new_from_slice(wrap_key)
    .map_err(|_| CryptoError::AeadEncryptFailed)?;
    let wrapped_dek = cipher.encrypt(
        Nonce::from_slice(&nonce_dek),
        Payload {
            msg: dek, //szyfruj dek
            aad: AAD_WRAP_DEK, //uwierzytelnij dodatkowe dane, ktore sa stale, zeby bylo wiadomo, ze to jest wrap dek, a nie cos innego
        },
    ).map_err(|_| CryptoError::AeadEncryptFailed)?;

    Ok((nonce_dek, wrapped_dek))
}
fn header_mac_generator(
    header_mac_key: &[u8; 32],
    canonical_header: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(header_mac_key)
        .map_err(|_| CryptoError::HmacKeyFailed)?;

    mac.update(canonical_header);

    let result = mac.finalize();
    let bytes = result.into_bytes();

    let mut header_mac = [0u8; 32];
    header_mac.copy_from_slice(&bytes);

    Ok(header_mac)
}

fn ct_body_generator(dek: &[u8], body: &[u8], canonical_header: &[u8], header_mac: &[u8; 32],) -> Result<([u8; 12], Vec<u8>), CryptoError> {
    let nonce_body = nonce_generator();
    let cipher = ChaCha20Poly1305::new_from_slice(dek)
        .map_err(|_| CryptoError::AeadEncryptFailed)?;
    let mut aad = Vec::new();
    aad.extend_from_slice(canonical_header);
    aad.extend_from_slice(header_mac);
    let ct_body = cipher.encrypt(
        Nonce::from_slice(&nonce_body), //wez bajty nonce_body i stworz z nich Nonce, ktory jest wymagany przez funkcje encrypt
        Payload {
            msg: body,
            aad: &aad,
        },
    ).map_err(|_| CryptoError::AeadEncryptFailed)?;
    Ok((nonce_body, ct_body))
}

pub struct InitCryptoFirst {
    pub salt: [u8; 16],
    pub dek: Zeroizing<[u8; 32]>,
    pub nonce_dek: [u8; 12],
    pub wrapped_dek: Vec<u8>,
    pub header_mac_key: Zeroizing<[u8; 32]>,
}

pub fn initcryptofirst(password: &[u8]) -> Result<InitCryptoFirst, CryptoError> {
    let salt = salt_generator();
    let dek = dek_generator();

    let master_key = derive_master_key(password, &salt, &KdfParams { memory: 64 * 1024, iterations: 3, parallelism: 1 })?;
    let wrap_key = create_wrap_key(master_key.as_ref())?;
    let header_mac_key = create_header_key(master_key.as_ref())?;

    let (nonce_dek, wrapped_dek) =
        wrapped_dek_generator(wrap_key.as_ref(), dek.as_ref())?;

    Ok(InitCryptoFirst {
        salt,
        dek,
        header_mac_key,
        nonce_dek,
        wrapped_dek,
    })
}

pub struct InitCryptoSecond {                 
    pub header_mac: [u8; 32],
    pub nonce_body: [u8; 12],
    pub ct_body: Vec<u8>,
}

pub fn initcryptosecond(
    dek: &[u8],
    header_mac_key: &[u8; 32],
    canonical_header: &[u8],
    body: &[u8],
) -> Result<InitCryptoSecond, CryptoError> {
    let header_mac = header_mac_generator(header_mac_key, canonical_header)?;
    let (nonce_body, ct_body) = ct_body_generator(dek, body, canonical_header, &header_mac)?;

    Ok(InitCryptoSecond {
        header_mac,
        nonce_body,
        ct_body,
    })
}


// dalsza czesc mini funkcji - teraz do vault open

/*1. punkt dla Stasiaka, sparsowanie naglowka da nam wazne dane do uwierzytelnienia */
//2. wczytanie hasla
//3. derive_master_key
//4. create_wrap_key
//5. create_header_key
//6. header_mac_generator

fn verify_header_mac(       // tutaj porownanie macow przez ConstantTimeEq, zeby uniknac atakow timingowych
    expected_mac: &[u8; 32],
    header_mac: &[u8; 32],
) -> Result<(), CryptoError> {
    if expected_mac.ct_eq(header_mac).into() {
        Ok(())
    } else {
        Err(CryptoError::ERR_BAD_PASSWORD_OR_CORRUPTED)
    }
}


fn unwrap_dek(          //deszyfracja dek, jesli sie nie uda, to znaczy ze haslo jest zle albo dane sa uszkodzone
    wrap_key: &[u8],
    nonce_dek: &[u8; 12],
    wrapped_dek: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(wrap_key)
        .map_err(|_| CryptoError::ERR_BAD_PASSWORD_OR_CORRUPTED)?;

    let dek_vec = Zeroizing::new(
    cipher.decrypt(
        Nonce::from_slice(nonce_dek),
        Payload {
            msg: wrapped_dek,
            aad: AAD_WRAP_DEK,
        },
    ).map_err(|_| CryptoError::ERR_BAD_PASSWORD_OR_CORRUPTED)?
);

if dek_vec.len() != 32 {
    return Err(CryptoError::ERR_BAD_PASSWORD_OR_CORRUPTED);
}

let mut dek = Zeroizing::new([0u8; 32]);
dek.as_mut().copy_from_slice(&dek_vec);

Ok(dek)
}

fn decrypt_body(    //deszyfracja ciala, jesli sie nie uda, to znaczy ze haslo jest zle albo dane sa uszkodzone
    dek: &[u8],     
    nonce_body: &[u8; 12],
    ct_body: &[u8],
    canonical_header: &[u8],
    header_mac: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(dek)
        .map_err(|_| CryptoError::ERR_BAD_PASSWORD_OR_CORRUPTED)?;

    let mut aad = Vec::new();
    aad.extend_from_slice(canonical_header);
    aad.extend_from_slice(header_mac);

    cipher.decrypt(
        Nonce::from_slice(nonce_body),
        Payload {
            msg: ct_body,
            aad: &aad,
        },
    ).map_err(|_| CryptoError::ERR_BAD_PASSWORD_OR_CORRUPTED)
}

//struktura, ktora zawiera dek i odszyfrowane body, zeby zwrocic to z funkcji opencrypto
pub struct OpenCrypto {
    pub dek: Zeroizing<[u8; 32]>,
    pub body: Vec<u8>,
}

pub fn opencrypto(
    password: &[u8],
    salt: &[u8; 16],
    canonical_header: &[u8],
    header_mac: &[u8; 32],
    nonce_dek: &[u8; 12],
    wrapped_dek: &[u8],
    nonce_body: &[u8; 12],
    ct_body: &[u8],
    kdf_params: &KdfParams,
) -> Result<OpenCrypto, CryptoError> {
    let master_key = derive_master_key(password, &salt, kdf_params)?;
    let wrap_key = create_wrap_key(master_key.as_ref())?;
    let header_mac_key = create_header_key(master_key.as_ref())?;
    let expected_mac = header_mac_generator(&header_mac_key, canonical_header)?;
    verify_header_mac(&expected_mac, header_mac)?;
    let dek = unwrap_dek(wrap_key.as_ref(), nonce_dek, wrapped_dek)?;
    let body = decrypt_body(dek.as_ref(), nonce_body, ct_body, canonical_header, header_mac)?;

    Ok(OpenCrypto { dek, body })
}

pub struct SaveCrypto {
    pub nonce_body: [u8; 12],
    pub ct_body: Vec<u8>,
}

// Funkcja nadpisujaca vault przy zmianie body
pub fn savecrypto(
    dek: &[u8],
    canonical_header: &[u8],
    header_mac: &[u8; 32],
    body: &[u8],
) -> Result<SaveCrypto, CryptoError> {
    let (nonce_body, ct_body) = ct_body_generator(dek, body, canonical_header, header_mac)?;
    Ok(SaveCrypto { nonce_body, ct_body })
}

// Funkcja do verify with password
pub fn verifycrypto (
    password: &[u8],
    salt: &[u8; 16],
    canonical_header: &[u8],
    header_mac: &[u8; 32],
    nonce_dek: &[u8; 12],
    wrapped_dek: &[u8],
    kdf_params: &KdfParams,
) -> Result<(), CryptoError> {
    let master_key = derive_master_key(password, salt, kdf_params)?;
    let wrap_key = create_wrap_key(master_key.as_ref())?;
    let header_mac_key = create_header_key(master_key.as_ref())?;
    let expected_mac = header_mac_generator(&header_mac_key, canonical_header)?;
    verify_header_mac(&expected_mac, header_mac)?;
    let _dek = unwrap_dek(wrap_key.as_ref(), nonce_dek, wrapped_dek)?;
    Ok(())
}

pub struct ChangeCrypto {
    pub salt: [u8; 16],
    pub nonce_dek: [u8; 12],
    pub wrapped_dek: Vec<u8>,
    pub dek: Zeroizing<[u8; 32]>,
    pub header_mac_key: Zeroizing<[u8; 32]>,
}

pub fn changecryptofirst(
    old_password: &[u8],
    new_password: &[u8],
    old_salt: &[u8; 16],
    canonical_header_old: &[u8],
    old_header_mac: &[u8; 32],
    nonce_dek: &[u8; 12],
    wrapped_dek: &[u8],
    old_kdf_params: &KdfParams,
    new_kdf_params: &KdfParams,
) -> Result<ChangeCrypto, CryptoError> {
    let old_master_key = derive_master_key(old_password, old_salt, old_kdf_params)?;
    let old_wrap_key = create_wrap_key(old_master_key.as_ref())?;
    let old_header_mac_key = create_header_key(old_master_key.as_ref())?;
    let expected_mac = header_mac_generator(&old_header_mac_key, canonical_header_old)?;
    verify_header_mac(&expected_mac, old_header_mac)?;
    let dek = unwrap_dek(old_wrap_key.as_ref(), nonce_dek, wrapped_dek)?;

    let new_salt = salt_generator();
    let new_master_key = derive_master_key(new_password, &new_salt, new_kdf_params)?;
    let new_wrap_key = create_wrap_key(new_master_key.as_ref())?;
    let new_header_mac_key = create_header_key(new_master_key.as_ref())?;
    let (new_nonce_dek, new_wrapped_dek) =
        wrapped_dek_generator(new_wrap_key.as_ref(), dek.as_ref())?;

    Ok(ChangeCrypto {
    salt: new_salt,
    nonce_dek: new_nonce_dek,
    wrapped_dek: new_wrapped_dek,
    dek,
    header_mac_key: new_header_mac_key,
    })
}

//tu wchodzi czesc piotrka a zeby dokonczyc musi wywolac initcryptosecond bo to beda te same funkcje

pub fn upgradekdf(
    password: &[u8],
    old_salt: &[u8; 16],
    canonical_header_old: &[u8],
    old_header_mac: &[u8; 32],
    nonce_dek: &[u8; 12],
    wrapped_dek: &[u8],
    old_kdf_params: &KdfParams,
    new_kdf_params: &KdfParams,
) -> Result<ChangeCrypto, CryptoError> {
    changecryptofirst(
        password, password, old_salt, canonical_header_old,
        old_header_mac, nonce_dek, wrapped_dek,
        old_kdf_params, new_kdf_params,
    )
}
    
    

//TESTY RFC
#[cfg(test)]

mod rfc_tests{
    use super::*; // modul pozwala nam korzystac z funkcji i struktur zdefiniowanych w module crypto

    #[test]
    fn rfc9106_test(){
        let password = [0x01u8; 32];
        let salt = [0x02u8; 16];
        let kdf_params = KdfParams { memory: 32, iterations: 3, parallelism: 4};
        
        let test_master_key = derive_master_key(&password, &salt, &kdf_params).unwrap();

        let expected_key = [ 0x03, 0xaa, 0xb9, 0x65, 0xc1, 0x20, 0x01, 0xc9, 0xd7, 0xd0, 0xd2, 0xde, 0x33, 0x19, 0x2c, 0x04, 0x94, 0xb6, 0x84, 0xbb, 0x14, 0x81, 0x96, 0xd7, 0x3c, 0x1d, 0xf1, 0xac, 0xaf, 0x6d, 0x0c, 0x2e];
        // jest to klucz obliczony na podstawie danych z test vectora z RFC 9106, ktory jest dostepny pod adresem https://www.rfc-editor.org/rfc/rfc9106.html#section-4.2.1
        //nie korzystam z add i secretu, wiec wyjscie nie byloby zgodne z rfc, ale ten klucz zostal obliczony na podstawie soli, hasla i parametrow w oddzielnym programie w pythonie, ktory korzysta z biblioteki argon2, wiec jest zgodny z rfc

        assert_eq!(test_master_key.as_ref(), &expected_key);
    }
    #[test]
    fn rfc8439_test(){
        let key = [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                   0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
                   0x9e, 0x9f];
        let nonce = [0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
        let aad = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
        let plaintext = [0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
                         0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
                         0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 
                         0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
                         0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
                         0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
                         0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
                         0x74, 0x2e];


        let expected_ciphertext_and_tag = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,

        //dodatkowo tag poly1305
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ];

        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap(); //nie korzystam z funkcji wlasnej jak w powyzszym tescie dlatego, ze generowanie odpowiednich kluczy odbywa sie poprzez wykorzystanie tej funkcji, dlatego pozwalam sobie zrobic test rfc bezposrednio na niej
    
        let actual_ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .unwrap();

    assert_eq!(actual_ciphertext.as_slice(), expected_ciphertext_and_tag);
        }

        #[test]
        fn rfc4231_test_case1(){
            let key = [0x0b; 20];
            let data = [0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65];
            let expected_hmac = [0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                                  0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7];
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).unwrap();
            mac.update(&data);
            let actual_hmac = mac.finalize().into_bytes();
            assert_eq!(actual_hmac.as_slice(), expected_hmac);

        }
        #[test]
        fn rfc4231_test_case2(){
            let key = [0x4a, 0x65, 0x66, 0x65];
            let data = [0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20,
                        0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f];

            let expected_hmac = [0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
                                  0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43];
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).unwrap();
            mac.update(&data);
            let actual_hmac = mac.finalize().into_bytes();
            assert_eq!(actual_hmac.as_slice(), expected_hmac);

        }
        #[test]
        fn rfc4321_test_case3(){
            let key = [0xaa; 20];
            let data = [0xdd; 50];
            let expected_hmac = [0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe];

            let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).unwrap();
            mac.update(&data);
            let actual_hmac = mac.finalize().into_bytes();
            assert_eq!(actual_hmac.as_slice(), expected_hmac);
        }
        #[test]
        fn rfc4321_test_case4(){
            let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                       0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19];
            let data = [0xcd; 50];
            let expected_hmac = [0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a,
                                  0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b];
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).unwrap();
            mac.update(&data);
            let actual_hmac = mac.finalize().into_bytes();
            assert_eq!(actual_hmac.as_slice(), expected_hmac);
        }
        //dla hdkf testujemy dwa case'y, bo pierwszy zaklada istnienie salta i info, a drugi zaklada brak salta i info, wiec testujemy oba przypadki, zeby miec pewnosc, ze funkcja dziala poprawnie w obu sytuacjach
        //w naszym kodzie korzystamy tylko z info
        #[test]
        fn rfc5869_test_case1(){ //podobne sytuacje co powyzej. Testuje uzywane funkcje hkdf, ale nie korzystam z funkcji create_wrap_key, ktore maja juz szczegolowe dzialania
            let key = [0x0b; 22]; 
            let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
            let hkdf = Hkdf::<Sha256>::new(Some(&salt), &key);
            let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
            let expected_okm = [0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
                                  0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
                                  0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65];
            let mut actual_okm = [0u8; 42];
            hkdf.expand(&info, actual_okm.as_mut()).unwrap();
            assert_eq!(actual_okm.as_slice(), expected_okm);
        }
        
        #[test]
        fn rfc5869_test_case3(){ 
            let key = [0x0b; 22]; 
            let hkdf = Hkdf::<Sha256>::new(None, &key);

            let expected_okm = [0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
                                  0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
                                  0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8];
            let mut actual_okm = [0u8; 42];
            hkdf.expand(&[], actual_okm.as_mut()).unwrap();
            assert_eq!(actual_okm.as_slice(), expected_okm);
        }
    }


