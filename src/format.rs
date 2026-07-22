use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use std::fs::{File, rename};
use std::io::{Read, Write, Result as IoResult};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{initcryptofirst, initcryptosecond, opencrypto, KdfParams};

pub const CANONICAL_HEADER_SIZE: usize = 100;

// STRUKTURY DANYCH I FORMATU

pub struct VaultHeader {
    pub version: u16,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u8,
    pub salt: [u8; 16],
    pub nonce_dek: [u8; 12],
    pub wrapped_dek: [u8; 48],
}

impl VaultHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(CANONICAL_HEADER_SIZE);

        buf.extend_from_slice(b"VLT1");
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(&[0u8, 0u8]);
        buf.push(1);
        buf.extend_from_slice(&self.kdf_memory_kib.to_be_bytes());
        buf.extend_from_slice(&self.kdf_iterations.to_be_bytes());
        buf.push(self.kdf_parallelism);
        buf.push(16);
        buf.extend_from_slice(&self.salt);
        buf.push(1);
        buf.extend_from_slice(&self.nonce_dek);
        buf.extend_from_slice(&48u32.to_be_bytes());
        buf.extend_from_slice(&self.wrapped_dek);

        assert_eq!(buf.len(), CANONICAL_HEADER_SIZE, "Gwarancja kanoniczności: nagłówek musi mieć dokładnie 100B!");
        buf
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RecordType {
    Login,
    Note,
    Apikey,
    Totp,
    Sshkey,
    Attachment,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VaultBody {
    pub schema_version: u32,
    pub records: Vec<VaultRecord>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultRecord {
    pub id: [u8; 16],
    #[serde(rename = "type")]
    pub record_type: RecordType,
    pub title: String,
    pub tags: Vec<String>,
    pub notes: String,
    pub created_at: u64,
    pub modified_at: u64,
    pub fields: BTreeMap<String, Vec<u8>>,
}

pub fn serialize_body(body: &VaultBody) -> Vec<u8> {
    let mut buffer = Vec::new();
    ciborium::into_writer(body, &mut buffer).expect("Błąd krytyczny serializacji CBOR");
    buffer
}

// FUNKCJE POMOCNICZE (UUID I CZAS)

pub fn generate_uuid_v4() -> [u8; 16] {
    uuid::Uuid::new_v4().into_bytes()
}

pub fn current_time_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Błąd krytyczny pobierania czasu systemowego")
        .as_nanos() as u64
}

// ZAPIS BAZY

pub fn atomic_write(target_path: &Path, data: &[u8]) -> IoResult<()> {
    let temp_path = target_path.with_extension("tmp");
    let mut temp_file = File::create(&temp_path)?;

    temp_file.write_all(data)?;
    temp_file.sync_all()?;

    rename(&temp_path, target_path)?;
    Ok(())
}

pub fn save_vault(password: &[u8], body_data: &VaultBody, path: &Path) -> IoResult<()> {
    let crypto_first = initcryptofirst(password).map_err(|_| std::io::ErrorKind::PermissionDenied)?;

    let mut wrapped_dek_arr = [0u8; 48];
    wrapped_dek_arr.copy_from_slice(&crypto_first.wrapped_dek);

    let header = VaultHeader {
        version: 1,
        kdf_memory_kib: 64 * 1024,
        kdf_iterations: 3,
        kdf_parallelism: 1,
        salt: crypto_first.salt,
        nonce_dek: crypto_first.nonce_dek,
        wrapped_dek: wrapped_dek_arr,
    };
    let canonical_header = header.to_bytes();
    let raw_body = serialize_body(body_data);

    let crypto_second = initcryptosecond(
        crypto_first.dek.as_ref(),
        crypto_first.header_mac_key.as_ref().try_into().unwrap(),
        &canonical_header,
        &raw_body
    ).map_err(|_| std::io::ErrorKind::InvalidData)?;

    let mut final_file_bytes = Vec::new();
    final_file_bytes.extend_from_slice(&canonical_header);
    final_file_bytes.extend_from_slice(&crypto_second.header_mac);
    final_file_bytes.extend_from_slice(&crypto_second.nonce_body);
    final_file_bytes.extend_from_slice(&crypto_second.ct_body);

    atomic_write(path, &final_file_bytes)?;
    Ok(())
}

// ODCZYT BAZY

pub fn load_vault(password: &[u8], path: &Path) -> IoResult<VaultBody> {
    // wczytujemy cały plik do pamięci RAM jako ciąg bajtów
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    // minimum 144B: 100B nagłówek + 32B HMAC + 12B nonce_body
    if data.len() < 144 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Plik jest zbyt krótki."));
    }

    // wycinamy kanoniczny nagłówek i sprawdzamy magiczne bajty
    let canonical_header = &data[0..100];
    if &canonical_header[0..4] != b"VLT1" {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Nieobsługiwany format pliku (brak VLT1)."));
    }

    // rozpakowujemy parametry z nagłówka bajt po bajcie
    let memory_kib = u32::from_be_bytes(canonical_header[9..13].try_into().unwrap());
    let iterations = u32::from_be_bytes(canonical_header[13..17].try_into().unwrap());
    let parallelism = canonical_header[17] as u32;

    let kdf_params = KdfParams {
        memory: memory_kib,
        iterations,
        parallelism,
    };

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&canonical_header[19..35]);

    let mut nonce_dek = [0u8; 12];
    nonce_dek.copy_from_slice(&canonical_header[36..48]);

    let wrapped_dek = &canonical_header[52..100]; // wycinek &[u8]

    // wycinamy HMAC i nonce dla ciała bazy
    let mut header_mac = [0u8; 32];
    header_mac.copy_from_slice(&data[100..132]);

    let mut nonce_body = [0u8; 12];
    nonce_body.copy_from_slice(&data[132..144]);

    // reszta pliku to szyfrogram
    let ct_body = &data[144..];

    let open_result = opencrypto(
        password,
        &salt,
        canonical_header,
        &header_mac,
        &nonce_dek,
        wrapped_dek,
        &nonce_body,
        ct_body,
        &kdf_params,
    ).map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("Błąd deszyfrowania: {:?}", e)))?;

    // odtwarzamy strukturę ze zdeszyfrowanych bajtów używając CBOR
    let body: VaultBody = ciborium::from_reader(open_result.body.as_slice())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Odszyfrowano, ale struktura danych jest uszkodzona."))?;

    Ok(body)
}

// WERYFIKACJA STRUKTURALNA (BEZ HASŁA)

// lista możliwych błędów strukturalnych pliku
#[derive(Debug, PartialEq)]
pub enum VerifyError {
    FileTooShort,       // plik krótszy niż 144B
    BadMagic,           // pierwsze 4 bajty to nie "VLT1"
    UnsupportedVersion, // version != 1
    FlagsNotZero,       // bajty flags (offset 6-7) nie są wyzerowane
    UnknownKdfId,       // kdf_id (offset 8) != 1
    KdfMemoryZero,      // kdf_memory_kib == 0
    KdfIterationsZero,  // kdf_iterations == 0
    KdfParallelismZero, // kdf_parallelism == 0
    WrongSaltLen,       // kdf_salt_len (offset 18) != 16
    UnknownAeadId,      // aead_id (offset 35) != 1
    WrongWrappedDekLen, // wrapped_dek_len (offset 48-51) != 48
}

// sprawdza plik vault bez hasła
pub fn verify_structure(path: &Path) -> Result<(), VerifyError> {
    let mut file = File::open(path).map_err(|_| VerifyError::FileTooShort)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|_| VerifyError::FileTooShort)?;
    verify_structure_from_bytes(&data)
}

// FUNKCJE DLA FUZZERA
// przyjmują &[u8] zamiast ścieżki, fuzzer wywołuje je bezpośrednio bez plików na dysku

// parser nagłówka
pub fn fuzz_parse_header(data: &[u8]) -> Result<(), VerifyError> {
    verify_structure_from_bytes(data)
}

// parser body CBOR po deszyfrowaniu
pub fn fuzz_parse_body(data: &[u8]) -> Option<VaultBody> {
    ciborium::from_reader(data).ok()
}

pub fn verify_structure_from_bytes(data: &[u8]) -> Result<(), VerifyError> {
    // minimum 144B: 100B nagłówek + 32B HMAC + 12B nonce_body
    if data.len() < 144 {
        return Err(VerifyError::FileTooShort);
    }

    let h = &data[0..CANONICAL_HEADER_SIZE];

    if &h[0..4] != b"VLT1" {
        return Err(VerifyError::BadMagic);
    }

    let version = u16::from_be_bytes(h[4..6].try_into().unwrap());
    if version != 1 {
        return Err(VerifyError::UnsupportedVersion);
    }

    // flagi (offset 6-7) muszą być 0
    if h[6] != 0 || h[7] != 0 {
        return Err(VerifyError::FlagsNotZero);
    }

    // kdf_id (offset 8) — 1 = Argon2id
    if h[8] != 1 {
        return Err(VerifyError::UnknownKdfId);
    }

    // parametry Argon2id, żaden nie może być zerowy
    let kdf_memory = u32::from_be_bytes(h[9..13].try_into().unwrap());
    if kdf_memory == 0 {
        return Err(VerifyError::KdfMemoryZero);
    }

    let kdf_iterations = u32::from_be_bytes(h[13..17].try_into().unwrap());
    if kdf_iterations == 0 {
        return Err(VerifyError::KdfIterationsZero);
    }

    let kdf_parallelism = h[17];
    if kdf_parallelism == 0 {
        return Err(VerifyError::KdfParallelismZero);
    }

    // kdf_salt_len (offset 18), musi wynosić dokładnie 16
    let salt_len = h[18];
    if salt_len != 16 {
        return Err(VerifyError::WrongSaltLen);
    }

    // aead_id (offset 35) — 1 = ChaCha20-Poly1305
    let aead_id = h[35];
    if aead_id != 1 {
        return Err(VerifyError::UnknownAeadId);
    }

    // wrapped_dek_len (offset 48-51), musi wynosić 48 (32B DEK + 16B tag)
    let wrapped_dek_len = u32::from_be_bytes(h[48..52].try_into().unwrap());
    if wrapped_dek_len != 48 {
        return Err(VerifyError::WrongWrappedDekLen);
    }

    Ok(())
}

// TESTY JEDNOSTKOWE MODUŁU FORMAT
#[cfg(test)]
mod format_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn minimal_vault_body() -> VaultBody {
        VaultBody { schema_version: 1, records: vec![] }
    }

    fn sample_record() -> VaultRecord {
        let mut fields = BTreeMap::new();
        fields.insert("password".to_string(), b"tajne".to_vec());
        VaultRecord {
            id: [0u8; 16],
            record_type: RecordType::Login,
            title: "Test".to_string(),
            tags: vec!["test".to_string()],
            notes: "notatka".to_string(),
            created_at: 1_000_000,
            modified_at: 2_000_000,
            fields,
        }
    }

    fn minimal_valid_file_bytes() -> Vec<u8> {
        let header = VaultHeader {
            version: 1,
            kdf_memory_kib: 65536,
            kdf_iterations: 3,
            kdf_parallelism: 1,
            salt: [0u8; 16],
            nonce_dek: [0u8; 12],
            wrapped_dek: [0u8; 48],
        };
        let mut bytes = header.to_bytes(); // 100B nagłówek
        bytes.extend_from_slice(&[0u8; 32]); // 32B dla HMAC
        bytes.extend_from_slice(&[0u8; 12]); // 12B dla nonce_body
        bytes
    }

    // sprawdza gwarancję kanoniczności, nagłówek zawsze musi mieć dokładnie 100B
    #[test]
    fn header_has_exactly_100_bytes() {
        let header = VaultHeader {
            version: 1, kdf_memory_kib: 65536, kdf_iterations: 3, kdf_parallelism: 1,
            salt: [0xABu8; 16], nonce_dek: [0xCDu8; 12], wrapped_dek: [0xEFu8; 48],
        };
        assert_eq!(header.to_bytes().len(), CANONICAL_HEADER_SIZE);
    }

    // sprawdza że pierwsze 4 bajty to VLT1
    #[test]
    fn header_starts_with_magic_vlt1() {
        let header = VaultHeader {
            version: 1, kdf_memory_kib: 65536, kdf_iterations: 3, kdf_parallelism: 1,
            salt: [0u8; 16], nonce_dek: [0u8; 12], wrapped_dek: [0u8; 48],
        };
        assert_eq!(&header.to_bytes()[0..4], b"VLT1");
    }

    #[test]
    fn header_fields_at_correct_offsets() {
        let header = VaultHeader {
            version: 1,
            kdf_memory_kib: 0x00010203,
            kdf_iterations: 0x04050607,
            kdf_parallelism: 0x08,
            salt: [0xAAu8; 16],
            nonce_dek: [0xBBu8; 12],
            wrapped_dek: [0xCCu8; 48],
        };
        let bytes = header.to_bytes();

        assert_eq!(u16::from_be_bytes(bytes[4..6].try_into().unwrap()), 1);   // version
        assert_eq!(bytes[6], 0);                                               // flags[0]
        assert_eq!(bytes[7], 0);                                               // flags[1]
        assert_eq!(bytes[8], 1);                                               // kdf_id = Argon2id
        assert_eq!(u32::from_be_bytes(bytes[9..13].try_into().unwrap()), 0x00010203);  // kdf_memory
        assert_eq!(u32::from_be_bytes(bytes[13..17].try_into().unwrap()), 0x04050607); // kdf_iterations
        assert_eq!(bytes[17], 0x08);                                           // kdf_parallelism
        assert_eq!(bytes[18], 16);                                             // salt_len
        assert_eq!(&bytes[19..35], &[0xAAu8; 16]);                            // salt
        assert_eq!(bytes[35], 1);                                              // aead_id = ChaCha20
        assert_eq!(&bytes[36..48], &[0xBBu8; 12]);                            // nonce_dek
        assert_eq!(u32::from_be_bytes(bytes[48..52].try_into().unwrap()), 48); // wrapped_dek_len
        assert_eq!(&bytes[52..100], &[0xCCu8; 48]);                           // wrapped_dek
    }

    // testy serializacji CBOR

    #[test]
    fn serialize_body_empty_records() {
        // pusta baza daje niepuste wyjście CBOR
        let bytes = serialize_body(&minimal_vault_body());
        assert!(!bytes.is_empty());
    }

    #[test]
    fn serialize_body_roundtrip() {
        // serializacja i deserializacja muszą dać identyczną strukturę
        let body = VaultBody { schema_version: 1, records: vec![sample_record()] };
        let bytes = serialize_body(&body);
        let restored: VaultBody = ciborium::from_reader(bytes.as_slice())
            .expect("Deserializacja CBOR nie powinna się nie udać");

        assert_eq!(restored.schema_version, 1);
        assert_eq!(restored.records.len(), 1);
        assert_eq!(restored.records[0].title, "Test");
        assert_eq!(restored.records[0].record_type, RecordType::Login);
        assert_eq!(restored.records[0].tags, vec!["test".to_string()]);
    }

    #[test]
    fn serialize_body_preserves_binary_fields() {
        // hasło musi przeżyć bez zmian
        let body = VaultBody { schema_version: 1, records: vec![sample_record()] };
        let bytes = serialize_body(&body);
        let restored: VaultBody = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(restored.records[0].fields.get("password").unwrap(), b"tajne");
    }

    // testy verify_structure
    #[test]
    fn verify_structure_valid_file() {
        let path = std::env::temp_dir().join("vault_test_ok.db");
        std::fs::write(&path, minimal_valid_file_bytes()).unwrap();
        let result = verify_structure(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(result, Ok(()));
    }

    // plik krótszy niż 144B musi zwrócić FileTooShort
    #[test]
    fn verify_structure_file_too_short() {
        let path = std::env::temp_dir().join("vault_test_short.db");
        std::fs::write(&path, b"VLT1za_krotki").unwrap();
        let result = verify_structure(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(result, Err(VerifyError::FileTooShort));
    }

    // nadpisanie magic bajty ZZZZ musi zwrócić BadMagic
    #[test]
    fn verify_structure_bad_magic() {
        let path = std::env::temp_dir().join("vault_test_magic.db");
        let mut bytes = minimal_valid_file_bytes();
        bytes[0..4].copy_from_slice(b"ZZZZ");
        std::fs::write(&path, &bytes).unwrap();
        let result = verify_structure(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(result, Err(VerifyError::BadMagic));
    }

    // wersja inna niż 1 musi zwrócić UnsupportedVersion
    #[test]
    fn verify_structure_unsupported_version() {
        let path = std::env::temp_dir().join("vault_test_ver.db");
        let mut bytes = minimal_valid_file_bytes();
        bytes[4..6].copy_from_slice(&2u16.to_be_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let result = verify_structure(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(result, Err(VerifyError::UnsupportedVersion));
    }

    // niezerowe bajty flags muszą zwrócić FlagsNotZero
    #[test]
    fn verify_structure_flags_not_zero() {
        let path = std::env::temp_dir().join("vault_test_flags.db");
        let mut bytes = minimal_valid_file_bytes();
        bytes[6] = 0x01; // zarezerwowany bit ustawiony
        std::fs::write(&path, &bytes).unwrap();
        let result = verify_structure(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(result, Err(VerifyError::FlagsNotZero));
    }

    // kdf_id inny niż 1 musi zwrócić UnknownKdfId
    #[test]
    fn verify_structure_unknown_kdf_id() {
        let path = std::env::temp_dir().join("vault_test_kdf.db");
        let mut bytes = minimal_valid_file_bytes();
        bytes[8] = 0x02; // nieznany identyfikator KDF
        std::fs::write(&path, &bytes).unwrap();
        let result = verify_structure(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(result, Err(VerifyError::UnknownKdfId));
    }

    // kdf_memory_kib = 0 musi zwrócić KdfMemoryZero
    #[test]
    fn verify_structure_kdf_memory_zero() {
        let path = std::env::temp_dir().join("vault_test_mem.db");
        let mut bytes = minimal_valid_file_bytes();
        bytes[9..13].copy_from_slice(&0u32.to_be_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let result = verify_structure(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(result, Err(VerifyError::KdfMemoryZero));
    }

    // aead_id inny niż 1 musi zwrócić UnknownAeadId
    #[test]
    fn verify_structure_unknown_aead_id() {
        let path = std::env::temp_dir().join("vault_test_aead.db");
        let mut bytes = minimal_valid_file_bytes();
        bytes[35] = 0x02; // nieznany identyfikator AEAD
        std::fs::write(&path, &bytes).unwrap();
        let result = verify_structure(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(result, Err(VerifyError::UnknownAeadId));
    }

    // wrapped_dek_len inny niż 48 musi zwrócić WrongWrappedDekLen
    #[test]
    fn verify_structure_wrong_wrapped_dek_len() {
        let path = std::env::temp_dir().join("vault_test_dek.db");
        let mut bytes = minimal_valid_file_bytes();
        bytes[48..52].copy_from_slice(&32u32.to_be_bytes()); // 32 zamiast 48
        std::fs::write(&path, &bytes).unwrap();
        let result = verify_structure(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(result, Err(VerifyError::WrongWrappedDekLen));
    }

    // UUID v4 musi mieć dokładnie 16 bajtów
    #[test]
    fn generate_uuid_v4_returns_16_bytes() {
        assert_eq!(generate_uuid_v4().len(), 16);
    }

    #[test]
    fn generate_uuid_v4_different_values() {
        // dwa kolejne UUID nie powinny być identyczne
        assert_ne!(generate_uuid_v4(), generate_uuid_v4());
    }

    // czas systemowy nigdy nie może być zerem
    #[test]
    fn current_time_nanos_is_nonzero() {
        assert!(current_time_nanos() > 0);
    }

    #[test]
    fn current_time_nanos_is_monotonic() {
        // drugi odczyt nie może być wcześniejszy niż pierwszy
        let t1 = current_time_nanos();
        let t2 = current_time_nanos();
        assert!(t2 >= t1);
    }

    // testy funkcji fuzz

    #[test]
    fn fuzz_parse_header_empty_buffer() {
        // pusty bufor musi zwrócić błąd
        assert_eq!(fuzz_parse_header(&[]), Err(VerifyError::FileTooShort));
    }

    #[test]
    fn fuzz_parse_header_all_zeros() {
        // 144 bajty zer — poprawna długość, ale zły magic
        assert_eq!(fuzz_parse_header(&[0u8; 144]), Err(VerifyError::BadMagic));
    }

    #[test]
    fn fuzz_parse_header_all_ff() {
        // 144 bajty 0xFF — nie może spowodować błędu
        assert!(fuzz_parse_header(&[0xFFu8; 144]).is_err());
    }

    #[test]
    fn fuzz_parse_header_valid_buffer() {
        // poprawny bufor musi przejść przez fuzz_parse_header
        assert_eq!(fuzz_parse_header(&minimal_valid_file_bytes()), Ok(()));
    }

    #[test]
    fn fuzz_parse_body_empty_buffer() {
        // pusty bufor, parser CBOR zwraca None
        assert!(fuzz_parse_body(&[]).is_none());
    }

    #[test]
    fn fuzz_parse_body_garbage_bytes() {
        // losowe bajty nie są poprawnym CBOR
        assert!(fuzz_parse_body(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x42, 0x13]).is_none());
    }

    #[test]
    fn fuzz_parse_body_valid_cbor() {
        // poprawny CBOR VaultBody musi się sparsować
        let bytes = serialize_body(&minimal_vault_body());
        assert!(fuzz_parse_body(&bytes).is_some());
    }

    #[test]
    fn verify_structure_from_bytes_matches_verify_structure() {
        // verify_structure i verify_structure_from_bytes muszą dawać identyczny wynik
        let bytes = minimal_valid_file_bytes();
        let path = std::env::temp_dir().join("vault_test_delegate.db");
        std::fs::write(&path, &bytes).unwrap();
        let result_file = verify_structure(&path);
        let result_bytes = verify_structure_from_bytes(&bytes);
        std::fs::remove_file(&path).ok();
        assert_eq!(result_file, result_bytes);
    }
}
