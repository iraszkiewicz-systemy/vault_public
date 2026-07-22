use expectrl::{spawn, Expect};
use std::fs;
use std::path::Path;
use std::time::Instant;
use tempfile::tempdir;

const PASSWORD: &str = "StrongPassword123!";
const NEW_PASSWORD: &str = "NewStrongPassword123!";
const WEAK_PASSWORD: &str = "password123";

fn vault_bin() -> String {
    env!("CARGO_BIN_EXE_vault").to_string()
}

fn run_init(path: &Path, password: &str) {
    let cmd = format!("{} init {}", vault_bin(), path.display());
    let mut p = spawn(cmd).expect("failed to spawn init");

    p.expect("haslo glowne:")
        .expect("missing password prompt");
    p.send_line(password)
        .expect("failed to send password");

    p.expect("powtorz haslo:")
        .expect("missing confirmation prompt");
    p.send_line(password)
        .expect("failed to send password confirmation");

    p.expect("utworzony")
        .expect("vault should be created");
}

fn assert_open_rejected(path: &Path, password: &str) {
    let cmd = format!("{} open {}", vault_bin(), path.display());
    let mut p = spawn(cmd).expect("failed to spawn open");

    p.expect("haslo glowne:")
        .expect("missing password prompt");
    p.send_line(password)
        .expect("failed to send password");

    let opened = p.expect("vault>").is_ok();

    assert!(
        !opened,
        "vault should reject corrupted file or wrong password"
    );
}

fn add_one_login_record(path: &Path, password: &str) {
    let cmd = format!("{} open {}", vault_bin(), path.display());
    let mut p = spawn(cmd).expect("failed to spawn open");

    p.expect("haslo glowne:").unwrap();
    p.send_line(password).unwrap();

    p.expect("vault>").unwrap();

    p.send_line("add login").unwrap();

    p.expect("tytul:").unwrap();
    p.send_line("adversarial_login").unwrap();

    p.expect("tagi").unwrap();
    p.send_line("adversarial").unwrap();

    p.expect("notatki:").unwrap();
    p.send_line("test").unwrap();

    p.expect("url:").unwrap();
    p.send_line("https://example.com").unwrap();

    p.expect("username:").unwrap();
    p.send_line("student").unwrap();

    p.expect("password:").unwrap();
    p.send_line("Secret123!").unwrap();

    p.expect("dodano rekord").unwrap();
    p.expect("vault>").unwrap();

    p.send_line("exit").unwrap();
}

fn read_bytes(path: &Path) -> Vec<u8> {
    fs::read(path).expect("failed to read vault file")
}

fn write_bytes(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("failed to write modified vault file")
}


#[test]
fn a1_body_ciphertext_bitflip_is_rejected() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("a1_body_bitflip.vault");

    run_init(&vault_path, PASSWORD);
    add_one_login_record(&vault_path, PASSWORD);

    let mut bytes = read_bytes(&vault_path);

    assert!(bytes.len() > 144, "vault should contain encrypted body");
    bytes[144] ^= 0x01;

    write_bytes(&vault_path, &bytes);

    assert_open_rejected(&vault_path, PASSWORD);
}

#[test]
fn a2_kdf_iterations_downgrade_is_rejected() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("a2_kdf_downgrade.vault");

    run_init(&vault_path, PASSWORD);

    let mut bytes = read_bytes(&vault_path);

    // kdf_iterations: offset 13..17, big-endian.
    bytes[13..17].copy_from_slice(&1u32.to_be_bytes());

    write_bytes(&vault_path, &bytes);

    assert_open_rejected(&vault_path, PASSWORD);
}


#[test]
fn a3_aead_id_change_is_rejected() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("a3_aead_change.vault");

    run_init(&vault_path, PASSWORD);

    let mut bytes = read_bytes(&vault_path);

    // aead_id: offset 35, poprawnie 1 = ChaCha20-Poly1305.
    bytes[35] = 2;

    write_bytes(&vault_path, &bytes);

    assert_open_rejected(&vault_path, PASSWORD);
}


#[test]
fn a4_wrapped_dek_bitflip_is_rejected() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("a4_wrapped_dek.vault");

    run_init(&vault_path, PASSWORD);

    let mut bytes = read_bytes(&vault_path);

    // wrapped_dek: offset 52..100.
    bytes[52] ^= 0x01;

    write_bytes(&vault_path, &bytes);

    assert_open_rejected(&vault_path, PASSWORD);
}


#[test]
#[ignore] //uruchom recznie tylko do raportu
fn a5_weak_password_bruteforce_cost_is_measured() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("a5_weak_password.vault");

    run_init(&vault_path, WEAK_PASSWORD);

    let start = Instant::now();

    // Przykładowa mała próbka błędnych haseł - pomiar kosztu pojedynczych prób
    let guesses = [
        "123456",
        "password",
        "qwerty",
        "admin",
        "haslo123",
    ];

    for guess in guesses {
        assert_open_rejected(&vault_path, guess);
    }

    let elapsed = start.elapsed();

    println!(
        "A5 brute-force measurement: {} guesses took {:?}",
        guesses.len(),
        elapsed
    );
}


#[test]
fn a6_old_password_after_changepass_is_rejected() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("a6_changepass.vault");

    run_init(&vault_path, PASSWORD);

    let cmd = format!("{} open {}", vault_bin(), vault_path.display());
    let mut p = spawn(cmd).expect("failed to spawn open");

    p.expect("haslo glowne:").unwrap();
    p.send_line(PASSWORD).unwrap();

    p.expect("vault>").unwrap();

    p.send_line("changepass").unwrap();

    p.expect("aktualne haslo glowne:").unwrap();
    p.send_line(PASSWORD).unwrap();

    p.expect("haslo glowne:").unwrap();
    p.send_line(NEW_PASSWORD).unwrap();

    p.expect("powtorz haslo:").unwrap();
    p.send_line(NEW_PASSWORD).unwrap();

    p.expect("vault>").unwrap();
    p.send_line("exit").unwrap();

    assert_open_rejected(&vault_path, PASSWORD);
}


#[test]
fn a7_truncated_body_is_rejected() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("a7_truncated.vault");

    run_init(&vault_path, PASSWORD);
    add_one_login_record(&vault_path, PASSWORD);

    let mut bytes = read_bytes(&vault_path);

    assert!(bytes.len() > 160, "vault should be long enough to truncate body");

    let new_len = 144 + ((bytes.len() - 144) / 2);
    bytes.truncate(new_len);

    write_bytes(&vault_path, &bytes);

    assert_open_rejected(&vault_path, PASSWORD);
}


#[test]
fn a8_empty_file_is_rejected() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("a8_empty.vault");

    // Tworzymy pusty plik vault
    fs::write(&vault_path, []).expect("failed to write empty file");

    assert_open_rejected(&vault_path, PASSWORD);
}

#[test]
fn a8_wrong_magic_is_rejected() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("a8_wrong_magic.vault");

    // Najpierw tworzymy poprawny vault
    run_init(&vault_path, PASSWORD);

    // Potem psujemy magic bytes na początku pliku
    let mut bytes = read_bytes(&vault_path);

    // Magic jest na początku pliku, bajty 0..4. wpisujemy bledna wartosc
    bytes[0..4].copy_from_slice(b"BAD!");

    write_bytes(&vault_path, &bytes);

    assert_open_rejected(&vault_path, PASSWORD);
}
