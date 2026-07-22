use expectrl::{spawn, Expect};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

const MASTER_PASSWORD: &str = "StrongPassword123!";
const NEW_MASTER_PASSWORD: &str = "NewStrongPassword123!";
const LOGIN_TITLE: &str = "konto_uczelniane";
const LOGIN_URL: &str = "https://example.com";
const LOGIN_USERNAME: &str = "student";
const LOGIN_PASSWORD: &str = "SecretLoginPassword123!";


fn vault_bin() -> String {
    env!("CARGO_BIN_EXE_vault").to_string()
}

fn run_init(path: &Path) {
    let cmd = format!("{} init {}", vault_bin(), path.display());
    let mut p = spawn(cmd).expect("failed to spawn init");

    p.expect("haslo glowne:")
        .expect("missing master password prompt");
    p.send_line(MASTER_PASSWORD)
        .expect("failed to send master password");

    p.expect("powtorz haslo:")
        .expect("missing password confirmation prompt");
    p.send_line(MASTER_PASSWORD)
        .expect("failed to send password confirmation");

    p.expect("utworzony")
        .expect("vault should be created");
}

fn assert_open_rejected(path: &Path, password: &str) {
    let cmd = format!("{} open {}", vault_bin(), path.display());
    let mut p = spawn(cmd).expect("failed to spawn open with rejected password");

    p.expect("haslo glowne:")
        .expect("missing master password prompt");
    p.send_line(password)
        .expect("failed to send rejected password");

    let opened = p.expect("vault>").is_ok();

    assert!(
        !opened,
        "vault should not open with rejected password"
    );
}

#[test]
fn e2e_1_init_add_login_list_get_value_matches() {
    let dir = tempdir().expect("failed to create temporary directory");
    let vault_path = dir.path().join("test.vault");

    // E2E-1 krok 1: init
    run_init(&vault_path);

    // E2E-1 krok 2: open
    let cmd = format!("{} open {}", vault_bin(), vault_path.display());
    let mut p = spawn(cmd).expect("failed to spawn open");

    p.expect("haslo glowne:")
        .expect("missing master password prompt");
    p.send_line(MASTER_PASSWORD)
        .expect("failed to send master password");

    p.expect("vault>")
        .expect("vault session should start");

    // E2E-1 krok 3: add login
    p.send_line("add login")
        .expect("failed to send add login command");

    p.expect("tytul:")
        .expect("missing title prompt");
    p.send_line(LOGIN_TITLE)
        .expect("failed to send title");

    p.expect("tagi")
        .expect("missing tags prompt");
    p.send_line("uczelnia,wat")
        .expect("failed to send tags");

    p.expect("notatki:")
        .expect("missing notes prompt");
    p.send_line("notatka testowa")
        .expect("failed to send notes");

    p.expect("url:")
        .expect("missing url prompt");
    p.send_line(LOGIN_URL)
        .expect("failed to send url");

    p.expect("username:")
        .expect("missing username prompt");
    p.send_line(LOGIN_USERNAME)
        .expect("failed to send username");

    p.expect("password:")
        .expect("missing login password prompt");
    p.send_line(LOGIN_PASSWORD)
        .expect("failed to send login password");

    p.expect("dodano rekord")
        .expect("record should be added");

    // E2E-1 krok 4: list
    p.expect("vault>")
        .expect("vault prompt should appear after add");
    p.send_line("list")
        .expect("failed to send list command");

    p.expect(LOGIN_TITLE)
        .expect("list should show added record title");

    // E2E-1 krok 5: get
    p.expect("vault>")
        .expect("vault prompt should appear after list");
    p.send_line(format!("get {}", LOGIN_TITLE))
        .expect("failed to send get command");

    // E2E-1 krok 6: wartość zgadza się
    p.expect(LOGIN_USERNAME)
        .expect("get should show saved username");

    p.expect(LOGIN_PASSWORD)
        .expect("get should show saved login password");

p.expect("vault>")
    .expect("vault prompt should appear after get");
p.send_line("exit")
    .expect("failed to send exit command");

// Dodatkowe sprawdzenie E2E-1: po zamknięciu sesji otwieramy vault ponownie i sprawdzamy czy rekord faktycznie został zapisany w pliku
let cmd = format!("{} open {}", vault_bin(), vault_path.display());
let mut p = spawn(cmd).expect("failed to spawn reopen");

p.expect("haslo glowne:")
    .expect("missing master password prompt during reopen");
p.send_line(MASTER_PASSWORD)
    .expect("failed to send master password during reopen");

p.expect("vault>")
    .expect("vault session should start after reopen");

p.send_line(format!("get {}", LOGIN_TITLE))
    .expect("failed to send get command after reopen");

p.expect(LOGIN_USERNAME)
    .expect("get after reopen should show saved username");

p.expect(LOGIN_PASSWORD)
    .expect("get after reopen should show saved login password");

p.expect("vault>")
    .expect("vault prompt should appear after get after reopen");
p.send_line("exit")
    .expect("failed to send exit command after reopen");
}


#[test]
fn e2e_2_add_100_records_changepass_open_new_password_all_present() {
    let dir = tempdir().expect("failed to create temporary directory");
    let vault_path = dir.path().join("test_changepass.vault");

    // E2E-2 krok 1: init
    run_init(&vault_path);

    // E2E-2 krok 2: open starym hasłem
    let cmd = format!("{} open {}", vault_bin(), vault_path.display());
    let mut p = spawn(cmd).expect("failed to spawn open");

    p.expect("haslo glowne:")
        .expect("missing master password prompt");
    p.send_line(MASTER_PASSWORD)
        .expect("failed to send master password");

    p.expect("vault>")
        .expect("vault session should start");

    // E2E-2 krok 3: dodanie 100 rekordów typu login
    for i in 0..100 {
        let title = format!("login_{:03}", i);
        let username = format!("user_{:03}", i);
        let password = format!("Password_{:03}!", i);

        p.send_line("add login")
            .expect("failed to send add login command");

        p.expect("tytul:")
            .expect("missing title prompt");
        p.send_line(&title)
            .expect("failed to send title");

        p.expect("tagi")
            .expect("missing tags prompt");
        p.send_line("test,e2e")
            .expect("failed to send tags");

        p.expect("notatki:")
            .expect("missing notes prompt");
        p.send_line("rekord testowy e2e-2")
            .expect("failed to send notes");

        p.expect("url:")
            .expect("missing url prompt");
        p.send_line("https://example.com")
            .expect("failed to send url");

        p.expect("username:")
            .expect("missing username prompt");
        p.send_line(&username)
            .expect("failed to send username");

        p.expect("password:")
            .expect("missing password prompt");
        p.send_line(&password)
            .expect("failed to send login password");

        p.expect("dodano rekord")
            .expect("record should be added");

        p.expect("vault>")
            .expect("vault prompt should appear after add");
    }

    // E2E-2 krok 4: changepass
    p.send_line("changepass")
        .expect("failed to send changepass command");

    p.expect("aktualne haslo glowne:")
        .expect("missing current password prompt");
    p.send_line(MASTER_PASSWORD)
        .expect("failed to send current master password");

    p.expect("haslo glowne:")
        .expect("missing new password prompt");
    p.send_line(NEW_MASTER_PASSWORD)
        .expect("failed to send new master password");

    p.expect("powtorz haslo:")
        .expect("missing new password confirmation prompt");
    p.send_line(NEW_MASTER_PASSWORD)
        .expect("failed to send new master password confirmation");

    p.expect("vault>")
        .expect("vault prompt should appear after changepass");

    p.send_line("exit")
        .expect("failed to send exit command");

    // Dodatkowe sprawdzenie E2E-2: po zmianie hasła stare hasło nie powinno już otwierać vaulta
    assert_open_rejected(&vault_path, MASTER_PASSWORD);

    // E2E-2 krok 5: open nowym hasłem
    let cmd = format!("{} open {}", vault_bin(), vault_path.display());
    let mut p = spawn(cmd).expect("failed to spawn open with new password");

    p.expect("haslo glowne:")
        .expect("missing master password prompt");
    p.send_line(NEW_MASTER_PASSWORD)
        .expect("failed to send new master password");

    p.expect("vault>")
        .expect("vault session should start with new password");

    // E2E-2 krok 6: sprawdzenie czy mamy wszystkie rekordy
    for i in 0..100 {
        let title = format!("login_{:03}", i);
        let username = format!("user_{:03}", i);
        let password = format!("Password_{:03}!", i);

        p.send_line(format!("get {}", title))
            .expect("failed to send get command");

        p.expect(&title)
            .expect("get should show record title");

        p.expect(&username)
            .expect("get should show saved username");

        p.expect(&password)
            .expect("get should show saved password");

        p.expect("vault>")
            .expect("vault prompt should appear after get");
    }

    p.send_line("exit")
        .expect("failed to send exit command");
}


#[test]
fn e2e_3_attach_4mib_extract_bytes_identical() {
    let dir = tempdir().expect("failed to create temporary directory");
    let vault_path = dir.path().join("test_attach.vault");
    let input_path = dir.path().join("input_4mib.bin");
    let output_path = dir.path().join("output_4mib.bin");

    // Przygotowanie pliku 4 MiB
    let input_data: Vec<u8> = (0..(4 * 1024 * 1024))
        .map(|i| (i % 251) as u8)
        .collect();

    fs::write(&input_path, &input_data)
        .expect("failed to write input 4 MiB file");

    // E2E-3 krok 1: init
    run_init(&vault_path);

    // E2E-3 krok 2: open
    let cmd = format!("{} open {}", vault_bin(), vault_path.display());
    let mut p = spawn(cmd).expect("failed to spawn open");

    p.expect("haslo glowne:")
        .expect("missing master password prompt");
    p.send_line(MASTER_PASSWORD)
        .expect("failed to send master password");

    p.expect("vault>")
        .expect("vault session should start");

    // E2E-3 krok 3: attach 4 MiB plik
    p.send_line(format!(
        "attach {} --title zalacznik_4mib",
        input_path.display()
    ))
    .expect("failed to send attach command");

    p.expect("dolaczono zalacznik")
        .expect("attachment should be added");

    p.expect("4194304 B")
        .expect("attachment size should be 4 MiB");

    p.expect("vault>")
        .expect("vault prompt should appear after attach");

    // E2E-3 krok 4: extract do wskazanego pliku
    p.send_line(format!(
        "extract zalacznik_4mib {}",
        output_path.display()
    ))
    .expect("failed to send extract command");

    p.expect("zapisano 4194304 B")
        .expect("extract should save 4 MiB");

    p.expect("vault>")
        .expect("vault prompt should appear after extract");

    p.send_line("exit")
        .expect("failed to send exit command");

    // E2E-3 krok 5: porównanie
    let output_data = fs::read(&output_path)
        .expect("failed to read extracted file");

    assert_eq!(
        input_data, output_data,
        "extracted file bytes should be identical to original file bytes"
    );
}


#[test]
fn e2e_4_upgrade_kdf_open_same_password() {
    let dir = tempdir().expect("failed to create temporary directory");
    let vault_path = dir.path().join("test_upgrade_kdf.vault");

    // E2E-4 krok 1: init
    run_init(&vault_path);

    // E2E-4 krok 2: open tym samym hasłem
    let cmd = format!("{} open {}", vault_bin(), vault_path.display());
    let mut p = spawn(cmd).expect("failed to spawn open");

    p.expect("haslo glowne:")
        .expect("missing master password prompt");
    p.send_line(MASTER_PASSWORD)
        .expect("failed to send master password");

    p.expect("vault>")
        .expect("vault session should start");

    // Dodajemy 1 rekord kontrolny, zeby po upgrade-kdf sprawdzic czy vault nadal poprawnie odszyfrowuje dane
    p.send_line("add login")
        .expect("failed to send add login command");

    p.expect("tytul:")
        .expect("missing title prompt");
    p.send_line("konto_po_upgrade")
        .expect("failed to send title");

    p.expect("tagi")
        .expect("missing tags prompt");
    p.send_line("upgrade,kdf")
        .expect("failed to send tags");

    p.expect("notatki:")
        .expect("missing notes prompt");
    p.send_line("rekord kontrolny e2e-4")
        .expect("failed to send notes");

    p.expect("url:")
        .expect("missing url prompt");
    p.send_line("https://example.com")
        .expect("failed to send url");

    p.expect("username:")
        .expect("missing username prompt");
    p.send_line("user_upgrade")
        .expect("failed to send username");

    p.expect("password:")
        .expect("missing password prompt");
    p.send_line("PasswordAfterUpgrade123!")
        .expect("failed to send login password");

    p.expect("dodano rekord")
        .expect("record should be added");

    p.expect("vault>")
        .expect("vault prompt should appear after add");

    // E2E-4 krok 3: upgrade-kdf
  
    p.send_line("upgrade-kdf --memory 65536 --iterations 4 --parallelism 2")
        .expect("failed to send upgrade-kdf command");

    p.expect("haslo glowne:")
        .expect("missing password prompt during upgrade-kdf");
    p.send_line(MASTER_PASSWORD)
        .expect("failed to send master password for upgrade-kdf");

    p.expect("vault>")
        .expect("vault prompt should appear after upgrade-kdf");

    p.send_line("exit")
        .expect("failed to send exit command");

    // E2E-4 krok 4: ponowne open tym samym haslem
    let cmd = format!("{} open {}", vault_bin(), vault_path.display());
    let mut p = spawn(cmd).expect("failed to spawn open after upgrade-kdf");

    p.expect("haslo glowne:")
        .expect("missing master password prompt");
    p.send_line(MASTER_PASSWORD)
        .expect("failed to send same master password after upgrade-kdf");

    p.expect("vault>")
        .expect("vault session should start after upgrade-kdf");

    // E2E-4 krok 5: sprawdzamy czy dane nadal sa dostepne
    p.send_line("get konto_po_upgrade")
        .expect("failed to send get command");

    p.expect("user_upgrade")
        .expect("get should show saved username after upgrade-kdf");

    p.expect("PasswordAfterUpgrade123!")
        .expect("get should show saved password after upgrade-kdf");

    p.expect("vault>")
        .expect("vault prompt should appear after get");

    p.send_line("exit")
        .expect("failed to send exit command");
}