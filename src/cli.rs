use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as OsCommand, ExitCode, Stdio};

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams};
use crate::format::{
    self, current_time_nanos, generate_uuid_v4, RecordType, VaultBody, VaultHeader, VaultRecord,
};

// Jeden komunikat dla blednego hasla i uszkodzonego pliku (F-17).
const ERR_OPEN: &str = "bledne haslo lub uszkodzony plik";

// Domyslne parametry Argon2id (NF-02), zgodne z formatem zapisywanym przez init.
const KDF_MEMORY_KIB: u32 = 64 * 1024;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u8 = 1;

// Limit rozmiaru zalacznika (spec §3.1: do 5 MiB kazdy).
const MAX_ATTACHMENT: u64 = 5 * 1024 * 1024;

// ─── CLI najwyzszego poziomu (argv) ───────────────────────────────────────────

#[derive(Parser)]
#[command(name = "vault", version, about = "Bezpieczny menedzer sekretow")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Tworzy nowy vault, prosi o haslo glowne (z potwierdzeniem).
    Init { path: PathBuf },
    /// Otwiera vault i uruchamia interaktywna sesje (haslo glowne).
    Open { path: PathBuf },
    /// Sprawdza plik: struktura (bez hasla) lub pelna integralnosc (--with-password).
    Verify {
        path: PathBuf,
        /// Pelna weryfikacja kryptograficzna naglowka i body (wymaga hasla).
        #[arg(long = "with-password")]
        with_password: bool,
    },
}

pub fn run() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Init { path } => cmd_init(path),
        Command::Open { path } => cmd_open(path),
        Command::Verify {
            path,
            with_password,
        } => cmd_verify(path, with_password),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("blad: {e}");
            ExitCode::FAILURE
        }
    }
}

// ─── komendy argv ─────────────────────────────────────────────────────────────

// ### INIT ### — jedyne miejsce, ktore generuje swiezy salt + DEK (przez save_vault).
fn cmd_init(path: PathBuf) -> Result<(), String> {
    if path.exists() {
        return Err(format!(
            "plik {} juz istnieje — uzyj innej sciezki",
            path.display()
        ));
    }

    // Haslo z potwierdzeniem, bez echo (F-19).
    let password = read_password_with_confirmation()?;

    let body = VaultBody {
        schema_version: 1,
        records: Vec::new(),
    };

    format::save_vault(password.as_bytes(), &body, &path)
        .map_err(|e| format!("nie udalo sie utworzyc vaulta: {e}"))?;

    println!("vault utworzony: {}", path.display());
    Ok(())
}

// ### OPEN ### — deszyfruje, trzyma DEK w sesji i wchodzi w petle interaktywna.
fn cmd_open(path: PathBuf) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("plik {} nie istnieje", path.display()));
    }

    // Najpierw haslo, potem wszystkie sprawdzenia -> jeden komunikat (F-17).
    let password = read_password()?;

    let parsed = parse_file(&path)?;

    // opencrypto sprawdza header_mac, odwija DEK i deszyfruje body (AEAD tag).
    let opened = crypto::opencrypto(
        password.as_bytes(),
        &parsed.salt,
        &parsed.canonical_header,
        &parsed.header_mac,
        &parsed.nonce_dek,
        &parsed.wrapped_dek,
        &parsed.nonce_body,
        &parsed.ct_body,
        &parsed.kdf_params,
    )
    .map_err(|_| ERR_OPEN.to_string())?;

    let body: VaultBody =
        ciborium::from_reader(opened.body.as_slice()).map_err(|_| ERR_OPEN.to_string())?;

    // Sesja trzyma DEK (a nie haslo) — body re-szyfrujemy tym samym DEK (spec 7.5).
    let mut session = Session {
        path,
        dek: opened.dek,
        canonical_header: parsed.canonical_header,
        header_mac: parsed.header_mac,
        body,
    };
    // `password` (Zeroizing) wychodzi tu ze scope i zostaje wyzerowane.

    println!("vault otwarty: {}", session.path.display());
    println!("rekordow: {}", session.body.records.len());
    println!("wpisz 'help' aby zobaczyc komendy, 'exit' aby zamknac sesje.");

    run_session(&mut session)
}

// ### VERIFY ###
fn cmd_verify(path: PathBuf, with_password: bool) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("plik {} nie istnieje", path.display()));
    }

    if !with_password {
        // Tylko struktura: magic, wersja, dlugosci pol. Bez gwarancji integralnosci.
        return match format::verify_structure(&path) {
            Ok(()) => {
                println!("struktura pliku OK (bez gwarancji integralnosci kryptograficznej).");
                Ok(())
            }
            Err(e) => Err(format!("blad struktury pliku: {e:?}")),
        };
    }

    // Pelna integralnosc kryptograficzna naglowka i body (analogicznie do open,
    // ale bez uruchamiania sesji). Jeden komunikat dla wszystkich bledow (F-17).
    let password = read_password()?;
    let parsed = parse_file(&path)?;

    let opened = crypto::opencrypto(
        password.as_bytes(),
        &parsed.salt,
        &parsed.canonical_header,
        &parsed.header_mac,
        &parsed.nonce_dek,
        &parsed.wrapped_dek,
        &parsed.nonce_body,
        &parsed.ct_body,
        &parsed.kdf_params,
    )
    .map_err(|_| ERR_OPEN.to_string())?;

    // Body musi byc takze poprawnym CBOR-em po deszyfrowaniu.
    let _body: VaultBody =
        ciborium::from_reader(opened.body.as_slice()).map_err(|_| ERR_OPEN.to_string())?;

    println!("integralnosc kryptograficzna OK (naglowek + body).");
    Ok(())
}

// ─── parsowanie pliku vault na komponenty ─────────────────────────────────────
// format.rs nie wystawia parsera zwracajacego pola naglowka, wiec robi to tutaj
// warstwa Vault Service. Offsety zgodne z format::VaultHeader::to_bytes / load_vault.

struct ParsedFile {
    salt: [u8; 16],
    nonce_dek: [u8; 12],
    wrapped_dek: Vec<u8>, // 48 B
    nonce_body: [u8; 12],
    canonical_header: Vec<u8>, // 100 B (offsety 0..99)
    header_mac: [u8; 32],
    ct_body: Vec<u8>,
    kdf_params: KdfParams,
}

fn parse_file(path: &Path) -> Result<ParsedFile, String> {
    let data = std::fs::read(path).map_err(|_| ERR_OPEN.to_string())?;

    // 100B naglowek + 32B header_mac + 12B nonce_body = minimum 144B.
    if data.len() < 144 {
        return Err(ERR_OPEN.to_string());
    }

    let canonical_header = data[0..100].to_vec();
    if &canonical_header[0..4] != b"VLT1" {
        return Err(ERR_OPEN.to_string());
    }

    let kdf_params = header_kdf_params(&canonical_header);

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&canonical_header[19..35]);

    let mut nonce_dek = [0u8; 12];
    nonce_dek.copy_from_slice(&canonical_header[36..48]);

    let wrapped_dek = canonical_header[52..100].to_vec();

    let mut header_mac = [0u8; 32];
    header_mac.copy_from_slice(&data[100..132]);

    let mut nonce_body = [0u8; 12];
    nonce_body.copy_from_slice(&data[132..144]);

    let ct_body = data[144..].to_vec();

    Ok(ParsedFile {
        salt,
        nonce_dek,
        wrapped_dek,
        nonce_body,
        canonical_header,
        header_mac,
        ct_body,
        kdf_params,
    })
}

// Odczyt parametrow Argon2id z kanonicznego naglowka (100 B).
fn header_kdf_params(canonical: &[u8]) -> KdfParams {
    KdfParams {
        memory: u32::from_be_bytes(canonical[9..13].try_into().unwrap()),
        iterations: u32::from_be_bytes(canonical[13..17].try_into().unwrap()),
        parallelism: canonical[17] as u32,
    }
}

// ─── stan otwartej sesji ──────────────────────────────────────────────────────

struct Session {
    path: PathBuf,
    // DEK trzymany w pamieci na czas sesji (zeroizowany przy wyjsciu). Body
    // re-szyfrujemy tym samym DEK — bez ponownego Argon2id (spec 7.5).
    dek: Zeroizing<[u8; 32]>,
    canonical_header: Vec<u8>, // 100 B; zmienia sie tylko przy changepass
    header_mac: [u8; 32],      // 32 B; zmienia sie tylko przy changepass
    body: VaultBody,
}

impl Session {
    // Zapis biezacego body na dysk: ten sam naglowek, ten sam DEK, NOWY nonce_body.
    fn save(&self) -> Result<(), String> {
        let body_cbor = format::serialize_body(&self.body);

        let saved = crypto::savecrypto(
            self.dek.as_ref(),
            &self.canonical_header,
            &self.header_mac,
            &body_cbor,
        )
        .map_err(|_| "nie udalo sie zaszyfrowac body".to_string())?;

        let mut bytes =
            Vec::with_capacity(self.canonical_header.len() + 32 + 12 + saved.ct_body.len());
        bytes.extend_from_slice(&self.canonical_header);
        bytes.extend_from_slice(&self.header_mac);
        bytes.extend_from_slice(&saved.nonce_body);
        bytes.extend_from_slice(&saved.ct_body);

        format::atomic_write(&self.path, &bytes)
            .map_err(|e| format!("nie udalo sie zapisac vaulta: {e}"))
    }
}

// ─── komendy sesji (parsowane z linii REPL) ───────────────────────────────────

#[derive(Parser)]
#[command(no_binary_name = true, about = "komendy dostepne w otwartej sesji")]
struct SessionCli {
    #[command(subcommand)]
    cmd: SessionCommand,
}

#[derive(Subcommand)]
enum SessionCommand {
    /// Wyswietla liste rekordow (bez wartosci sekretow).
    List {
        /// Filtruj po typie: login|note|apikey|totp|sshkey|attachment
        #[arg(long = "type")]
        type_filter: Option<String>,
        /// Filtruj po tagu.
        #[arg(long = "tag")]
        tag_filter: Option<String>,
    },
    /// Pokazuje rekord. Z --clip kopiuje pole do schowka zamiast je wyswietlac.
    Get {
        /// Identyfikator (prefiks UUID) lub dokladny tytul.
        id: String,
        /// Skopiuj pole do schowka (czyszczone po 30 s) zamiast wyswietlac sekrety.
        #[arg(long = "clip")]
        clip: bool,
        /// Konkretne pole (z --clip: ktore skopiowac; bez --clip: pokaz tylko jego wartosc).
        #[arg(long = "field")]
        field: Option<String>,
    },
    /// Dodaje rekord interaktywnie.
    Add {
        /// Typ rekordu: login|note|apikey|totp|sshkey
        #[arg(value_name = "TYP")]
        type_name: String,
    },
    /// Edytuje istniejacy rekord.
    Edit {
        /// Identyfikator (prefiks UUID) lub dokladny tytul.
        id: String,
    },
    /// Usuwa rekord (z potwierdzeniem).
    Rm {
        /// Identyfikator (prefiks UUID) lub dokladny tytul.
        id: String,
    },
    /// Zmienia haslo glowne (re-wrap DEK, body bez zmian logicznych).
    Changepass,
    /// Wzmacnia parametry Argon2id (to samo haslo, mocniejszy KDF).
    UpgradeKdf {
        /// Pamiec Argon2id w KiB (min 65536 = 64 MiB; domyslnie 2x biezaca).
        #[arg(long = "memory")]
        memory: Option<u32>,
        /// Liczba iteracji (min 3; domyslnie biezaca + 1).
        #[arg(long = "iterations")]
        iterations: Option<u32>,
        /// Rownoleglosc (min 1; domyslnie biezaca).
        #[arg(long = "parallelism")]
        parallelism: Option<u8>,
    },
    /// Dolacza plik jako rekord typu attachment (max 5 MiB).
    Attach {
        /// Sciezka do pliku do dolaczenia.
        file: PathBuf,
        /// Tytul rekordu (domyslnie nazwa pliku).
        #[arg(long = "title")]
        title: Option<String>,
    },
    /// Wydobywa zalacznik do pliku.
    Extract {
        /// Identyfikator (prefiks UUID) lub dokladny tytul rekordu attachment.
        id: String,
        /// Docelowy plik lub katalog (domyslnie oryginalna nazwa w biezacym katalogu).
        dest: Option<PathBuf>,
    },
    /// Eksportuje WSZYSTKIE rekordy do JAWNEGO (niezaszyfrowanego!) pliku CBOR.
    Export {
        /// Sciezka pliku wyjsciowego.
        file: PathBuf,
        /// Format eksportu (obecnie tylko cbor).
        #[arg(long = "format", default_value = "cbor")]
        format: String,
    },
    /// Importuje rekordy z pliku CBOR i dolacza je do vaulta.
    Import {
        /// Sciezka pliku wejsciowego (CBOR).
        file: PathBuf,
        /// Format importu (obecnie tylko cbor).
        #[arg(long = "format", default_value = "cbor")]
        format: String,
    },
    /// Zamyka sesje.
    #[command(visible_alias = "quit")]
    Exit,
}

// Glowna petla REPL.
fn run_session(session: &mut Session) -> Result<(), String> {
    loop {
        print!("vault> ");
        io::stdout().flush().ok();

        let line = match read_line()? {
            Some(l) => l,
            None => {
                // EOF (Ctrl-Z / Ctrl-D) — koncz sesje.
                println!();
                return Ok(());
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Parsowanie linii jak argv (bez nazwy binarki).
        let sc = match SessionCli::try_parse_from(trimmed.split_whitespace()) {
            Ok(sc) => sc,
            Err(e) => {
                // Bledna komenda / help — wypisz i wroc do petli.
                e.print().ok();
                continue;
            }
        };

        let outcome = match sc.cmd {
            SessionCommand::Exit => return Ok(()),
            SessionCommand::List {
                type_filter,
                tag_filter,
            } => cmd_list(session, type_filter.as_deref(), tag_filter.as_deref()),
            SessionCommand::Get { id, clip, field } => {
                cmd_get(session, &id, clip, field.as_deref())
            }
            SessionCommand::Add { type_name } => cmd_add(session, &type_name),
            SessionCommand::Edit { id } => cmd_edit(session, &id),
            SessionCommand::Rm { id } => cmd_rm(session, &id),
            SessionCommand::Changepass => cmd_changepass(session),
            SessionCommand::UpgradeKdf {
                memory,
                iterations,
                parallelism,
            } => cmd_upgrade_kdf(session, memory, iterations, parallelism),
            SessionCommand::Attach { file, title } => {
                cmd_attach(session, &file, title.as_deref())
            }
            SessionCommand::Extract { id, dest } => cmd_extract(session, &id, dest.as_deref()),
            SessionCommand::Export { file, format } => cmd_export(session, &file, &format),
            SessionCommand::Import { file, format } => cmd_import(session, &file, &format),
        };

        if let Err(e) = outcome {
            eprintln!("blad: {e}");
        }
    }
}

// ─── handlery komend sesji ────────────────────────────────────────────────────

// ### LIST ###
fn cmd_list(
    session: &Session,
    type_filter: Option<&str>,
    tag_filter: Option<&str>,
) -> Result<(), String> {
    let want_type = match type_filter {
        Some(t) => Some(parse_type(t)?),
        None => None,
    };

    let mut shown = 0usize;
    for rec in &session.body.records {
        // Filtry: typ i tag (brak filtra = przepuszcza wszystko).
        let type_ok = want_type.as_ref().is_none_or(|t| &rec.record_type == t);
        let tag_ok = tag_filter.is_none_or(|tag| rec.tags.iter().any(|x| x == tag));
        if !type_ok || !tag_ok {
            continue;
        }

        let tags = if rec.tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", rec.tags.join(", "))
        };
        // Tylko tytuly i metadane — zadnych wartosci sekretow (F-03).
        println!(
            "{}  {:<10}  {}{}",
            format_id(&rec.id),
            type_str(&rec.record_type),
            rec.title,
            tags
        );
        shown += 1;
    }

    if shown == 0 {
        println!("(brak rekordow)");
    }
    Ok(())
}

// ### GET ### — domyslnie wyswietla rekord; z --clip kopiuje pole do schowka.
fn cmd_get(
    session: &Session,
    needle: &str,
    clip: bool,
    field: Option<&str>,
) -> Result<(), String> {
    let idx = find_one(session, needle)?;
    let rec = &session.body.records[idx];

    // --field bez --clip: pokaz tylko wartosc wskazanego pola.
    if !clip && let Some(name) = field {
        let val = rec
            .fields
            .get(name)
            .ok_or_else(|| format!("rekord nie ma pola '{name}'"))?;
        println!("{}", String::from_utf8_lossy(val));
        return Ok(());
    }

    // Naglowek rekordu (zawsze).
    println!("id:       {}", format_id(&rec.id));
    println!("typ:      {}", type_str(&rec.record_type));
    println!("tytul:    {}", rec.title);
    if !rec.tags.is_empty() {
        println!("tagi:     {}", rec.tags.join(", "));
    }
    if !rec.notes.is_empty() {
        println!("notatki:  {}", rec.notes);
    }

    if clip {
        // Tryb schowka: NIE wyswietlamy sekretow, kopiujemy wybrane pole.
        for (name, kind) in field_spec(&rec.record_type) {
            if is_secret(kind) {
                continue;
            }
            if let Some(val) = rec.fields.get(*name) {
                println!("{name:<14}{}", String::from_utf8_lossy(val));
            }
        }

        let target = match field {
            Some(f) => f.to_string(),
            None => primary_field(&rec.record_type)
                .ok_or("ten typ nie ma pola do skopiowania")?
                .to_string(),
        };
        let value = rec
            .fields
            .get(&target)
            .ok_or_else(|| format!("rekord nie ma pola '{target}'"))?;
        let value = String::from_utf8_lossy(value).to_string();

        clipboard_set(&value)?;
        println!("pole '{target}' skopiowane do schowka (wyczyszczone za 30 s).");
        spawn_clipboard_clear(value);
    } else {
        // Tryb domyslny: pokaz wszystkie pola, takze sekretne (sesja uwierzytelniona).
        for (name, _kind) in field_spec(&rec.record_type) {
            if let Some(val) = rec.fields.get(*name) {
                println!("{name:<14}{}", String::from_utf8_lossy(val));
            }
        }
    }

    Ok(())
}

// ### ADD ###
fn cmd_add(session: &mut Session, type_name: &str) -> Result<(), String> {
    let rtype = parse_type(type_name)?;
    if rtype == RecordType::Attachment {
        return Err("zalacznik dodaje sie komenda 'attach <plik>', nie 'add'".into());
    }

    let title = prompt_line("tytul: ")?;
    if title.is_empty() {
        return Err("tytul nie moze byc pusty".into());
    }
    let tags = parse_tags(&prompt_line("tagi (oddzielone przecinkami): ")?);
    let notes = prompt_line("notatki: ")?;

    let mut fields: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (name, kind) in field_spec(&rtype) {
        if let Some(value) = read_field(name, kind, None)? {
            fields.insert((*name).to_string(), value.into_bytes());
        }
    }

    let now = current_time_nanos();
    let record = VaultRecord {
        id: generate_uuid_v4(),
        record_type: rtype,
        title,
        tags,
        notes,
        created_at: now,
        modified_at: now,
        fields,
    };

    let id_str = format_id(&record.id);
    session.body.records.push(record);
    session.save()?;
    println!("dodano rekord: {id_str}");
    Ok(())
}

// ### EDIT ###
fn cmd_edit(session: &mut Session, needle: &str) -> Result<(), String> {
    let idx = find_one(session, needle)?;

    // Pracujemy na kopii, zapisujemy dopiero po udanym zebraniu danych.
    let mut rec = session.body.records[idx].clone();

    println!("(pozostaw puste aby zachowac biezaca wartosc)");

    let new_title = prompt_line(&format!("tytul [{}]: ", rec.title))?;
    if !new_title.is_empty() {
        rec.title = new_title;
    }

    let cur_tags = rec.tags.join(", ");
    let new_tags = prompt_line(&format!("tagi [{cur_tags}]: "))?;
    if !new_tags.is_empty() {
        rec.tags = parse_tags(&new_tags);
    }

    let new_notes = prompt_line(&format!("notatki [{}]: ", rec.notes))?;
    if !new_notes.is_empty() {
        rec.notes = new_notes;
    }

    for (name, kind) in field_spec(&rec.record_type) {
        // Sekrety: read_field nie pokazuje biezacej wartosci (tylko [bez zmian]).
        let current = rec
            .fields
            .get(*name)
            .map(|v| String::from_utf8_lossy(v).to_string());
        if let Some(new_val) = read_field(name, kind, current.as_deref())? {
            rec.fields.insert((*name).to_string(), new_val.into_bytes());
        }
    }

    rec.modified_at = current_time_nanos();
    session.body.records[idx] = rec;
    session.save()?;
    println!("rekord zaktualizowany.");
    Ok(())
}

// ### RM ###
fn cmd_rm(session: &mut Session, needle: &str) -> Result<(), String> {
    let idx = find_one(session, needle)?;
    let title = session.body.records[idx].title.clone();
    let id_str = format_id(&session.body.records[idx].id);

    let confirm = prompt_line(&format!("usunac rekord '{title}' ({id_str})? [t/N]: "))?;
    if !matches!(confirm.to_lowercase().as_str(), "t" | "tak" | "y" | "yes") {
        println!("anulowano.");
        return Ok(());
    }

    session.body.records.remove(idx);
    session.save()?;
    println!("usunieto rekord: {id_str}");
    Ok(())
}

// Wyciaga z kanonicznego naglowka pola potrzebne do re-key.
fn header_components(canonical: &[u8]) -> ([u8; 16], [u8; 12], Vec<u8>, KdfParams) {
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&canonical[19..35]);
    let mut nonce_dek = [0u8; 12];
    nonce_dek.copy_from_slice(&canonical[36..48]);
    let wrapped_dek = canonical[52..100].to_vec();
    (salt, nonce_dek, wrapped_dek, header_kdf_params(canonical))
}

// Po re-key (changepass / upgrade-kdf): buduje nowy naglowek z ChangeCrypto,
// reszyfruje body tym samym DEK i zapisuje atomowo; aktualizuje stan sesji.
fn apply_rekey(
    session: &mut Session,
    change: crypto::ChangeCrypto,
    new_kdf: &KdfParams,
) -> Result<(), String> {
    if change.wrapped_dek.len() != 48 {
        return Err("nieprawidlowa dlugosc wrapped_dek".into());
    }
    let mut wrapped_dek_arr = [0u8; 48];
    wrapped_dek_arr.copy_from_slice(&change.wrapped_dek);

    let new_header = VaultHeader {
        version: 1,
        kdf_memory_kib: new_kdf.memory,
        kdf_iterations: new_kdf.iterations,
        kdf_parallelism: new_kdf.parallelism as u8,
        salt: change.salt,
        nonce_dek: change.nonce_dek,
        wrapped_dek: wrapped_dek_arr,
    };
    let new_canonical = new_header.to_bytes();

    // Nowy header_mac + reszyfracja body tym samym DEK z nowym AAD.
    let body_cbor = format::serialize_body(&session.body);
    let second = crypto::initcryptosecond(
        change.dek.as_ref(),
        change.header_mac_key.as_ref().try_into().unwrap(),
        &new_canonical,
        &body_cbor,
    )
    .map_err(|_| "nie udalo sie zaszyfrowac".to_string())?;

    let mut bytes = Vec::with_capacity(new_canonical.len() + 32 + 12 + second.ct_body.len());
    bytes.extend_from_slice(&new_canonical);
    bytes.extend_from_slice(&second.header_mac);
    bytes.extend_from_slice(&second.nonce_body);
    bytes.extend_from_slice(&second.ct_body);

    format::atomic_write(&session.path, &bytes)
        .map_err(|e| format!("nie udalo sie zapisac vaulta: {e}"))?;

    // Aktualizuj stan sesji (DEK ten sam, naglowek nowy).
    session.dek = change.dek;
    session.canonical_header = new_canonical;
    session.header_mac = second.header_mac;
    Ok(())
}

// ### CHANGEPASS ### — re-wrap tego samego DEK pod nowym haslem (spec 7.6).
fn cmd_changepass(session: &mut Session) -> Result<(), String> {
    let (old_salt, old_nonce_dek, old_wrapped_dek, old_kdf) =
        header_components(&session.canonical_header);

    // Re-uwierzytelnienie: stare haslo, potem nowe (z potwierdzeniem).
    let old_password = Zeroizing::new(
        rpassword::prompt_password("aktualne haslo glowne: ")
            .map_err(|e| format!("nie udalo sie wczytac hasla: {e}"))?,
    );
    let new_password = read_password_with_confirmation()?;

    // changepass zachowuje parametry KDF, zmienia tylko haslo (i salt).
    let new_kdf = KdfParams {
        memory: KDF_MEMORY_KIB,
        iterations: KDF_ITERATIONS,
        parallelism: KDF_PARALLELISM as u32,
    };

    let change = crypto::changecryptofirst(
        old_password.as_bytes(),
        new_password.as_bytes(),
        &old_salt,
        &session.canonical_header,
        &session.header_mac,
        &old_nonce_dek,
        &old_wrapped_dek,
        &old_kdf,
        &new_kdf,
    )
    .map_err(|_| "bledne aktualne haslo lub uszkodzony plik".to_string())?;

    apply_rekey(session, change, &new_kdf)?;
    println!("haslo glowne zmienione.");
    Ok(())
}

// ### UPGRADE-KDF ### — wzmacnia parametry Argon2id, to samo haslo (spec 7.7).
fn cmd_upgrade_kdf(
    session: &mut Session,
    memory: Option<u32>,
    iterations: Option<u32>,
    parallelism: Option<u8>,
) -> Result<(), String> {
    let (old_salt, old_nonce_dek, old_wrapped_dek, old_kdf) =
        header_components(&session.canonical_header);

    // Nowe parametry: z flag albo mocniejsze domyslne (2x pamiec, +1 iteracja).
    let new_kdf = KdfParams {
        memory: memory.unwrap_or(old_kdf.memory.saturating_mul(2)),
        iterations: iterations.unwrap_or(old_kdf.iterations + 1),
        parallelism: parallelism.map(|p| p as u32).unwrap_or(old_kdf.parallelism),
    };

    // Nie pozwalamy oslabic vaulta ani zejsc ponizej minimum NF-02.
    if new_kdf.memory < KDF_MEMORY_KIB || new_kdf.memory < old_kdf.memory {
        return Err(format!(
            "pamiec nie moze byc mniejsza niz {KDF_MEMORY_KIB} KiB ani niz biezaca ({} KiB)",
            old_kdf.memory
        ));
    }
    if new_kdf.iterations < KDF_ITERATIONS || new_kdf.iterations < old_kdf.iterations {
        return Err(format!(
            "liczba iteracji nie moze byc mniejsza niz {KDF_ITERATIONS} ani niz biezaca ({})",
            old_kdf.iterations
        ));
    }
    if new_kdf.parallelism < 1 {
        return Err("rownoleglosc musi byc >= 1".into());
    }

    let password = read_password()?;

    let change = crypto::upgradekdf(
        password.as_bytes(),
        &old_salt,
        &session.canonical_header,
        &session.header_mac,
        &old_nonce_dek,
        &old_wrapped_dek,
        &old_kdf,
        &new_kdf,
    )
    .map_err(|_| "bledne haslo lub uszkodzony plik".to_string())?;

    apply_rekey(session, change, &new_kdf)?;
    println!(
        "parametry KDF zaktualizowane: pamiec={} KiB, iteracje={}, rownoleglosc={}.",
        new_kdf.memory, new_kdf.iterations, new_kdf.parallelism
    );
    Ok(())
}

// ### ATTACH ### — dolacza plik jako rekord typu attachment (max 5 MiB).
fn cmd_attach(session: &mut Session, file: &Path, title: Option<&str>) -> Result<(), String> {
    let data = std::fs::read(file).map_err(|e| format!("nie udalo sie odczytac pliku: {e}"))?;
    if data.len() as u64 > MAX_ATTACHMENT {
        return Err(format!(
            "plik ma {} B — limit to {} B (5 MiB)",
            data.len(),
            MAX_ATTACHMENT
        ));
    }

    let filename = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "zalacznik".to_string());
    let mime = guess_mime(file);
    let size = data.len();

    let mut fields: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    fields.insert("filename".to_string(), filename.clone().into_bytes());
    fields.insert("mime_type".to_string(), mime.into_bytes());
    fields.insert("size".to_string(), size.to_string().into_bytes());
    fields.insert("data".to_string(), data);

    let now = current_time_nanos();
    let record = VaultRecord {
        id: generate_uuid_v4(),
        record_type: RecordType::Attachment,
        title: title.unwrap_or(&filename).to_string(),
        tags: Vec::new(),
        notes: String::new(),
        created_at: now,
        modified_at: now,
        fields,
    };

    let id_str = format_id(&record.id);
    session.body.records.push(record);
    session.save()?;
    println!("dolaczono zalacznik '{filename}' ({size} B): {id_str}");
    Ok(())
}

// ### EXTRACT ### — zapisuje dane zalacznika do pliku.
fn cmd_extract(session: &Session, needle: &str, dest: Option<&Path>) -> Result<(), String> {
    let idx = find_one(session, needle)?;
    let rec = &session.body.records[idx];

    let data = rec
        .fields
        .get("data")
        .ok_or("rekord nie zawiera danych zalacznika (pole 'data')")?;

    let filename = rec
        .fields
        .get("filename")
        .map(|v| String::from_utf8_lossy(v).to_string())
        .unwrap_or_else(|| "zalacznik".to_string());

    // Sciezka docelowa: brak -> nazwa oryginalna; katalog -> nazwa w nim.
    let out_path = match dest {
        None => PathBuf::from(&filename),
        Some(p) if p.is_dir() => p.join(&filename),
        Some(p) => p.to_path_buf(),
    };

    if out_path.exists() {
        return Err(format!(
            "plik {} juz istnieje — podaj inna sciezke",
            out_path.display()
        ));
    }

    std::fs::write(&out_path, data).map_err(|e| format!("nie udalo sie zapisac pliku: {e}"))?;
    println!("zapisano {} B do {}", data.len(), out_path.display());
    Ok(())
}

// ### EXPORT ### — jawny (niezaszyfrowany) zrzut rekordow do CBOR (F-10).
fn cmd_export(session: &Session, file: &Path, format: &str) -> Result<(), String> {
    if !format.eq_ignore_ascii_case("cbor") {
        return Err(format!("nieobslugiwany format '{format}' — dostepny: cbor"));
    }
    if file.exists() {
        return Err(format!(
            "plik {} juz istnieje — podaj inna sciezke",
            file.display()
        ));
    }

    // Glosne ostrzezenie + potwierdzenie (F-10): to jawny plik ze WSZYSTKIMI sekretami.
    println!("!!! UWAGA: eksport tworzy JAWNY, NIEZASZYFROWANY plik ze wszystkimi sekretami.");
    println!("!!! Kazdy z dostepem do niego odczyta Twoje hasla. Trzymaj go bezpiecznie i usun po uzyciu.");
    let confirm = prompt_line(&format!("kontynuowac eksport do {}? [t/N]: ", file.display()))?;
    if !matches!(confirm.to_lowercase().as_str(), "t" | "tak" | "y" | "yes") {
        println!("anulowano.");
        return Ok(());
    }

    let bytes = format::serialize_body(&session.body);
    std::fs::write(file, &bytes).map_err(|e| format!("nie udalo sie zapisac eksportu: {e}"))?;
    println!(
        "wyeksportowano {} rekordow do {}",
        session.body.records.len(),
        file.display()
    );
    Ok(())
}

// ### IMPORT ### — wczytuje rekordy z pliku CBOR i dolacza je do vaulta (F-11).
fn cmd_import(session: &mut Session, file: &Path, format: &str) -> Result<(), String> {
    if !format.eq_ignore_ascii_case("cbor") {
        return Err(format!("nieobslugiwany format '{format}' — dostepny: cbor"));
    }

    let data = std::fs::read(file).map_err(|e| format!("nie udalo sie odczytac pliku: {e}"))?;
    let imported: VaultBody = ciborium::from_reader(data.as_slice())
        .map_err(|_| "plik nie jest poprawnym eksportem CBOR".to_string())?;

    let total = imported.records.len();
    if total == 0 {
        println!("brak rekordow do zaimportowania.");
        return Ok(());
    }

    // Pomijamy rekordy o id juz obecnym (ochrona przed podwojnym importem).
    let existing: std::collections::HashSet<[u8; 16]> =
        session.body.records.iter().map(|r| r.id).collect();
    let mut added = 0usize;
    for rec in imported.records {
        if existing.contains(&rec.id) {
            continue;
        }
        session.body.records.push(rec);
        added += 1;
    }

    session.save()?;
    println!(
        "zaimportowano {added} z {total} rekordow ({} pominieto jako duplikaty)",
        total - added
    );
    Ok(())
}

// Zgaduje typ MIME na podstawie rozszerzenia (proste, bez zaleznosci).
fn guess_mime(file: &Path) -> String {
    let ext = file
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let mime = match ext.as_str() {
        "txt" => "text/plain",
        "md" => "text/markdown",
        "json" => "application/json",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "zip" => "application/zip",
        "csv" => "text/csv",
        _ => "application/octet-stream",
    };
    mime.to_string()
}

// ─── helpery: typy rekordow ───────────────────────────────────────────────────

fn parse_type(s: &str) -> Result<RecordType, String> {
    match s.to_lowercase().as_str() {
        "login" => Ok(RecordType::Login),
        "note" => Ok(RecordType::Note),
        "apikey" => Ok(RecordType::Apikey),
        "totp" => Ok(RecordType::Totp),
        "sshkey" => Ok(RecordType::Sshkey),
        "attachment" => Ok(RecordType::Attachment),
        other => Err(format!("nieznany typ rekordu: '{other}'")),
    }
}

fn type_str(t: &RecordType) -> &'static str {
    match t {
        RecordType::Login => "login",
        RecordType::Note => "note",
        RecordType::Apikey => "apikey",
        RecordType::Totp => "totp",
        RecordType::Sshkey => "sshkey",
        RecordType::Attachment => "attachment",
    }
}

// Rodzaj pola — steruje sposobem wczytywania i walidacja w add/edit.
enum FieldKind {
    Text,                                          // dowolny tekst, widoczny
    Secret,                                        // dowolny tekst, bez echo (F-19)
    Base32Secret,                                  // sekret bez echo + walidacja base32
    Choice(&'static [&'static str], &'static str), // dozwolone wartosci + domyslna
}

fn is_secret(kind: &FieldKind) -> bool {
    matches!(kind, FieldKind::Secret | FieldKind::Base32Secret)
}

// Pola specyficzne dla typu (spec §4.2). TOTP ma ograniczone wartosci (RFC 6238).
fn field_spec(t: &RecordType) -> &'static [(&'static str, FieldKind)] {
    match t {
        RecordType::Login => &[
            ("url", FieldKind::Text),
            ("username", FieldKind::Text),
            ("password", FieldKind::Secret),
        ],
        RecordType::Note => &[("content", FieldKind::Text)],
        RecordType::Apikey => &[
            ("key", FieldKind::Secret),
            ("environment", FieldKind::Text),
            ("expires_at", FieldKind::Text),
        ],
        RecordType::Totp => &[
            ("secret_base32", FieldKind::Base32Secret),
            (
                "algorithm",
                FieldKind::Choice(&["SHA1", "SHA256", "SHA512"], "SHA1"),
            ),
            ("digits", FieldKind::Choice(&["6", "8"], "6")),
            ("period", FieldKind::Choice(&["30", "60"], "30")),
        ],
        RecordType::Sshkey => &[
            ("public_key", FieldKind::Text),
            ("private_key", FieldKind::Secret),
            ("passphrase", FieldKind::Secret),
        ],
        RecordType::Attachment => &[
            ("filename", FieldKind::Text),
            ("mime_type", FieldKind::Text),
            ("size", FieldKind::Text),
        ],
    }
}

// Wczytuje jedno pole wg jego rodzaju. Zwraca:
//   Some(v) -> ustaw wartosc v,  None -> pomin (w add: nie ustawiaj; w edit: zachowaj).
// `current` = biezaca wartosc (Some tylko w edit); dla sekretow nie jest wyswietlana.
fn read_field(
    name: &str,
    kind: &FieldKind,
    current: Option<&str>,
) -> Result<Option<String>, String> {
    match kind {
        FieldKind::Text => {
            let prompt = match current {
                Some(c) => format!("{name} [{c}]: "),
                None => format!("{name}: "),
            };
            let v = prompt_line(&prompt)?;
            Ok(if v.is_empty() { None } else { Some(v) })
        }
        FieldKind::Secret | FieldKind::Base32Secret => {
            // Base32Secret dostaje podpowiedz o oczekiwanym formacie.
            let label = if matches!(kind, FieldKind::Base32Secret) {
                format!("{name} (base32, z aplikacji 2FA)")
            } else {
                name.to_string()
            };
            let prompt = match current {
                Some(_) => format!("{label} [bez zmian]: "),
                None => format!("{label}: "),
            };
            let v = rpassword::prompt_password(prompt)
                .map_err(|e| format!("nie udalo sie wczytac '{name}': {e}"))?;
            if v.is_empty() {
                return Ok(None);
            }
            if matches!(kind, FieldKind::Base32Secret) {
                let normalized = normalize_base32(&v).ok_or_else(|| {
                    format!("'{name}' nie jest poprawnym base32 (dozwolone A-Z, 2-7)")
                })?;
                Ok(Some(normalized))
            } else {
                Ok(Some(v))
            }
        }
        FieldKind::Choice(allowed, default) => {
            let hint = allowed.join("|");
            let prompt = match current {
                Some(c) => format!("{name} ({hint}) [{c}]: "),
                None => format!("{name} ({hint}) [{default}]: "),
            };
            let v = prompt_line(&prompt)?;
            if v.is_empty() {
                // W add (brak current) zastosuj domyslna; w edit zachowaj biezaca.
                return Ok(if current.is_none() {
                    Some((*default).to_string())
                } else {
                    None
                });
            }
            match allowed.iter().find(|a| a.eq_ignore_ascii_case(&v)) {
                Some(canon) => Ok(Some((*canon).to_string())),
                None => Err(format!("'{name}' musi byc jedna z: {hint}")),
            }
        }
    }
}

// dopuszcza tylko A-Z, 2-7 oraz padding '='. Zwraca None jesli niepoprawne/puste.
fn normalize_base32(s: &str) -> Option<String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    if cleaned.is_empty() {
        return None;
    }
    if cleaned.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7' | '=')) {
        Some(cleaned)
    } else {
        None
    }
}

// Glowne pole kopiowane do schowka przez `get` (gdy nie podano --field).
fn primary_field(t: &RecordType) -> Option<&'static str> {
    match t {
        RecordType::Login => Some("password"),
        RecordType::Note => Some("content"),
        RecordType::Apikey => Some("key"),
        RecordType::Totp => Some("secret_base32"),
        RecordType::Sshkey => Some("private_key"),
        RecordType::Attachment => None,
    }
}

// ─── helpery: wyszukiwanie rekordow ───────────────────────────────────────────

fn format_id(id: &[u8; 16]) -> String {
    uuid::Uuid::from_bytes(*id).to_string()
}

// Dopasowanie po dokladnym tytule lub po prefiksie UUID (hex, ignoruje myslniki).
fn find_records(session: &Session, needle: &str) -> Vec<usize> {
    let needle_l = needle.to_lowercase();
    let needle_hex = needle_l.replace('-', "");
    let hex_query = !needle_hex.is_empty() && needle_hex.chars().all(|c| c.is_ascii_hexdigit());

    let mut hits = Vec::new();
    for (i, rec) in session.body.records.iter().enumerate() {
        if rec.title.to_lowercase() == needle_l {
            hits.push(i);
            continue;
        }
        if hex_query {
            let id_hex = format_id(&rec.id).replace('-', "");
            if id_hex.starts_with(&needle_hex) {
                hits.push(i);
            }
        }
    }
    hits
}

// Zwraca dokladnie jeden indeks albo blad (brak / wieloznaczne).
fn find_one(session: &Session, needle: &str) -> Result<usize, String> {
    let hits = find_records(session, needle);
    match hits.len() {
        0 => Err(format!("nie znaleziono rekordu: '{needle}'")),
        1 => Ok(hits[0]),
        n => Err(format!(
            "'{needle}' pasuje do {n} rekordow — podaj dluzszy prefiks id"
        )),
    }
}

fn parse_tags(s: &str) -> Vec<String> {
    s.split(',')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

// ─── helpery: wejscie / hasla ─────────────────────────────────────────────────

// Czyta jedna linie z REPL. Zwraca None na EOF.
fn read_line() -> Result<Option<String>, String> {
    let mut s = String::new();
    let n = io::stdin()
        .read_line(&mut s)
        .map_err(|e| format!("blad odczytu wejscia: {e}"))?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(s.trim_end_matches(['\n', '\r']).to_string()))
}

// Wypisuje prompt i czyta jedna (widoczna) linie tekstu.
fn prompt_line(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    io::stdout().flush().ok();
    match read_line()? {
        Some(s) => Ok(s),
        None => Err("nieoczekiwany koniec wejscia".into()),
    }
}

// Wczytuje haslo bez echo (F-19) i prosi o potwierdzenie.
fn read_password_with_confirmation() -> Result<Zeroizing<String>, String> {
    let p1 = rpassword::prompt_password("haslo glowne: ")
        .map_err(|e| format!("nie udalo sie wczytac hasla: {e}"))?;
    let p1 = Zeroizing::new(p1);

    let p2 = rpassword::prompt_password("powtorz haslo: ")
        .map_err(|e| format!("nie udalo sie wczytac hasla: {e}"))?;
    let p2 = Zeroizing::new(p2);

    // Stalo-czasowe porownanie.
    if p1.len() != p2.len() || !constant_time_eq(p1.as_bytes(), p2.as_bytes()) {
        return Err("hasla sie nie zgadzaja".into());
    }

    if p1.is_empty() {
        return Err("haslo nie moze byc puste".into());
    }

    Ok(p1)
}

// Wczytuje haslo bez potwierdzenia (uzywane przez `open` i `verify`).
fn read_password() -> Result<Zeroizing<String>, String> {
    let p = rpassword::prompt_password("haslo glowne: ")
        .map_err(|e| format!("nie udalo sie wczytac hasla: {e}"))?;
    Ok(Zeroizing::new(p))
}

// Stalo-czasowe porownanie bajtow (rowne dlugosci sprawdzane wczesniej).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ─── helpery: schowek (Windows, F-04 / F-18) ──────────────────────────────────
// Bez dodatkowej zaleznosci (whitelist §10.2) — uzywamy wbudowanego clip.exe.

fn clipboard_set(value: &str) -> Result<(), String> {
    let mut child = OsCommand::new("clip")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("nie udalo sie uruchomic clip.exe: {e}"))?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or("brak strumienia wejscia dla clip.exe")?;
        stdin
            .write_all(value.as_bytes())
            .map_err(|e| format!("zapis do schowka nie powiodl sie: {e}"))?;
    }

    child
        .wait()
        .map_err(|e| format!("clip.exe zakonczyl sie bledem: {e}"))?;
    Ok(())
}

// F-18 Tryb --clip automatycznie czyści schowek po 30 s, ale tylko jeśli zawartość schowka
// nadal jest wartością skopiowaną przez vault.
fn spawn_clipboard_clear(value: String) {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(30));

        let current = OsCommand::new("powershell")
            .args(["-NoProfile", "-Command", "Get-Clipboard"])
            .output();

        if let Ok(out) = current {
            let now = String::from_utf8_lossy(&out.stdout);
            let now = now.trim_end_matches(['\r', '\n']);
            if now == value {
                let _ = OsCommand::new("powershell")
                    .args(["-NoProfile", "-Command", "Set-Clipboard -Value ''"])
                    .output();
            }
        }
    });
}
