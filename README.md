# vault — bezpieczny menedżer sekretów

`vault` to narzędzie wiersza poleceń (CLI) do przechowywania poświadczeń — loginów,
haseł, kluczy API, sekretów TOTP, kluczy SSH i krótkich załączników — w **jednym
pliku zaszyfrowanym hasłem głównym**.

Szyfrowanie opiera się na sprawdzonych prymitywach: **Argon2id** (wyprowadzanie klucza
z hasła), **ChaCha20-Poly1305** (szyfrowanie uwierzytelnione) i **HMAC-SHA256**
(integralność nagłówka). Hasło główne nigdy nie jest zapisywane na dysk; bez niego
zawartości nie da się odzyskać.

> Projekt zespołowy — Kryptologia i Cyberbezpieczeństwo - Systemy kryptograficzne

---

## Instalacja

Potrzebujesz tylko **Windows x86_64**. Są dwie drogi:

### Opcja A — gotowy plik (bez kompilacji)

1. Pobierz `vault.exe`
2. Umieść go w dowolnym folderze i uruchamiaj z **wiersza poleceń (cmd)**.

To program konsolowy — uruchamiaj go z `cmd`, nie dwuklikiem.

### Opcja B — zbuduj samodzielnie ze źródeł

Wymaga zainstalowanego **Rusta** (<https://rustup.rs>). Po sklonowaniu repozytorium,
w katalogu projektu:

```sh
cargo build --release
```

Gotowa binarka: `target/release/vault.exe`.

> Aby wołać `vault` z dowolnego katalogu, dodaj folder z `vault.exe` do zmiennej
> `PATH`, albo zainstaluj globalnie: `cargo install --path .`

## Szybki start

Jedna komenda wystarczy, aby utworzyć i otworzyć vault:

```sh
vault.exe init test.db
```

Program poprosi o hasło główne (z potwierdzeniem), tworzy plik `test.db` i gotowe.

## Podstawowe komendy

`vault` działa w trybie **sesji**: `open` raz weryfikuje hasło i otwiera sesję,
w której wykonujesz kolejne komendy bez ponownego wpisywania hasła.

```text
vault.exe init test.db               # utwórz nowy vault
vault.exe open test.db               # otwórz sesję (pyta o hasło)
  vault> add login                   # dodaj rekord (interaktywnie)
  vault> list                        # lista rekordów (bez wartości sekretów)
  vault> list --type=login           # filtr po typie
  vault> get <id|tytuł>              # pokaż rekord
  vault> get <id> --clip             # skopiuj sekret do schowka (czyści się po 30 s)
  vault> edit <id|tytuł>             # edytuj rekord
  vault> rm <id|tytuł>               # usuń rekord (z potwierdzeniem)
  vault> changepass                  # zmień hasło główne
  vault> attach plik.pdf             # dołącz plik (≤ 5 MiB)
  vault> extract <id> kopia.pdf      # wyodrębnij załącznik
  vault> help                        # pełna lista komend
  vault> exit                        # zamknij sesję

vault.exe verify test.db                 # sprawdź strukturę pliku (bez hasła)
vault.exe verify test.db --with-password # pełna weryfikacja integralności
```

Hasła i sekrety wprowadzasz interaktywnie, **bez echa** (nie są nigdy przekazywane
w argumentach linii poleceń).

Dostępne typy rekordów: `login`, `note`, `apikey`, `totp`, `sshkey` oraz `attachment`
(dodawany komendą `attach`).

## FAQ

**Zapomniałem hasła głównego — da się odzyskać dane?**
Nie. Nie ma żadnej furtki powrotnej ani odzyskiwania — to istota bezpieczeństwa. Bez hasła
plik jest bezużyteczny. Trzymaj hasło w bezpiecznym miejscu.

**Gdzie trzymać plik vaulta?**
Gdziekolwiek — to jeden zwykły plik. Rób kopie zapasowe

**Dwuklik nic nie robi.**
`vault` to aplikacja konsolowa. Otwórz `cmd`, przejdź do folderu z plikiem i wpisz
np. `vault.exe init test.db`.

**Przy haśle nic się nie wyświetla.**
Tak ma być — pole hasła nie pokazuje znaków (tryb bez echa), żeby nikt nie podejrzał.

**Jak wołać po prostu `vault` zamiast `vault.exe` z pełną ścieżką?**
Dodaj folder z `vault.exe` do zmiennej środowiskowej `PATH`, albo zbuduj ze źródeł
i uruchom `cargo install --path .`.

**Czy działa na Linux/macOS?**
Oficjalna binarka jest pod Windows x86_64. Ze źródeł (`cargo build --release`) można
zbudować na innych systemach, ale nie są one wspierane w tej wersji.

## Bezpieczeństwo w skrócie

- **Wszystko chroni jedno hasło główne.** Cała zawartość pliku jest nim zaszyfrowana.
  Nikt — łącznie z autorami programu — nie odczyta jej bez tego hasła. Nie ma żadnej
  furtki ani odzyskiwania.
- **Twoje hasło to klucz do wszystkiego.** Siła ochrony zależy od siły hasła. Użyj
  **długiego, unikalnego** hasła głównego (najlepiej kilka słów). Słabe hasło można
  złamać, choć program celowo robi to bardzo powolnym i kosztownym.
- **Hasło nigdzie nie jest zapisywane** ani pokazywane na ekranie. Sekrety wpisujesz
  „w ciemno" (bez widocznych znaków).

*Praktyczne rady:** używaj mocnego hasła, rób kopie zapasowe pliku, a po pracy zamykaj
sesję komendą `exit`.

Plik można zweryfikować w następujący sposób:
```sh
gpg --import Igor_Raszkiewicz_0x7C43F6F7C217808F_public.asc
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS
```
  
Fingerprint: `417A9D165CCC244552A0ECAE7C43F6F7C217808F`
