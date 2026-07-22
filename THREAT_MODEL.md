

# Threat Model

## 1. Opis systemu

Aplikacja jest lokalnym menedżerem sekretów działającym poprzez CLI.  
Dane użytkownika są przechowywane w pojedynczym zaszyfrowanym pliku `.vault`.

Dostęp do danych chroniony jest hasłem głównym podawanym przez użytkownika.  
Z hasła, przy użyciu funkcji Argon2id, wyprowadzany jest klucz główny (`master_key`), który służy do wyprowadzenia klucza opakowującego (`wrap_key`).

`wrap_key` używany jest do odszyfrowania losowo generowanego klucza DEK (`Data Encryption Key`), którym szyfrowana jest zawartość sejfu.

Aplikacja obsługuje:

- loginy i hasła,
- klucze API,
- sekrety TOTP,
- klucze SSH,
- małe pliki binarne (do 5 MiB).

Za pomocą CLI można wykonać następujące działania:

- utworzenie nowego sejfu,
- otwarcie sejfu,
- wylistowanie rekordów,
- pobranie rekordu,
- dodanie rekordu,
- edycję rekordu,
- usunięcie rekordu,
- zmianę hasła głównego,
- aktualizację parametrów KDF,
- dodanie załącznika,
- wyciągnięcie załącznika,
- import rekordów z JSON,
- eksport sejfu do JSON,
- sprawdzenie struktury sejfu,
- sprawdzenie integralności sejfu.

Aplikacja działa wyłącznie lokalnie na urządzeniu użytkownika.  
Nie zapewnia synchronizacji z chmurą, współdzielenia sekretów ani obsługi wielu użytkowników.

---

# 2. Zasoby (Assets)

| Zasób | Dlaczego ważny? |
|---|---|
| Sekrety użytkownika | Główny cel ochrony systemu; wymagają zachowania poufności i integralności |
| Hasło główne użytkownika | Pozwala wyprowadzić `master_key` i uzyskać dostęp do sejfu; jeśli ktoś je pozna, może odszyfrować cały sejf - odpowiedzialność za utrzymanie hasła w tajemnicy jest po stronie użytkownika |
| `master_key` | Umożliwia wyprowadzenie `wrap_key` oraz `header_mac_key`; jeśli ktoś je pozna, może doprowadzić do kompromitacji sejfu |
| `wrap_key` | Służy do odszyfrowania DEK; jeśli ktoś je pozna, może odszyfrować DEK i dostać się do sekretów |
| DEK | Losowe, służy do szyfrowania i odszyfrowywania zawartości sejfu; jeśli ktoś je pozna, może odszyfrować treść sekretów |
| `header_mac_key` | Umożliwia weryfikację integralności nagłówka; jego kompromitacja pozwala tworzyć poprawne MAC dla zmodyfikowanych metadanych |
| Integralność sejfu | Zapewnia wykrywanie manipulacji danymi, parametrami kryptograficznymi i strukturą vaulta |

---

# 3. Aktorzy i przeciwnicy

## User

Właściciel vaulta, zna hasło główne.

### Co robi?

- wpisuje hasło,
- korzysta z CLI,
- dodaje sekrety.

---

## Złodziej urządzenia

Osoba posiadająca fizyczny dostęp do laptopa/dysku/pliku `.vault`, ale nieznająca hasła.

### Opis

Najważniejszy przeciwnik w modelu zagrożeń tej aplikacji. Atakujący ma pełny dostęp do pliku vaulta, ale nie ma dostępu do działającej sesji użytkownika ani pamięci RAM procesu

### Co robi? 

- próbuje odgadnąć hasło metodą brute force offline, 
-	analizuje strukturę pliku, 
-	próbuje odzyskać DEK z opakowanego DEK, 
-	wykonuje ataki słownikowe na hasło użytkownika, 
-	próbuje wykorzystać słabe parametry KDF

---

## Local attacker

Osoba mająca możliwość modyfikacji pliku `.vault` na dysku użytkownika

### Opis

Nie musi znać hasła użytkownika. Próbuje manipulować strukturą pliku lub metadanymi kryptograficznymi w celu naruszenia integralności sejfu lub wywołania niepoprawnego działania aplikacji

### Co robi?

-	zmienia bajty ciphertextu body, 
-	modyfikuje parametry Argon2id, 
-	Podmienia opakowany DEK, 
-	zmienia identyfikator algorytmu AEAD, 
-	ucina plik (truncation attack), 
-	dostarcza uszkodzony lub niepoprawny plik wejściowy w celu niekontrolowanego zachowania aplikacji


---

## Curious admin

Administrator systemu lub osoba z podwyższonymi uprawnieniami mająca dostęp do plików użytkownika

### Opis

Atakujący może kopiować pliki znajdujące się na urządzeniu użytkownika, ale nie posiada hasła głównego i nie ma dostępu do pamięci procesu podczas otwartej sesji

### Co robi?

-	kopiuje plik .vault,
-	wykonuje ataki offline, 
-	analizuje metadane vaulta, 
-	próbuje wykonać brute force hasła

---

## Attacker posiadający starą kopię sejfu

Osoba posiadająca starą wersję vaulta oraz stare hasło.

### Opis

Przeciwnik próbuje uzyskać dostęp do aktualnej wersji sejfu po wykonaniu operacji changepass

### Co robi?

-	używa starego hasła do odszyfrowania nowej wersji vaulta, 
-	porównuje stare i nowe wersje pliku, 
- próbuje odzyskać aktualny DEK

---

## Malware *(out of scope)*

Złośliwe oprogramowanie działające na urządzeniu użytkownika.

### Opis

Atakujący posiada możliwość wykonywania kodu na urządzeniu użytkownika

### Co robi?

-	przechwytuje hasło główne (keylogger), 
-	odczytuje klucze z pamięci RAM, 
-	przechwytuje odszyfrowane dane podczas działania aplikacji, 
- modyfikuje proces aplikacji

---

## Attacker z dostępem do RAM *(out of scope)*

Zaawansowany przeciwnik posiadający możliwość analizy pamięci procesu

### Opis

Atakujący ma dostęp do pamięci RAM podczas otwartej sesji i może próbować odzyskać klucze kryptograficzne

### Co robi?

-	wykonuje memory dump procesu, 
-	analizuje pamięć RAM, 
-	próbuje odzyskać master_key, wrap_key, DEK

---

## Remote attacker *(out of scope)*

Atakujący próbujący uzyskać zdalny dostęp przez sieć.

Aplikacja nie posiada interfejsów sieciowych.

---

# 4. Założenia bezpieczeństwa

## System zakłada

- poprawne działanie systemu operacyjnego,
- system operacyjny dostarcza kryptograficznie bezpieczny generator liczb pseudolosowych (CSPRNG) o wystarczającej entropii,
- brak aktywnego malware,
- stosowanie silnego hasła głównego,
- poprawne działanie i odporność na typowe ataki side-channel używanych implementacji kryptograficznych.

## System nie chroni przed

-	podatnościami i błędami implementacji używanych bibliotek kryptograficznych
-	malware działającym z uprawnieniami użytkownika, 
- odczytem pamięci RAM przez przeciwnika podczas otwartej sesji, 
-	phishingiem hasła głównego użytkownika
- złośliwie zmodyfikowaną wersją aplikacji lub jej zależności (supply-chain attack) 


---

# 5. Powierzchnia ataku

| Element | Możliwy atak |
|---|---|
| CLI input | Niepoprawne argumenty CLI/malformed input, path manipulation, argument injection |
| Parser vaulta | malformed file, fuzzing |
| Hasło główne | brute force |
| Format vaulta | Manipulacja nagłówkiem, downgrade attack, replay starych danych, podmiana wrapped DEK, truncation |
| Import/export | Malicious JSON, malformed import, parser abuse, huge payload, path manipulation |
| Operacje na pliku | Race conditions, partial write, zniszczenie danych, overwrite attack |
| Załączniki | Parser binarny, duże pliki, malformed binary |
| RAM | extraction attack *(out of scope)* |

---

# 6. Scenariusze zagrożeń

## Offline brute-force attack

### Atak

Atakujący posiada plik .vault i próbuje odgadnąć hasło główne metodą brute force lub słownikową, wykonując wszystkie operacje offline (bez limitów prób)

### Wpływ

jeżeli uda się złamać hasło - pełna kompromitacja sejfu, dostęp do wszystkich sekretów; wpływ na poufność, brak wpływu na integralność

### Prawdopodobieństwo

średnie - zależy od siły hasła użytkownika; Argon2id znacząco podnosi koszt ataku

### Zabezpieczenia

Argon2id z KDF o wysokim koszcie obliczeniowym, inna sól dla każdego sejfu, losowy DEK, key wrapping

---

## Vault tampering

### Atak

Atakujący modyfikuje plik .vault poprzez:
-	Zmianę szyfrogramu,
-	Manipulację nagłówkiem,
-	Podmienienie wrapped DEK,
-	Zmainę parametrów KDF/AEAD na słabsze


### Wpływ

-	brak dostępu do danych (jeśli wykryte), 
-	potencjalne uszkodzenie pliku, 
-	próby downgrade attack, 
- ryzyko crasha przy złej implementacji (jeśli brak walidacji)

### Prawdopodobieństwo

wysokie - atakujący ma łatwy dostęp do pliku, atak nie wymaga wiedzy o kryptografii

### Zabezpieczenia

-	AEAD (integralność body), 
-	AAD (binding nagłówka do szyfrogramu), 
-	HMAC nagłówka, 
-	canonical header (ochrona przed zmianą parametrów), 
-	walidacja struktury pliku

---

## Malformed file / fuzzing attack

### Atak

Atakujący dostarcza uszkodzony lub pusty vault/losowe bajty/niezgodne długości pól/dane o innym formacie niż zakłada program

### Wpływ

crash aplikacji, niekontrolowane błędy parsera, potencjalne luki memory safety (przy błędnej implementacji)

### Prawdopodobieństwo

średnie - atak łatwy do wykonania, często używany w testach automatycznych

### Zabezpieczenia

-	walidacja formatu, 
-	bezpieczne parsowanie (bounds checking), 
-	fuzz testing parsera, 
-	kontrolowana obsługa błędów (no crash policy)

---

## Path manipulation / argument injection

### Atak

Atakujący podaje złośliwe argumenty CLI:
-	../ (path traversal), 
-	nadpisanie plików systemowych, 
-	niepoprawne flagi, 
-	manipulacja wejściem CLI

### Wpływ

-	dostęp do nieautoryzowanych plików, 
-	nadpisanie danych, 
-	uszkodzenie vaulta

### Prawdopodobieństwo

niskie/średnie - zależy od implementacji CLI i walidacji ścieżek

### Zabezpieczenia

-	whitelist ścieżek (ograniczenie dostępu tylko do katalogu vaulta)
-	canonicalization path,
-	brak shell execution

---

## Malicious import / export attack

### Atak

Atakujący dostarcza:
•	złośliwy JSON, 
•	bardzo duży payload, 
•	niepoprawne struktury, 
•	dane próbujące obejść walidację

### Wpływ

-	wstrzyknięcie fałszywych rekordów, 
-	crash parsera,
-	DoS (memory exhaustion),
-	uszkodzenie vaulta po imporcie

### Prawdopodobieństwo

średnie - import/export to typowy punkt wejścia

### Zabezpieczenia

-	schema validation JSON,
-	limit rozmiaru payloadu, 
-	sanity checks, 
-	walidacja rekordów przed zapisaniem

---

## Replay attack

### Atak

Atakujący używając starej kopii vaulta i starego hasła próbuje odczytać lub mieszać wersje plików

### Wpływ

-	dostęp do starych danych, 
-	brak wpływu na aktualny vault, 
-	ryzyko konfuzji wersji danych

### Prawdopodobieństwo

niskie - wymaga wcześniejszego wycieku

### Zabezpieczenia

- Strict format validation – brak kompatybilności po zmianie hasła
- nowy DEK po zmianie hasła, 
- versioning i integrity check headera


---

## Truncation / partial write attack

### Atak

Atakujący wykorzystuje plik .vault który jest ucięty, częściowo zapisany lub uszkodzony

### Wpływ

-	utrata dostępu do danych, 
-	wykrycie błędu integralności

### Prawdopodobieństwo

średnie - możliwe przy crashu systemu lub przerwaniu zapisu

### Zabezpieczenia

-	atomic write (temp + rename), 
-	Fsync (wymuszenie zapisu na dysk przed finalizacją)
-	AEAD tag verification, 
-	HMAC nagłówka

---

## Large attachment / DoS attack

### Atak

Atakujący importuje dane wymuszające wysokie zużycie pamięci (np. bardzo duże załączniki)

### Wpływ

-	DoS aplikacji, 
-	spowolnienie, 
-	potencjalny crash przez memory exhaustion

### Prawdopodobieństwo

średnie - atak łatwy do wykonania

### Zabezpieczenia

- limit 5 MiB per attachment, 
- limit całkowity vaulta, 
- walidacja rozmiarów przed deserializacją


---

## Error oracle / timing side-channel attack

### Atak

Atakujący wielokrotnie podaje różne hasła i modyfikuje plik vaulta. W ten sposób obeserwuje różnice w komunikatach błędów (error oracle) i czas odpowiedzi systemu (timing oracle). Za pomocą tych komunikatów próbuje:
- sprawdzić poprawność częściowej deszyfracji, 
- wnioskować o strukturze danych, 
- zawężać przestrzeń brute force

### Wpływ

-	redukcja przestrzeni brute-force (szybsze łamanie hasła), 
-	możliwość częściowego odzyskiwania informacji o strukturze vaulta, 
-	potencjalne obejście jednolitego modelu błędów, 
-	naruszenie założeń poufności w sposób pośredni

### Prawdopodobieństwo

średnie - do wykonania poprzez automatyczne skrypty, skuteczność zależy od implementacji obsługi błędów

### Zabezpieczenia

-	jednolity komunikat błędu (brak rozróżnienia typów błędów na poziomie CLI), 
-	stałoczasowe lub zbliżone do stałoczasowych ścieżki krytyczne,
-	unikanie early-exit w weryfikacji
-	brak ujawniania szczegółów walidacji

---

## RAM extraction attack *(out of scope)*

### Atak

Atakujący wykonuje dump pamięci procesu, odzyskuje klucze i odczytuje dane

### Wpływ

pełna kompromitacja wszystkich sekretów

### Prawdopodobieństwo

niskie/średnie - wymaga malware

### Zabezpieczenia

zeroization, secure memory

---

# 7. Mitigacje (Zabezpieczenia)

System stosuje wielowarstwowy model ochrony obejmujący:

## 7.1 Kryptografia

-	Argon2id jako KDF - zwiększa koszt obliczeniowy brute-force offline, chroni przed atakami słownikowymi i zgadywaniem hasła
-	Salt per vault – chroni przed atakami z użyciem rainbow tables, zapewnia unikalność wyprowadzania kluczy dla sejfów
-	Losowy DEK – separacja bezpieczeństwa między hasłem i danymi
-	Key wrapping – po kompromitacji hasła system i tak wymaga prawidłowego unwrap
-	CSPRNG (systemowy generator liczb losowych) - używany do generowania DEK


## 7.2 Integralność danych

-	AEAD – zapewnia poufność i integralność body, wykrywa każdą modyfikację
-	AAD – obejmuje nagłówek vaulta, co wiąże parametry kryptograficzne z szyfrogramem body
-	HMAC nagłówka - chroni metadane, wykrywa manipulacje nagłówkiem
-	Canonical header format – wymusza jednoznaczną strukturę nagłówka, eliminuje możliwość manipulacji formatem danych
-	Walidacja struktury pliku – wykrywa zmodyfikowane i niepoprawne .vault


## 7.3 Walidacja wejścia

-	Strict parsing + bound checking – brak odczytu poza granicami danych
-	Walidacja długości i typów pól, walidacja spójności struktury
-	Fuzz testing parserów
-	JSON import/export validation – odrzucanie niezgodnych danych
-	Fail-safe error handling – brak crashy aplikacji


## 7.4 Ochrona CLI

-	Walidacja argumentów CLI
-	Path normalization – eliminacja ../ i path traversal
-	Ograniczenie operacji tylko do dozwolonego katalogu (whitelist dostępu)

## 7.5 Ochrona przed DoS

-	Schema validation JSON, bezpieczny parser JSON
-	Sanity checks rekordów
-	Limit rozmiaru danych wejściowych
-	Odrzucenie niepoprawnych danych przed alokacją pamięci

## 7.6 Replay protection

-	Wersjonowanie vaulta
-	Re-wrapping DEK nowym master_key po zmianie hasła
-	HMAC nagłówka - odrzucanie plików o niezgodnej wersji formatu vaulta


## 7.7 Truncation protection

-	Atomic write
-	Fsync (wymuszenie zapisu na dysk przed finalizacją)
-	AEAD tag verification
-	HMAC nagłówka
-	Odrzucanie pliku przy wykryciu niespójności


## 7.8 Obsługa błędów

-	Ujednolicony model błędów, minimalizacja różnic w odpowiedziach systemu
-	Jednolity komunikat błędu
-	Minimalizacja różnic czasowych operacji
-	Brak ujawniania szczegółów walidacji
-	Brak early-exit w ścieżkach krytycznych


## 7.9 Zarządzanie kluczami

-	Zeroizacja kluczy – usuwanie sekretów po użyciu
-	Ograniczenie czasu ekspozycji kluczy - klucze istnieją tylko w pamięci operacyjnej w trakcie wykonywania operacji kryptograficznych
-	Brak trwałego przechowywania kluczy w pamięci w postaci jawnej
-	Separacja ról poszczególnych kluczy


---

# 8. Argumenty dla celów bezpieczeństwa

## S-1 — Poufność

Cel S-1 zakłada, że bez znajomości hasła głównego atakujący nie odzyska zawartości rekordów zapisanych w pliku vault. Poufność danych zapewnia szyfrowanie body sejfu przy użyciu losowo generowanego klucza DEK. DEK nie jest przechowywany jawnie w pliku, tylko w postaci opakowanej przy użyciu klucza wyprowadzonego pośrednio z hasła głównego użytkownika.

Hasło główne jest przetwarzane przez Argon2id, co zwiększa koszt ataku offline brute-force. Z uzyskanego materiału kluczowego wyprowadzane są osobne klucze do różnych celów, między innymi `wrap_key` oraz `header_mac_key`. Dzięki temu znajomość samego pliku vault nie wystarcza do odszyfrowania rekordów. Atakujący, który posiada tylko plik `.vault`, musi najpierw odgadnąć poprawne hasło główne, następnie poprawnie wyprowadzić klucze i dopiero wtedy odszyfrować DEK oraz body.

Poufność jest ograniczona przez założenia modelu zagrożeń. System nie chroni przed malware, keyloggerem, phishingiem hasła głównego ani atakiem z dostępem do pamięci RAM podczas aktywnej sesji. Jeśli atakujący pozna hasło główne lub uzyska dostęp do odszyfrowanych danych w pamięci procesu, cel S-1 nie może być zagwarantowany.

## S-2 — Integralność

Cel S-2 zakłada, że każda modyfikacja pliku vault, zarówno nagłówka, jak i body, zostanie wykryta przez `open` albo `verify --with-password`. Integralność body zapewnia mechanizm AEAD, który jednocześnie szyfruje dane i dołącza tag uwierzytelniający. Każda zmiana szyfrogramu body, nonce albo tagu powoduje błąd deszyfrowania.

Integralność nagłówka chroniona jest przez HMAC wyliczany dla kanonicznej postaci nagłówka. Dzięki temu zmiana parametrów KDF, identyfikatora algorytmu AEAD, soli, nonce lub opakowanego DEK jest wykrywana podczas otwierania albo pełnej weryfikacji sejfu. Dodatkowo nagłówek jest powiązany z szyfrogramem przez AAD, co utrudnia mieszanie elementów pochodzących z różnych wersji pliku.

`verify` bez hasła może wykrywać tylko błędy strukturalne, takie jak zły magic, zbyt krótki plik albo niepoprawne długości pól. Pełna weryfikacja integralności kryptograficznej wymaga hasła, dlatego wykonuje ją `open` albo `verify --with-password`.

## S-3 — Downgrade resistance

Cel S-3 zakłada, że atakujący nie może niezauważalnie osłabić parametrów KDF ani zmienić algorytmu AEAD. Parametry takie jak pamięć Argon2id, liczba iteracji, poziom równoległości oraz identyfikator AEAD są zapisane w nagłówku vaulta. Nagłówek jest chroniony przez HMAC oraz używany jako AAD dla szyfrowania body.

Jeżeli atakujący zmieni parametry KDF, na przykład zmniejszy liczbę iteracji Argon2id, weryfikacja HMAC nagłówka nie powiedzie się. Podobnie zmiana identyfikatora AEAD, na przykład próba podstawienia innego algorytmu, zostanie wykryta jako manipulacja metadanymi. Program powinien wtedy odrzucić plik kontrolowanym błędem, bez otwierania sejfu i bez przechodzenia do sesji `vault>`.

Odporność na downgrade nie oznacza, że pierwotnie słabe parametry KDF stają się automatycznie silne. Oznacza jedynie, że atakujący nie może samodzielnie i po cichu obniżyć parametrów zapisanych w poprawnym pliku vault. Wzmocnienie parametrów powinno być wykonywane jawnie przez użytkownika za pomocą `upgrade-kdf`.

## S-4 — Brute-force resistance

Cel S-4 zakłada, że Argon2id z parametrami określonymi w specyfikacji czyni próby offline brute-force kosztownymi. Atakujący posiadający plik `.vault` może wykonywać próby zgadywania hasła lokalnie, bez kontaktu z aplikacją lub serwerem, dlatego system nie może narzucić limitu prób. Zabezpieczeniem jest koszt obliczeniowy i pamięciowy KDF.

Każda próba hasła wymaga wykonania Argon2id z parametrami zapisanymi w nagłówku oraz próby weryfikacji/odszyfrowania danych. Zastosowanie unikalnej soli dla każdego sejfu uniemożliwia efektywne wykorzystanie gotowych tablic i powoduje, że ten sam użytkownik z tym samym hasłem w różnych sejfach otrzymuje inny materiał kluczowy.

Odporność na brute-force zależy od siły hasła użytkownika. System zwiększa koszt zgadywania, ale nie eliminuje ryzyka, jeżeli użytkownik wybierze bardzo krótkie, popularne albo słownikowe hasło. Z tego powodu słabe hasła pozostają ryzykiem resztkowym i powinny być opisane w dokumentacji oraz testowane pomiarowo w scenariuszu A5.

## S-5 — Odporność bieżącego pliku na stare hasło

Cel S-5 zakłada, że po wykonaniu `changepass` stare hasło nie wystarcza do otwarcia bieżącej wersji pliku vault. Podczas zmiany hasła system wyprowadza nowy materiał kluczowy z nowego hasła, aktualizuje dane zależne od hasła oraz ponownie opakowuje DEK tak, aby aktualna wersja pliku mogła zostać otwarta tylko nowym hasłem.

Po `changepass` próba otwarcia aktualnego pliku starym hasłem powinna zakończyć się błędem. Stare hasło nie powinno poprawnie zweryfikować chronionych danych ani umożliwić odtworzenia DEK z aktualnego nagłówka. Ten warunek jest sprawdzany w testach E2E oraz w scenariuszu adwersarialnym A6.

Ograniczenie S-5 jest istotne: zmiana hasła nie chroni starych kopii vaulta, które atakujący posiadał przed wykonaniem `changepass`. Jeżeli atakujący ma starą kopię pliku oraz zna stare hasło, może nadal otworzyć tę starą kopię i odczytać dane znajdujące się w niej w momencie wykonania kopii. `changepass` chroni wyłącznie aktualną wersję pliku po zmianie hasła, a nie usuwa ani nie unieważnia wcześniejszych backupów znajdujących się poza kontrolą aplikacji.

---

# 9. Ryzyka resztkowe

## Ryzyka kryptograficzne

-	Brute-force nadal jest możliwy (tylko droższy) - Argon2id nie eliminuje ataku
-	Bezpieczeństwo zależne od implementacji kryptografii (błędy/podatności w bibliotekach kryptograficznych) - potencjalne obejście zabezpieczeń


## Ryzyka środowiskowe

Kompromitacja środowiska (malware, RAM access) - złośliwe oprogramowanie może doprowadzić do pełnej kompromitacji sejfu mimo użytych zabezpieczeń

## Ryzyka implementacyjne

Różnice przy obsłudze błędów - nadal będą istnieć (czas, zużycie zasobów), ale mniej zauważalne

## Ryzyka użytkownika

- Dobór słabego hasła przez użytkownika - system nie wymusza polityki haseł; krótkie lub popularne hasło może spowodować szybsze jego złamanie offline
-	Błędy użytkownika (utrata hasła, eksport danych do niezabezpieczonych miejsc) - system nie kontroluje użytkownika, ryzyko całkowitej utraty dostępu do danych przy zapomnieniu hasła


## Ryzyka operacyjne

- Stare kopie sejfu - mogą dalej istnieć u atakującego, który będzie próbował je odzyskać (program nie zarządza backupami)

---

# 10. Security Testing Strategy

## 10.1 Testy kryptograficzne

Wykorzystywane RFC:

- RFC 9106 — Argon2id,
- RFC 5869 — HKDF-SHA256,
- RFC 4231 — HMAC-SHA256,
- RFC 8439 — ChaCha20-Poly1305.

Zakres testów obejmuje:
-	poprawność wyprowadzania kluczy, 
-	poprawność szyfrowania i deszyfrowania, 
-	poprawność tagów integralności, 
-	obsługę błędnych danych wejściowych, 
-	zachowanie przy skrajnych parametrach KDF


---

## 10.2 Testy integracyjne (E2E)

1)	Przetestowanie podstawowego workflow: init -> add -> list -> get; zwrócona wartość musi być identyczna z zapisanym sekretem

2)	Zmiana hasła -> otwarcie sejfu z nowym hasłem; wszystkie rekordy dalej istnieją, stare hasło nie działa, nowy wrapped DEK różni się od starego

3)	Dodanie załączników -> extract; wyciągnięte bajty są identyczne z oryginałem

4)	Aktualizacja parametrów KDF; po upgrade-kdf i ponownym otwarciu sejfu dane pozostają poprawne, parametry Argon2id zostają zaktualizowane a integralność danych zachowana


---

## 10.3 Golden vectors

System zawiera deterministyczny zestaw testów kompatybilności. Wektor zawiera:

-	stałe hasło,
-	ustalony salt (16 zer), 
-	ustalone parametry Argon2id, 
-	deterministyczne nonce, 
-	ustalone rekordy testowe, 
-	oczekiwane bajty końcowego pliku .vault w Base64. 

Celem testów jest:

-	wykrywanie regresji formatu, 
-	zapewnienie kompatybilności między implementacjami, 
-	wykrywanie niezamierzonych zmian serializacji, 
-	zapewnienie bit-perfect reproducibility. 

Każda zmiana w Crypto Core lub formacie vaulta musi nadal generować identyczny wynik dla golden vectors.


---

## 10.4 Fuzz testing

1) Parser nagłówka; weryfikowane są:
-	brak panic, 
-	brak out-of-bounds access, 
-	brak integer overflow, 
-	poprawna obsługa losowych danych

3) Parser body po deszyfrowaniu; weryfikowane są:
-	brak panic, 
-	brak OOM, 
-	brak unbounded recursion, 
-	poprawna walidacja długości pól, 
-	odporność na malformed structures


---

## 10.5 Testy integralności i odporności na manipulację

Przy manipulacji plikiem .vault weryfikowane są:

-	modyfikacja ciphertextu, 
-	zmiana nonce, 
-	podmiana wrapped DEK, 
-	zmiana parametrów KDF, 
-	zmiana identyfikatora AEAD, 
-	truncation attack, 
-	replay starego nagłówka, 
-	uszkodzenie HMAC nagłówka

W wyniku manpiulacji:
-	vault zostaje odrzucony, 
- aplikacja nie crashuje, 
-	użytkownik otrzymuje jednolity komunikat błędu


---

## 10.6 Side-channel tests

Podczas testów wykonuje się:
-	pomiar czasu odpowiedzi dla poprawnego i błędnego hasła, 
-	weryfikację braku znaczących różnic czasowych, 
-	sprawdzenie jednolitych komunikatów błędów, 
-	testy constant-time comparison dla MAC/tag verification


---

## 10.7 Testy operacji plikowych

Testowane są scenariusze awarii podczas zapisu:
-	przerwanie procesu podczas save, 
-	crash przed rename, 
-	częściowy zapis pliku, 
-	brak fsync, 
-	równoczesny dostęp do pliku

W przypadku poprawnego działania wynikiem jest:
-	brak utraty poprzedniej poprawnej wersji vaulta, 
-	brak zapisania częściowo poprawnego pliku,
-	poprawne działanie atomic write


---

## 10.8 DoS tests

Testy obejmują:
-	import bardzo dużych JSON,
-	rekordy o niepoprawnych długościach, 
-	załączniki > 5 MiB, 
-	bardzo dużą liczbę rekordów, 
-	ekstremalne parametry wejściowe parsera

W przypadku poprawnego działania wynikiem jest:
-	brak OOM, 
-	kontrolowane odrzucenie danych, 
-	brak degradacji działania systemu, 
-	brak crashy


---

## 10.9 Regression tests

Każdy wykryty bug skutkuje:

- dodaniem regression testu,
- odtworzeniem scenariusza,
- zabezpieczeniem przed ponownym wystąpieniem.

---

# 11. Podsumowanie

Przedstawiony model zagrożeń opisuje główne ryzyka związane z lokalnym menedżerem sekretów działającym w modelu offline. System został zaprojektowany z wykorzystaniem wielowarstwowych mechanizmów ochrony obejmujących kryptografię, integralność danych, walidację wejścia oraz bezpieczne operacje plikowe.

Zastosowanie Argon2id, AEAD, key wrapping oraz ochrony integralności nagłówka pozwala ograniczyć ryzyko brute-force, manipulacji vaultem oraz downgrade attack. Dodatkowo zastosowano mechanizmy ochrony parserów, fuzz testing oraz jednolitą obsługę błędów minimalizującą możliwość wystąpienia oracle i side-channel leakage.

Model uwzględnia również ograniczenia systemu i jasno definiuje zagrożenia pozostające poza zakresem ochrony, takie jak malware, kompromitacja pamięci RAM czy phishing hasła głównego.

Pomimo istniejących ryzyk resztkowych system zapewnia wysoki poziom ochrony poufności i integralności danych przy założeniach określonych w modelu zagrożeń

