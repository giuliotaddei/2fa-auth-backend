# 🔐 2FA Auth Backend

Sistema di autenticazione a due fattori (2FA) riutilizzabile, costruito con **Spring Boot 4** e **Java 21**. Espone API REST stateless pensate per essere integrate in qualsiasi applicazione frontend (Angular, React, mobile, ecc.) che necessiti di un livello di sicurezza con autenticazione TOTP, JWT e cifratura dei dati sensibili.

> Progetto realizzato come parte del mio portfolio personale, con l'obiettivo di applicare pattern di sicurezza realmente usati in produzione.

---

## Indice

- [Caratteristiche principali](#-caratteristiche-principali)
- [Stack tecnologico](#-stack-tecnologico)
- [Architettura](#-architettura)
- [Flusso di autenticazione](#-flusso-di-autenticazione)
- [Setup del progetto](#-setup-del-progetto)
- [Configurazione variabili d'ambiente](#-configurazione-variabili-dambiente)
- [Documentazione API](#-documentazione-api)
- [Sicurezza implementata](#-sicurezza-implementata)
- [Struttura del progetto](#-struttura-del-progetto)

---

## Caratteristiche principali

- **Autenticazione a due fattori (2FA)** tramite TOTP, compatibile con Google Authenticator, Authy e app simili
- **JWT** con flusso a doppio token: *temporary token* (dopo step 1 del login) e *access token* (dopo verifica OTP)
- **Refresh token rotation** — ogni utilizzo invalida il token precedente e ne emette uno nuovo
- **Cifratura AES-256-GCM** del secret TOTP salvato a database
- **Password hashate con bcrypt**, mai salvate in chiaro
- **Rate limiting** per IP sugli endpoint sensibili (login, registrazione, verifica OTP)
- **Account lockout automatico** dopo tentativi di login falliti ripetuti
- **Gestione centralizzata degli errori** con risposte JSON consistenti
- **100% gratuito** — nessun servizio a pagamento (niente SMS, niente email transazionali)

---

## Stack tecnologico

| Categoria | Tecnologia |
|---|---|
| Linguaggio | Java 21 |
| Framework | Spring Boot 4.1.0 |
| Sicurezza | Spring Security 6 |
| Database | MySQL 8 |
| ORM | Spring Data JPA / Hibernate |
| Autenticazione | JWT |
| TOTP | `com.eatthepath:java-otp` |
| QR Code | `com.google.zxing` |
| Rate Limiting | `bucket4j` |
| Build tool | Maven |

---

## Architettura

```
┌─────────────┐       HTTPS        ┌──────────────────┐       JDBC       ┌──────────┐
│   Frontend  │ ──────────────────▶│  Spring Boot API  │ ────────────────▶│  MySQL   │
│ (Angular/JS)│ ◀──────────────────│   (porta 8080)     │ ◀────────────────│          │
└─────────────┘    JSON + JWT       └──────────────────┘                  └──────────┘
```

Il backend è completamente **stateless**: nessuna sessione lato server, tutta l'autenticazione viaggia tramite JWT nell'header `Authorization`. Questo lo rende facilmente scalabile orizzontalmente e integrabile con qualsiasi frontend.

---

## Flusso di autenticazione

### Registrazione

```
1. POST /api/auth/register
   → il backend crea l'utente, genera un secret TOTP (cifrato AES-256 nel DB)
   → risponde con QR code (base64) + chiave manuale

2. L'utente scansiona il QR con Google Authenticator / Authy

3. POST /api/auth/register/confirm-totp
   → l'utente invia il primo codice OTP generato dall'app
   → il backend verifica e abilita definitivamente il 2FA sull'account
```

### Login

```
1. POST /api/auth/login
   → verifica email + password
   → se corrette, restituisce un tempToken (validità: 5 minuti)
   → il tempToken NON è sufficiente per accedere alle risorse protette

2. POST /api/auth/verify-totp
   → l'utente invia tempToken + codice OTP corrente
   → se valido, il backend emette accessToken (15 min) + refreshToken (7 giorni)
```

### Sessione e logout

```
POST /api/auth/refresh   → rinnova l'accessToken usando il refreshToken
                            (il refreshToken usato viene invalidato e ne viene emesso uno nuovo)

POST /api/auth/logout     → invalida tutti i refresh token dell'utente
                            (richiede accessToken valido nell'header Authorization)
```

### Perché due token separati al login?

Separare *tempToken* e *accessToken* impedisce che un client possa accedere alle risorse protette avendo verificato solo email+password, senza completare il secondo fattore. Il `tempToken` ha un claim `type: temp` che lo rende valido **solo** per l'endpoint `/verify-totp`.

---

## Setup del progetto

### Prerequisiti

- Java 21+
- Maven 3.9+
- MySQL 8+ (anche via Docker)

### 1. Clona il repository

```bash
git clone https://github.com/<tuo-username>/2fa-auth-backend.git
cd 2fa-auth-backend
```

### 2. Crea il database

Esegui lo script SQL incluso in `DDL/schema.sql`:

```bash
mysql -u root -p < DDL/schema.sql
```

Se MySQL è in Docker:

```bash
docker exec -i <nome-container> mysql -u root -p<password> < DDL/schema.sql
```

### 3. Configura le variabili d'ambiente

Vedi la sezione dedicata [qui sotto](#-configurazione-variabili-dambiente).

### 4. Avvia l'applicazione

```bash
mvn spring-boot:run
```

L'API sarà disponibile su `http://localhost:8080`.

---

## Configurazione variabili d'ambiente

Il progetto **non contiene segreti hardcoded**. Tutti i valori sensibili sono letti da variabili d'ambiente, da impostare nel tuo ambiente locale (IntelliJ: `Run → Edit Configurations → Environment Variables`) o nel servizio di hosting in caso di deploy.

| Variabile | Descrizione | Come generarla |
|---|---|---|
| `DB_USERNAME` | Username MySQL | — |
| `DB_PASSWORD` | Password MySQL | — |
| `JWT_SECRET` | Chiave per firmare i JWT (min. 64 byte) | `openssl rand -base64 64 \| tr -d '\n'` |
| `ENCRYPTION_KEY` | Chiave AES-256 per cifrare il secret TOTP (32 byte esatti) | `openssl rand -base64 32 \| tr -d '\n'` |
| `CORS_ALLOWED_ORIGINS` | Origini frontend autorizzate (opzionale, default `http://localhost:4200`) | — |

> **Importante**: quando generi le chiavi da terminale, usa sempre `tr -d '\n'` per evitare che vadano a capo su più righe — un newline o uno spazio accidentale nel valore copiato causa errori difficili da diagnosticare (`Illegal base64 character`).

> Non inserire mai questi valori tra virgolette nell'editor delle variabili d'ambiente di IntelliJ — verrebbero incluse letteralmente nel valore.

---

## 📡 Documentazione API

Tutti gli endpoint rispondono in JSON. Base path: `/api/auth`

| Metodo | Endpoint | Auth richiesta | Descrizione |
|---|---|---|---|
| `POST` | `/register` | No | Registra un nuovo utente, restituisce QR code TOTP |
| `POST` | `/register/confirm-totp` | No | Conferma la configurazione TOTP con il primo codice |
| `POST` | `/login` | No | Step 1: verifica email+password, restituisce tempToken |
| `POST` | `/verify-totp` | No | Step 2: verifica codice OTP, restituisce accessToken+refreshToken |
| `POST` | `/refresh` | No (richiede refreshToken nel body) | Rinnova l'accessToken |
| `POST` | `/logout` | Sì (Bearer accessToken) | Invalida tutti i refresh token dell'utente |

### Esempio: Registrazione

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123!"}'
```

**Risposta:**
```json
{
  "qrCodeUri": "iVBORw0KGgoAAAANSUhEUgAA...",
  "manualKey": "JX5RO6LRZNLVA2E5BEMP3L7QFIGYX2JZ"
}
```

### Esempio: Login completo

```bash
# Step 1
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123!"}'

# Step 2 (usando il tempToken ricevuto + codice dall'app authenticator)
curl -X POST http://localhost:8080/api/auth/verify-totp \
  -H "Content-Type: application/json" \
  -d '{"tempToken":"<temp_token>","totpCode":"123456"}'
```

**Risposta finale:**
```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
  "refreshToken": "4DtMzYUkjZQEW89iCysvln3I...",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

### Esempio: Endpoint protetto

```bash
curl -X POST http://localhost:8080/api/auth/logout \
  -H "Authorization: Bearer <access_token>"
```

---

## Sicurezza implementata

- **HTTPS in produzione**: tutte le comunicazioni vanno protette con TLS (in sviluppo locale si usa HTTP, ma il design assume sempre un livello TLS davanti)
- **Password**: hashate con `bcrypt`, mai salvate o loggate in chiaro
- **TOTP secret**: cifrato con AES-256-GCM prima del salvataggio su database; decifrato solo in memoria al momento della verifica
- **JWT**: firmati con HMAC-SHA, due tipologie distinte (`temp` e `access`) per impedire bypass del secondo fattore
- **Refresh token rotation**: ogni refresh invalida il token precedente, limitando l'impatto di un eventuale furto
- **Refresh token salvati come hash SHA-256**: anche con accesso al database, i token non sono direttamente utilizzabili
- **Rate limiting per IP**: protezione brute-force su login, registrazione e verifica OTP
- **Account lockout**: blocco temporaneo dopo tentativi di login falliti ripetuti
- **CORS configurato esplicitamente**: solo le origini autorizzate possono chiamare le API

---

## Struttura del progetto

```
src/main/java/com/giuliotaddei/
├── Application.java
├── config/
│   ├── RateLimitConfig.java        # Configurazione bucket4j
│   └── RateLimitFilter.java        # Filtro che applica il rate limit
├── controller/
│   └── AuthController.java         # Endpoint REST
├── dto/
│   ├── request/                    # DTO delle richieste in ingresso
│   └── response/                   # DTO delle risposte
├── entity/
│   ├── User.java
│   └── RefreshToken.java
├── exception/
│   ├── AuthException.java
│   ├── TokenException.java
│   └── GlobalExceptionHandler.java # Gestione centralizzata degli errori
├── repository/
│   ├── UserRepository.java
│   └── RefreshTokenRepository.java
├── security/
│   ├── SecurityConfig.java         # Configurazione Spring Security + CORS
│   ├── CustomUserDetailsService.java
│   └── jwt/
│       ├── JwtService.java         # Creazione e validazione JWT
│       └── JwtAuthFilter.java      # Filtro di autenticazione per richiesta
└── service/
    ├── AuthService.java            # Logica di business principale
    ├── TotpService.java            # Generazione/verifica TOTP, QR code
    ├── EncryptionService.java      # Cifratura AES-256-GCM
    └── RefreshTokenService.java    # Gestione lifecycle refresh token
```

---

## Possibili sviluppi futuri

- Frontend Angular dimostrativo che consuma queste API
- Recupero password via email
- Supporto a metodi 2FA aggiuntivi (WebAuthn/FIDO2)
- Test unitari e di integrazione
- Containerizzazione con Docker Compose (app + MySQL)

---

## Licenza

Progetto personale a scopo di portfolio. Sentiti libero di usarlo come riferimento o punto di partenza per i tuoi progetti.
