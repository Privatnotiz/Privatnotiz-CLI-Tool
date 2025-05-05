# Privatnotiz CLI

Ein Kommandozeilentool für den sicheren Austausch von geheimen Nachrichten über Privatnotiz.

## Installation

```bash
npm install -g privatnotiz-cli
```

## Nutzung

### Nachricht versenden

Erstelle eine verschlüsselte Nachricht und erhalte einen Link zum Teilen:

```bash
privatnotiz send -m "Meine geheime Nachricht"
```

Optionen:
- `-m, --message <text>` - Die zu verschlüsselnde Nachricht (erforderlich)
- `-e, --expires <hours>` - Ablaufzeit in Stunden (1-168, Standard: 24)

### Nachricht lesen

Rufe eine geheime Nachricht ab und entschlüssele sie:

```bash
privatnotiz read -u "https://privatnotiz.de/secret/abc123#key=..."
```

Optionen:
- `-u, --url <url>` - Die vollständige URL mit Entschlüsselungsschlüssel (erforderlich)

### API-Status überprüfen

Überprüfe, ob die öffentliche API verfügbar ist:

```bash
privatnotiz status
```

## Sicherheitsmerkmale

- **AES-256-CBC-Verschlüsselung** - Industriestandard für sichere Verschlüsselung
- **Client-seitige Verschlüsselung** - Daten werden lokal verschlüsselt, bevor sie gesendet werden
- **Sichere URL-Fragmente** - Schlüssel werden nie an den Server übertragen
- **Einmal-Abruf** - Nachrichten werden nach dem Lesen sofort gelöscht

## Beispiel

```bash
$ privatnotiz send -m "Hier sind die Zugangsdaten: User=admin, Pwd=S3cure!"

✓ Nachricht erfolgreich gespeichert!

Sichere URL:
https://privatnotiz.de/secret/abc123#key=AbCdEfG...

Diese URL enthält sowohl den Zugangslink als auch den Entschlüsselungsschlüssel.
Der Teil nach # wird niemals an den Server übertragen und ist nur im Browser verfügbar.

Die Nachricht läuft in 24 Stunden ab.

Wichtig: Die Nachricht kann nur einmal abgerufen werden und wird danach gelöscht.
```