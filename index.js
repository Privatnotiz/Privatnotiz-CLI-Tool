#!/usr/bin/env node

const { program } = require('commander');
const crypto = require('crypto');
const axios = require('axios');
const chalk = require('chalk');
const ora = require('ora');
const readline = require('readline');

// Konstanten
const API_BASE_URL = 'https://api.privatnotiz.de';
const VERSION = require('./package.json').version;

// Hilfsfunktionen
function validateApiResponse(response) {
  if (response.status === 503 && response.data.code === 'API_DISABLED') {
    console.error(chalk.red('Fehler: Die öffentliche API ist derzeit deaktiviert.'));
    console.log(chalk.yellow('Bitte kontaktieren Sie den Administrator von Privatnotiz.'));
    process.exit(1);
  }
}

// Funktion zum sicheren Abfragen eines Passworts
async function promptPassword(message) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  
  return new Promise((resolve) => {
    rl.question(message, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

// Debug-Funktion zum Anzeigen von Anfrage-Details
function debugRequest(method, url, data = null) {
  console.log(chalk.dim(`\nDEBUG - Sende Anfrage:
  Methode: ${method}
  URL: ${url}
  ${data ? `Daten: ${JSON.stringify(data, null, 2)}` : ''}`));
}

// CLI-Konfiguration
program
  .name('privatnotiz')
  .description('CLI-Tool für die sichere Übermittlung von Nachrichten über Privatnotiz')
  .version(VERSION);

program
  .command('send')
  .description('Nachricht verschlüsseln und senden')
  .requiredOption('-m, --message <text>', 'Nachricht, die verschlüsselt werden soll')
  .option('-e, --expires <hours>', 'Ablaufzeit in Stunden (1-168)', '24')
  .option('-p, --password', 'Mit Passwort schützen')
  .option('--debug', 'Debug-Modus aktivieren')
  .action(async ({ message, expires, password, debug }) => {
    const spinner = ora('Bereite Verschlüsselung vor...').start();
    
    try {
      // Passwortschutz einrichten, falls angefordert
      let passwordHash = null;
      if (password) {
        spinner.stop();
        const userPassword = await promptPassword('Bitte geben Sie ein Passwort ein: ');
        if (!userPassword) {
          console.error(chalk.red('Fehler: Kein Passwort angegeben.'));
          process.exit(1);
        }
        passwordHash = crypto.createHash('sha256').update(userPassword).digest('hex');
        spinner.start('Passwort gesichert...');
      }
      
      // Generiere Schlüssel und IV
      const key = crypto.randomBytes(32); // 256-bit AES-Key
      const iv = crypto.randomBytes(16);  // 128-bit IV für AES-CBC
      
      spinner.text = 'Verschlüssele Nachricht...';
      
      // Verschlüssele die Nachricht
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      let encrypted = cipher.update(message, 'utf8', 'base64');
      encrypted += cipher.final('base64');
      
      // Validiere die Ablaufzeit
      const expiryHours = parseInt(expires);
      if (isNaN(expiryHours) || expiryHours < 1 || expiryHours > 168) {
        spinner.stop();
        console.error(chalk.red('Fehler: Ungültige Ablaufzeit. Muss zwischen 1 und 168 Stunden liegen.'));
        process.exit(1);
      }
      
      spinner.text = 'Sende verschlüsselte Nachricht...';
      
      // Bereite Anfrage vor
      const requestData = {
        data: encrypted,
        iv: iv.toString('base64'),
        expiresIn: expiryHours
      };
      
      // Füge Passwort hinzu, wenn vorhanden
      if (passwordHash) {
        requestData.password = passwordHash;
      }
      
      // Korrekter API-Endpunkt für create
      const url = `${API_BASE_URL}/create`;
      
      if (debug) {
        spinner.stop();
        debugRequest('POST', url, requestData);
        spinner.start('Sende Anfrage...');
      }
      
      // Sende an den korrekten API-Endpunkt
      const response = await axios.post(url, requestData, {
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': `privatnotiz-cli/${VERSION}`,
          'X-CLI-Request': 'true'
        },
        timeout: 15000  // 15 Sekunden Timeout für langsame Verbindungen
      });
      
      validateApiResponse(response);
      
      spinner.stop();
      
      // Zeige dem Nutzer die Ergebnisse
      console.log(chalk.green('\n✓ Nachricht erfolgreich gespeichert!'));
      console.log(chalk.yellow('\nSichere URL:'));
      
      // Generiere die URL mit dem Fragment für den Entschlüsselungsschlüssel
      const baseUrl = response.data.url;
      const keyBase64 = key.toString('base64');
      const secureUrl = `${baseUrl}#key=${encodeURIComponent(keyBase64)}`;
      
      console.log(chalk.cyan(secureUrl));
      
      console.log(chalk.yellow('\nDiese URL enthält sowohl den Zugangslink als auch den Entschlüsselungsschlüssel.'));
      console.log(chalk.yellow('Der Teil nach # wird niemals an den Server übertragen und ist nur im Browser verfügbar.'));
      
      console.log(chalk.yellow(`\nDie Nachricht läuft in ${expiryHours} Stunden ab.`));
      
      if (passwordHash) {
        console.log(chalk.yellow('\nDie Nachricht ist zusätzlich mit einem Passwort geschützt.'));
      }
      
      console.log(chalk.red('\nWichtig: Die Nachricht kann nur einmal abgerufen werden und wird danach gelöscht.'));
      
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Fehler beim Senden der Nachricht:'));
      
      if (error.response) {
        // Die Anfrage wurde gestellt und der Server antwortete mit einem Statuscode
        // der außerhalb des Bereichs von 2xx liegt
        console.error(chalk.red(`  Status: ${error.response.status}`));
        console.error(chalk.red(`  Fehler: ${error.response.data.error || 'Unbekannter Fehler'}`));
        
        validateApiResponse(error.response);
      } else if (error.request) {
        // Die Anfrage wurde gestellt, aber es wurde keine Antwort erhalten
        console.error(chalk.red('  Keine Antwort vom Server erhalten. Ist die API erreichbar?'));
        
        if (debug) {
          console.error(chalk.dim('\nDebug-Informationen:'));
          console.error(chalk.dim(`  Anfrage-URL: ${error.request._currentUrl}`));
          console.error(chalk.dim(`  Anfrage-Methode: ${error.request.method}`));
          console.error(chalk.dim(`  Anfrage-Timeout: ${error.config?.timeout || 'Standard'} ms`));
          console.error(chalk.dim(`  Netzwerkfehler: ${error.code || 'Unbekannt'}`));
        } else {
          console.error(chalk.yellow('\nTipp: Verwenden Sie die "--debug" Option für mehr Informationen.'));
        }
      } else {
        // Etwas ist bei der Einrichtung der Anfrage schief gelaufen
        console.error(chalk.red(`  ${error.message}`));
      }
      
      process.exit(1);
    }
  });

program
  .command('read')
  .description('Geheime Nachricht abrufen und entschlüsseln')
  .requiredOption('-u, --url <url>', 'Komplette URL mit Entschlüsselungsschlüssel')
  .option('-p, --password <password>', 'Passwort für passwortgeschützte Nachrichten')
  .option('--debug', 'Debug-Modus aktivieren')
  .action(async ({ url, password, debug }) => {
    const spinner = ora('Überprüfe URL...').start();
    
    try {
      // Parse URL und extrahiere noteId und key
      const parsedUrl = new URL(url);
      const noteId = parsedUrl.pathname.split('/').pop();
      
      // Schlüssel aus dem Fragment extrahieren
      const fragment = parsedUrl.hash;
      const keyMatch = fragment.match(/key=([^&]+)/);
      
      if (!noteId || !keyMatch) {
        spinner.stop();
        console.error(chalk.red('Fehler: Ungültige URL. Stellen Sie sicher, dass die URL korrekt ist.'));
        process.exit(1);
      }
      
      const keyBase64 = decodeURIComponent(keyMatch[1]);
      const key = Buffer.from(keyBase64, 'base64');
      
      // API-Parameter vorbereiten
      const apiParams = {};
      if (password) {
        // Wenn ein Passwort angegeben wurde, hash es für den API-Aufruf
        apiParams.password = crypto.createHash('sha256').update(password).digest('hex');
      }
      
      spinner.text = 'Rufe geheime Nachricht ab...';
      
      // KORRIGIERT: Fehlende schließende Klammer hinzugefügt
      const apiUrl = `${API_BASE_URL}/read/${noteId}`; 
      
      if (debug) {
        spinner.stop();
        debugRequest('GET', apiUrl, apiParams);
        spinner.start('Sende Anfrage...');
      }
      
      // Rufe die Nachricht vom korrekten API-Endpunkt ab
      const response = await axios.get(apiUrl, {
        params: apiParams,
        headers: {
          'User-Agent': `privatnotiz-cli/${VERSION}`,
          'X-CLI-Request': 'true'
        },
        timeout: 15000  // 15 Sekunden Timeout
      });
      
      validateApiResponse(response);
      
      const { data: encryptedData, iv: ivBase64, password_protected } = response.data;
      
      // Wenn die Nachricht passwortgeschützt ist und kein Passwort angegeben wurde
      if (password_protected && !password) {
        spinner.stop();
        console.error(chalk.red('Fehler: Diese Nachricht ist passwortgeschützt.'));
        console.error(chalk.yellow('Bitte geben Sie das Passwort mit der Option -p an.'));
        process.exit(1);
      }
      
      spinner.text = 'Entschlüssele Nachricht...';
      
      // Entschlüssele die Nachricht
      const iv = Buffer.from(ivBase64, 'base64');
      const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
      decrypted += decipher.final('utf8');
      
      spinner.stop();
      
      console.log(chalk.green('\n✓ Nachricht erfolgreich entschlüsselt!'));
      console.log(chalk.yellow('\nInhalt:'));
      console.log(chalk.white('-'.repeat(50)));
      console.log(decrypted);
      console.log(chalk.white('-'.repeat(50)));
      
      if (response.data.deleted) {
        console.log(chalk.red('\nHinweis: Diese Nachricht wurde nach dem Lesen gelöscht und ist nicht mehr abrufbar.'));
      }
      
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Fehler beim Abrufen oder Entschlüsseln der Nachricht:'));
      
      if (error.response) {
        if (error.response.status === 404) {
          console.error(chalk.red('  Die Nachricht wurde nicht gefunden. Sie wurde möglicherweise bereits gelesen oder ist abgelaufen.'));
        } else if (error.response.status === 403 && error.response.data.code === 'INVALID_PASSWORD') {
          console.error(chalk.red('  Falsches Passwort für die passwortgeschützte Nachricht.'));
        } else {
          console.error(chalk.red(`  Status: ${error.response.status}`));
          console.error(chalk.red(`  Fehler: ${error.response.data.error || 'Unbekannter Fehler'}`));
          
          validateApiResponse(error.response);
        }
      } else if (error.request) {
        console.error(chalk.red('  Keine Antwort vom Server erhalten. Ist die API erreichbar?'));
        
        if (debug) {
          console.error(chalk.dim('\nDebug-Informationen:'));
          console.error(chalk.dim(`  Anfrage-URL: ${error.request._currentUrl}`));
          console.error(chalk.dim(`  Anfrage-Methode: ${error.request.method}`));
          console.error(chalk.dim(`  Anfrage-Timeout: ${error.config?.timeout || 'Standard'} ms`));
          console.error(chalk.dim(`  Netzwerkfehler: ${error.code || 'Unbekannt'}`));
        } else {
          console.error(chalk.yellow('\nTipp: Verwenden Sie die "--debug" Option für mehr Informationen.'));
        }
      } else {
        console.error(chalk.red(`  ${error.message}`));
      }
      
      process.exit(1);
    }
  });

program
  .command('status')
  .description('API-Status überprüfen')
  .option('--debug', 'Debug-Modus aktivieren')
  .action(async ({ debug }) => {
    const spinner = ora('Überprüfe API-Status...').start();
    
    try {
      const url = `${API_BASE_URL}/status`;
      
      if (debug) {
        spinner.stop();
        debugRequest('GET', url);
        spinner.start('Sende Anfrage...');
      }
      
      const response = await axios.get(url, {
        headers: {
          'User-Agent': `privatnotiz-cli/${VERSION}`,
          'X-CLI-Request': 'true'
        },
        timeout: 15000  // 15 Sekunden Timeout
      });
      
      spinner.stop();
      
      const enabled = response.data.enabled;
      
      if (enabled) {
        console.log(chalk.green('✓ Die öffentliche API ist aktiv und erreichbar.'));
        console.log(chalk.green('  Sie können Nachrichten senden und abrufen.'));
      } else {
        console.log(chalk.yellow('⚠ Die öffentliche API ist derzeit deaktiviert.'));
        console.log(chalk.yellow('  Bitte kontaktieren Sie den Administrator, um sie zu aktivieren.'));
      }
      
    } catch (error) {
      spinner.stop();
      console.error(chalk.red('Fehler beim Überprüfen des API-Status:'));
      
      if (error.response) {
        console.error(chalk.red(`  Status: ${error.response.status}`));
        console.error(chalk.red(`  Fehler: ${error.response.data.error || 'Unbekannter Fehler'}`));
      } else if (error.request) {
        console.error(chalk.red('  Keine Antwort vom Server erhalten. Ist die API erreichbar?'));
        
        if (debug) {
          console.error(chalk.dim('\nDebug-Informationen:'));
          console.error(chalk.dim(`  Anfrage-URL: ${error.request._currentUrl}`));
          console.error(chalk.dim(`  Anfrage-Methode: ${error.request.method}`));
          console.error(chalk.dim(`  Anfrage-Timeout: ${error.config?.timeout || 'Standard'} ms`));
          console.error(chalk.dim(`  Netzwerkfehler: ${error.code || 'Unbekannt'}`));
        } else {
          console.error(chalk.yellow('\nTipp: Verwenden Sie die "--debug" Option für mehr Informationen.'));
        }
      } else {
        console.error(chalk.red(`  ${error.message}`));
      }
      
      process.exit(1);
    }
  });

// Hilfskommando für allgemeine Informationen
program
  .command('info')
  .description('Informationen zum CLI-Tool anzeigen')
  .action(() => {
    console.log(chalk.cyan(`Privatnotiz CLI v${VERSION}`));
    console.log(chalk.white('\nEin Kommandozeilentool für den sicheren Austausch von Nachrichten über Privatnotiz.\n'));
    
    console.log(chalk.yellow('Verfügbare Befehle:'));
    console.log('  send     Nachricht verschlüsseln und senden');
    console.log('  read     Nachricht abrufen und entschlüsseln');
    console.log('  status   API-Status überprüfen');
    console.log('  info     Diese Informationen anzeigen');
    
    console.log(chalk.yellow('\nSicherheitsmerkmale:'));
    console.log('  - AES-256-CBC-Verschlüsselung (Industriestandard)');
    console.log('  - Client-seitige Verschlüsselung (Schlüssel verlässt nie Ihren Computer)');
    console.log('  - Einmal-Abruf (Nachrichten werden nach dem Lesen gelöscht)');
    console.log('  - Optionaler Passwortschutz');
    console.log('  - Zeitliche Begrenzung der Verfügbarkeit');
    
    console.log(chalk.yellow('\nBeispiele:'));
    console.log('  privatnotiz send -m "Geheime Nachricht" -e 48');
    console.log('  privatnotiz send -m "Geheime Nachricht" --debug');
    console.log('  privatnotiz send -m "Passwortgeschützte Nachricht" -p');
    console.log('  privatnotiz read -u "https://privatnotiz.de/secret/abc123#key=..."');
    console.log('  privatnotiz read -u "https://privatnotiz.de/secret/abc123#key=..." -p "MeinPasswort"');
    console.log('  privatnotiz status');
    
    console.log(chalk.red('\nWichtig: Alle Nachrichten werden nach dem ersten Lesen automatisch gelöscht!'));
  });

// Wenn kein Befehl angegeben wurde, zeige Hilfe an
if (!process.argv.slice(2).length) {
  program.outputHelp();
}

program.parse(process.argv);
