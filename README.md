# Hash_Attacks# Hash Security Analysis Project

Progetto per l'esame pratico di **Sicurezza dell'Informazione** che dimostra le vulnerabilità delle funzioni hash e implementa diversi tipi di attacchi crittografici.

## 🎯 Obiettivo

Questo progetto analizza la sicurezza delle funzioni hash attraverso:
- Implementazione di funzioni hash vulnerabili e sicure
- Sviluppo di algoritmi di attacco (brute force, dizionario, ibrido)
- Analisi delle prestazioni e vulnerabilità
- Dimostrazione pratica dei concetti teorici

## 🏗️ Struttura del Progetto

```
hash_security_project/
├── src/
│   ├── hash_functions.py      # Implementazioni delle funzioni hash
│   ├── attacks.py             # Algoritmi di attacco
│   ├── utils.py               # Utilities e analisi
│   └── main.py                # Demo principale
├── data/
│   └── wordlists/             # Dizionari per attacchi
├── results/                   # Risultati e grafici
├── requirements.txt           # Dipendenze Python
└── README.md                  # Questa documentazione
```

## 🚀 Installazione e Setup

### Prerequisiti
- Python 3.7+
- pip

### Installazione
```bash
# Clona il repository
git clone <your-repo-url>
cd hash_security_project

# Installa le dipendenze (consiglio di creare ed usare un virtaul enviroment con versione python diversa da 3.13.0 in quanto presenta un bug con una libreria di matplotlib)
pip install -r requirements.txt

# Esegui la demo
cd src
python main.py
```

## 📊 Funzionalità Implementate

### Funzioni Hash

#### Hash Vulnerabili (per dimostrazione)
- **WeakSumHash**: Somma semplice dei caratteri modulo un valore
- **SimpleXORHash**: XOR di tutti i byte
- **WeakMultiplyHash**: Moltiplicazione con overflow controllato

#### Hash Standard (per confronto)
- **MD5**: Algoritmo deprecato, vulnerabile
- **SHA-256**: Algoritmo sicuro, resistente alle collisioni

### Tipi di Attacco

#### 1. Attacco Brute Force
- Prova tutte le combinazioni possibili
- Configurabile per charset e lunghezza
- Misurazione delle prestazioni

#### 2. Attacco Dizionario  
- Utilizza wordlist di password comuni
- Più efficiente per password deboli
- Statistiche dettagliate sui tentativi

#### 3. Attacco Ibrido
- Combina dizionario con variazioni comuni
- Sostituzioni di caratteri (a→@, e→3, etc.)
- Aggiunta di numeri e simboli

#### 4. Ricerca Collisioni
- Algoritmo per trovare hash identici
- Dimostra vulnerabilità degli hash deboli
- Statistiche su tentativi e successi

### Analisi e Reporting

#### Analisi delle Prestazioni
- Velocità di hashing (hash/secondo)
- Tempo medio per attacco
- Tasso di successo per tipo di attacco
- Grafici comparativi

#### Analisi della Sicurezza
- Tasso di collisioni
- Distribuzione degli hash
- Vulnerabilità identificate
- Raccomandazioni di sicurezza

## 🎮 Modalità di Utilizzo

### Demo Automatica
```bash
cd src
python main.py
```

### Menu Interattivo
```bash
cd src
python main.py --interactive
```

### Test Singoli Moduli
```bash
cd src
python hash_functions.py    # Test funzioni hash
python attacks.py           # Test attacchi
python utils.py             # Setup struttura
```

## 📈 Esempi di Output

### Dimostrazione Funzioni Hash
```
Password        WeakSum    SimpleXOR    MD5                              SHA256
----------------------------------------------------------------------------------------
password        1404       4            5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
admin           505        0            21232f297a57a5a743894a0e4a801fc3     240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9
test            448        0            098f6bcd4621d373cade4e832627b4f6     9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

### Risultati Attacchi
```
✓ Password trovata: 'admin' dopo 15 tentativi in 0.003s
✓ Collisione trovata: 'abc' e 'bac' -> 294
✓ Attacco ibrido riuscito: 'admin123' (base: 'admin')
```

### Analisi Prestazioni
```
Hash Function        Hashes/sec      Collisions   Collision Rate
------------------------------------------------------------------
weak_sum            45000           23           0.023
simple_xor          52000           156          0.156
md5                 15000           0            0.000
sha256              8000            0            0.000
```

## 🔍 Vulnerabilità Dimostrate

### Hash Deboli
1. **Collisioni Frequenti**: Gli hash semplici producono facilmente collisioni
2. **Prevedibilità**: Pattern riconoscibili nell'output
3. **Velocità Eccessiva**: Permettono attacchi brute force rapidi

### Attacchi Efficaci
1. **Dizionario**: Efficace contro password comuni
2. **Brute Force**: Fattibile per password corte
3. **Ibrido**: Combina i vantaggi di entrambi
4. **Collisioni**: Dimostrano debolezza strutturale

## 🛡️ Contromisure e Raccomandazioni

### Funzioni Hash Sicure
- Utilizzare SHA-256 o superiore
- Considerare SHA-3 per nuove implementazioni
- Evitare MD5 e SHA-1

### Hashing delle Password
- Usare algoritmi specifici: bcrypt, scrypt, Argon2
- Implementare salt univoci
- Configurare parametri di costo adeguati

### Sicurezza Generale
- Password policy robuste
- Monitoraggio tentativi di accesso
- Implementazione di rate limiting

## 📋 Test e Validazione

### Scenari di Test
1. **Funzioni Hash**: Correttezza implementazione
2. **Attacchi**: Efficacia su hash deboli
3. **Prestazioni**: Velocità e scalabilità
4. **Collisioni**: Frequenza e riproducibilità

### Metriche Valutate
- Tempo di esecuzione
- Numero di tentativi
- Tasso di successo
- Memoria utilizzata

## 🔧 Configurazione Avanzata

### Personalizzazione Attacchi: 

Modificare nel file main.py i seguenti parametri (NB il file custom_wordlist.txt va creato da parte dell'utente che intende utilizzare un dizionario personalizzato e va inserito nella cartella data\wordlists)
```python
# Brute force personalizzato
manager.run_brute_force_attack(
    charset="abcdefghijklmnopqrstuvwxyz0123456789",
    min_length=6,
    max_length=8
)
```
### Personalizzazione demo attacchi:

 In main.py la classe HashSecurityDemos contiene tutte le varie demo degli attacchi (costituiscono un template base), la modifica è semplice e si può isolare esecuzione di un demo inserendo all'interno di interactive_menu() la voce desiderata associandola ad un intero (o semplicemente sostuituire una delle voci già presenti) o accorpare l'esecuzione della singola demo all'esecuzione globale di tutte le demo aggiungendo il caso desiderato a  run_full_demo(self) sempre in main.py

### Esempio: 

 Inserire attacco ibrido su hash sicuri (mi aspetto che abbia successo dato che la password scelta è comune (parola base nota e presente in common_passwords.txt), la variazione della parola base 'base123' viene testata da HybridAttack in attacks.py)
```python
    def demo_hybrid_attack_sha256(self):
        """Dimostra attacco ibrido"""
        self.print_header("ATTACCO IBRIDO")
        
        # Password con variazione comune
        target_password = "admin123"
        hash_func = self.hash_functions['sha256'] # <----- Inserire qui sha256 o md5 o algoritmo hash desiderato 
        target_hash = hash_func.hash_string(target_password)
        
        print(f"Target: '{target_password}' -> Hash: {target_hash}")
        print(f"Funzione hash: {hash_func.name}")
        
        # Esegue attacco ibrido
        manager = AttackManager(hash_func, target_hash)
        
        wordlist_path = "data/wordlists/common_passwords.txt" # <----- wordlist usata per attacco ibrido consultare la classe HybridAttack locata in attacks.py previa modifica
        if not os.path.exists(wordlist_path):
            self.print_error(f"Wordlist non trovata: {wordlist_path}")
            return
        
        print(f"\nEseguendo attacco ibrido...")
        result = manager.run_hybrid_attack(wordlist_path, verbose=False)
        
        if result.success:
            self.print_success(f"Password trovata: '{result.password_found}'")
            print(f"Parola base: '{result.additional_info.get('base_word', 'N/A')}'")
            print(f"Tentativi: {result.attempts}")
            print(f"Tempo: {result.time_elapsed:.3f} secondi")
        else:
            self.print_error("Password non trovata con attacco ibrido")
        
        # Salva risultato
        self.results_manager.save_result(result)
```

### Altro esempio di modifica - testo collisione su hash sicuri (mi aspetto non abbia successo)
```python
    def demo_collision_attacks_various_algorithms(self):
        """Dimostra attacchi di collisione"""
        self.print_header("ATTACCHI DI COLLISIONE")
        
        hashes = ['sha256', 'md5'] # <----- posso inserire qui un algoritmo a piacimento esempio 'sha256'
        
        for hash_name in hashes:
            hash_func = self.hash_functions[hash_name]
            print(f"\nTestando {hash_func.name}...")
            
            collision_tester = HashCollisionTester(hash_func)
            result = collision_tester.find_collision(100000) # <----- numero di tentativi effettuati
            
            if result['collision_found']:
                self.print_success(f"Collisione trovata dopo {result['attempts']} tentativi!")
                print(f"  '{result['string1']}' e '{result['string2']}' -> {result['hash_value']}")
            else:
                self.print_error(f"Nessuna collisione in {result['attempts']} tentativi")
                print(f"  Hash unici: {result['unique_hashes']}")
```

### E' possibile aggiungere altri algoritmi di hash, consultare la classe StandardHash presente in hash_functions.py

### Dizionario personalizzato
```python
manager.run_dictionary_attack("custom_wordlist.txt")
```

### Creazione Wordlist - Guardare file utils.py per eventuali modifiche alle wordlist
```python
# Wordlist numerica
WordlistManager.create_numeric_wordlist("numbers.txt", 1, 8)

# Wordlist personalizzata
WordlistManager.create_alpha_wordlist("letters.txt", 1, 5)
```

## 📊 Grafici e Visualizzazioni

Il progetto genera automaticamente:
- Grafici delle prestazioni per tipo di attacco
- Distribuzione dei tempi di esecuzione
- Analisi comparative delle funzioni hash
- Statistiche di successo

I grafici vengono salvati in `results/` in formato PNG ad alta risoluzione.

### Concetti Dimostrati
1. **Proprietà delle funzioni hash**
2. **Vulnerabilità crittografiche**
3. **Tecniche di attacco**
4. **Analisi delle prestazioni**
5. **Sicurezza pratica**


## 🚨 Considerazioni Etiche

Questo progetto è sviluppato esclusivamente per:
- Scopi educativi e didattici
- Dimostrazione di vulnerabilità
- Comprensione della sicurezza informatica

**Non deve essere utilizzato per attività illegali o dannose.**

## 📝 Licenza

Progetto sviluppato per l'esame di Sicurezza dell'Informazione.
Uso esclusivamente didattico e accademico.

---

**Autore**: Marco Crisafulli
**Corso**: Sicurezza dell'Informazione  
**Anno Accademico**: 2024/2025  
**Tutor**: Nicolò Romandini