# BPHAI - Behavioral Pattern Hashing AI

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/security-hardened-green.svg)](https://github.com/yourusername/bphai)

BPHAI è un sistema di intelligenza artificiale avanzato progettato per resistere agli attacchi di prompt injection attraverso l'uso di Rooted Neural Units (RNU) e tecniche di Move Masking.

## 🚀 Caratteristiche Principali

- **Rooted Neural Units (RNU)**: Unità neurali specializzate per diversi tipi di analisi
- **Move Masking**: Sistema di mascheramento delle risposte per contrastare attacchi
- **Orchestratore LLM**: Aggregazione intelligente dei risultati delle RNU
- **Resistenza ai Prompt Injection**: Protezione avanzata contro vari tipi di attacchi
- **Architettura Modulare**: Facilmente estensibile e personalizzabile
- **Elaborazione Asincrona**: Supporto per carichi di lavoro ad alta concorrenza
- **Monitoraggio Avanzato**: Metriche dettagliate e valutazione della salute del sistema

## 📋 Requisiti

- Python 3.8 o superiore
- Dipendenze elencate in `requirements.txt`

## 🛠️ Installazione

### Installazione Standard

```bash
# Clona il repository
git clone https://github.com/yourusername/bphai.git
cd bphai

# Crea un ambiente virtuale
python -m venv venv
source venv/bin/activate  # Su Windows: venv\Scripts\activate

# Installa le dipendenze
pip install -r requirements.txt

# Installa il pacchetto
pip install -e .
```

### Installazione per Sviluppo

```bash
# Installa con dipendenze di sviluppo
pip install -e ".[dev]"

# Configura pre-commit hooks
pre-commit install
```

### Installazione con Componenti Opzionali

```bash
# Con interfaccia web
pip install -e ".[web]"

# Con supporto database
pip install -e ".[database]"

# Con caching Redis
pip install -e ".[cache]"

# Installazione completa
pip install -e ".[all]"
```

## 🚀 Utilizzo Rapido

### Esempio Base

```python
from bphai import BPHAI

# Inizializza il sistema BPHAI
bphai = BPHAI()

# Elabora un input
response = bphai.process("Ciao, come stai?")

print(f"Risposta: {response.content}")
print(f"Livello di minaccia: {response.threat_assessment['threat_level'].name}")
print(f"Successo: {response.success}")
```

### Configurazione Personalizzata

```python
from bphai import BPHAI, BPHAIConfig
from core.move_masking import MaskingStrategy
from core.orchestrator import ThreatLevel

# Configurazione personalizzata
config = BPHAIConfig(
    enable_security_rnu=True,
    enable_analysis_rnu=True,
    enable_response_rnu=True,
    enable_move_masking=True,
    default_masking_strategy=MaskingStrategy.AGGRESSIVE,
    threat_threshold=ThreatLevel.MEDIUM,
    enable_logging=True
)

bphai = BPHAI(config)
```

### Elaborazione Asincrona

```python
import asyncio
from bphai import BPHAI

async def process_multiple():
    bphai = BPHAI()
    
    queries = [
        "Che tempo fa oggi?",
        "Spiegami l'intelligenza artificiale",
        "Come funziona il machine learning?"
    ]
    
    # Elabora tutte le query in parallelo
    tasks = [bphai.process_async(query) for query in queries]
    responses = await asyncio.gather(*tasks)
    
    for i, response in enumerate(responses):
        print(f"Query {i+1}: {response.content[:50]}...")

# Esegui l'esempio asincrono
asyncio.run(process_multiple())
```

## 🏗️ Architettura

### Componenti Principali

1. **BPHAI Core**: Interfaccia principale del sistema
2. **Rooted Neural Units (RNU)**: Unità specializzate per l'analisi
   - SecurityRNU: Rilevamento minacce
   - AnalysisRNU: Analisi del contenuto
   - ResponseRNU: Generazione risposte sicure
3. **Orchestratore**: Aggregazione e coordinamento delle RNU
4. **Move Masking**: Sistema di mascheramento delle risposte
5. **Sistema di Configurazione**: Gestione flessibile delle impostazioni

### Flusso di Elaborazione

```
Input → RNU Security → RNU Analysis → RNU Response → Orchestratore → Move Masking → Output
```

## 🔧 Configurazione

### File di Configurazione

Copia `.env.example` in `.env` e personalizza le impostazioni:

```bash
cp .env.example .env
```

### Variabili di Ambiente Principali

```env
# Configurazione Core
BPHAI_ENABLE_SECURITY_RNU=true
BPHAI_ENABLE_ANALYSIS_RNU=true
BPHAI_ENABLE_RESPONSE_RNU=true
BPHAI_ENABLE_MOVE_MASKING=true

# Soglie di Sicurezza
BPHAI_THREAT_THRESHOLD=MEDIUM
BPHAI_DEFAULT_MASKING_STRATEGY=MODERATE

# Performance
BPHAI_MAX_CONCURRENT_REQUESTS=100
BPHAI_REQUEST_TIMEOUT=30

# Logging
BPHAI_LOG_LEVEL=INFO
BPHAI_ENABLE_DETAILED_LOGGING=true
```

## 🧪 Test

### Esecuzione dei Test

```bash
# Esegui tutti i test
pytest

# Test con copertura
pytest --cov=src --cov-report=html

# Test specifici per la resistenza ai prompt injection
pytest tests/test_prompt_injection_resistance.py -v

# Test delle performance
pytest tests/test_bphai_core.py::test_performance_benchmark -v
```

### Test di Sicurezza

```bash
# Test di sicurezza con Bandit
bandit -r src/

# Controllo vulnerabilità dipendenze
safety check
```

## 📊 Esempi

### Esempi Inclusi

1. **basic_usage.py**: Utilizzo base del sistema
2. **advanced_usage.py**: Funzionalità avanzate e monitoraggio
3. **security_rnu.py**: Esempio di RNU per la sicurezza
4. **analysis_rnu.py**: Esempio di RNU per l'analisi
5. **response_rnu.py**: Esempio di RNU per le risposte

### Esecuzione degli Esempi

```bash
# Esempio base
python examples/basic_usage.py

# Esempio avanzato
python examples/advanced_usage.py
```

## 🔒 Sicurezza

### Caratteristiche di Sicurezza

- **Rilevamento Prompt Injection**: Identificazione automatica di tentativi di manipolazione
- **Move Masking**: Mascheramento delle risposte per contrastare attacchi
- **Validazione Input**: Controllo rigoroso degli input utente
- **Logging Sicuro**: Registrazione eventi senza esporre dati sensibili
- **Configurazione Sicura**: Gestione sicura delle credenziali

### Best Practices

1. Mantieni sempre aggiornate le dipendenze
2. Usa variabili d'ambiente per le configurazioni sensibili
3. Monitora regolarmente i log di sicurezza
4. Testa regolarmente la resistenza agli attacchi
5. Configura soglie di minaccia appropriate per il tuo caso d'uso

## 📈 Monitoraggio e Performance

### Metriche Disponibili

- Numero totale di richieste elaborate
- Minacce rilevate e bloccate
- Tempo medio di elaborazione
- Utilizzo memoria e CPU
- Stato di salute delle RNU
- Statistiche di Move Masking

### Monitoraggio in Tempo Reale

```python
from bphai import BPHAI

bphai = BPHAI()

# Ottieni stato del sistema
status = bphai.get_system_status()
print(f"Salute sistema: {status['system_health']}")
print(f"RNU attive: {status['rnu_count']}")
print(f"Statistiche: {status['statistics']}")
```

## 🔧 Sviluppo

### Struttura del Progetto

```
bphai/
├── src/
│   ├── core/                 # Componenti core
│   │   ├── rnu.py           # Rooted Neural Units
│   │   ├── orchestrator.py  # Orchestratore LLM
│   │   └── move_masking.py  # Move Masking
│   ├── examples/            # RNU di esempio
│   └── bphai.py            # Interfaccia principale
├── tests/                   # Test suite
├── examples/               # Esempi di utilizzo
├── docs/                   # Documentazione
└── requirements.txt        # Dipendenze
```

### Contribuire

1. Fork del repository
2. Crea un branch per la tua feature (`git checkout -b feature/AmazingFeature`)
3. Commit delle modifiche (`git commit -m 'Add some AmazingFeature'`)
4. Push al branch (`git push origin feature/AmazingFeature`)
5. Apri una Pull Request

### Linee Guida per lo Sviluppo

- Segui PEP 8 per lo stile del codice
- Scrivi test per tutte le nuove funzionalità
- Documenta il codice con docstring
- Usa type hints dove possibile
- Mantieni la compatibilità con Python 3.8+

## 🐛 Risoluzione Problemi

### Problemi Comuni

**Errore di importazione moduli**
```bash
# Assicurati che il pacchetto sia installato correttamente
pip install -e .
```

**Performance lente**
```python
# Disabilita RNU non necessarie per migliorare le performance
config = BPHAIConfig(
    enable_analysis_rnu=False,  # Se non serve analisi dettagliata
    enable_response_rnu=False   # Se non serve generazione risposte
)
```

**Memoria insufficiente**
```env
# Riduci il numero di richieste concorrenti
BPHAI_MAX_CONCURRENT_REQUESTS=50
```

### Debug

```python
# Abilita logging dettagliato
import logging
logging.basicConfig(level=logging.DEBUG)

# Usa modalità debug
config = BPHAIConfig(enable_logging=True, log_level="DEBUG")
bphai = BPHAI(config)
```

## 📚 Documentazione

- [Guida API](docs/api.md)
- [Tutorial Avanzato](docs/advanced.md)
- [Architettura del Sistema](docs/architecture.md)
- [Sicurezza](docs/security.md)
- [Performance](docs/performance.md)

## 🤝 Supporto

- **Issues**: [GitHub Issues](https://github.com/yourusername/bphai/issues)
- **Discussioni**: [GitHub Discussions](https://github.com/yourusername/bphai/discussions)
- **Email**: support@bphai.dev

## 📄 Licenza

Questo progetto è rilasciato sotto licenza MIT. Vedi il file [LICENSE](LICENSE) per i dettagli.

## 🙏 Riconoscimenti

- Ispirato dalle ricerche sulla sicurezza dell'AI
- Basato sui principi di defense in depth
- Contributi della comunità open source

## 🔄 Changelog

### v1.0.0 (2024-01-XX)
- Rilascio iniziale
- Implementazione RNU base
- Sistema Move Masking
- Orchestratore LLM
- Test di resistenza prompt injection

---

**BPHAI** - Proteggendo l'AI dal futuro, oggi.