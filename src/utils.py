import os
import time
import json
import matplotlib.pyplot as plt
import numpy as np
from typing import List, Dict, Any
from datetime import datetime

class Timer:
    """Classe per misurare tempi di esecuzione"""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
    
    def start(self):
        """Inizia il cronometro"""
        self.start_time = time.time()
    
    def stop(self):
        """Ferma il cronometro"""
        self.end_time = time.time()
        return self.elapsed()
    
    def elapsed(self):
        """Restituisce il tempo trascorso"""
        if self.start_time is None:
            return 0
        end = self.end_time or time.time()
        return end - self.start_time
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, *args):
        self.stop()

class WordlistManager:
    """Gestore per le wordlist"""
    
    @staticmethod
    def create_common_passwords_wordlist(filepath: str):
        """Crea una wordlist con password comuni"""
        common_passwords = [
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "1234567890", "abc123",
            "test", "user", "login", "pass", "root", "toor",
            "guest", "hello", "world", "demo", "sample",
            "secret", "key", "default", "changeme", "password1",
            "111111", "000000", "123123", "654321", "987654321",
            "sunshine", "princess", "football", "baseball", "dragon",
            "master", "shadow", "michael", "computer", "superman"
        ]
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            for password in common_passwords:
                f.write(password + '\n')
        
        return len(common_passwords)
    
    @staticmethod
    def create_numeric_wordlist(filepath: str, min_length: int = 1, max_length: int = 6):
        """Crea una wordlist con combinazioni numeriche"""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        count = 0
        
        with open(filepath, 'w') as f:
            for length in range(min_length, max_length + 1):
                for num in range(10 ** (length - 1), 10 ** length):
                    f.write(str(num) + '\n')
                    count += 1
        
        return count
    
    @staticmethod
    def create_alpha_wordlist(filepath: str, min_length: int = 1, max_length: int = 4):
        """Crea una wordlist con combinazioni alfabetiche"""
        import string
        import itertools
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        count = 0
        
        with open(filepath, 'w') as f:
            for length in range(min_length, max_length + 1):
                for combination in itertools.product(string.ascii_lowercase, repeat=length):
                    f.write(''.join(combination) + '\n')
                    count += 1
        
        return count
    
    @staticmethod
    def get_wordlist_info(filepath: str) -> Dict[str, Any]:
        """Restituisce informazioni su una wordlist"""
        if not os.path.exists(filepath):
            return {"error": "File non trovato"}
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        lengths = [len(line.strip()) for line in lines if line.strip()]
        
        return {
            "filepath": filepath,
            "total_entries": len(lines),
            "valid_entries": len(lengths),
            "min_length": min(lengths) if lengths else 0,
            "max_length": max(lengths) if lengths else 0,
            "avg_length": sum(lengths) / len(lengths) if lengths else 0,
            "file_size": os.path.getsize(filepath)
        }

class ResultsManager:
    """Gestisce i risultati degli attacchi"""
    
    def __init__(self, results_dir: str = "results"):
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)
    
    def save_result(self, result, filename: str = None):
        """Salva il risultato di un attacco"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"attack_result_{timestamp}.json"
        
        filepath = os.path.join(self.results_dir, filename)
        
        # Converte l'oggetto AttackResult in Log leggibile
        result_dict = {
            "timestamp": datetime.now().isoformat(),
            "success": result.success,
            "password_found": result.password_found,
            "attempts": result.attempts,
            "time_elapsed": result.time_elapsed,
            "hash_target": result.hash_target,
            "attack_type": result.attack_type,
            "additional_info": result.additional_info
        }
        
        with open(filepath, 'w') as f:
            json.dump(result_dict, f, indent=2)
        
        return filepath
    
    def load_results(self) -> List[Dict[str, Any]]:
        """Carica tutti i risultati salvati"""
        results = []
        
        for filename in os.listdir(self.results_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.results_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        result = json.load(f)
                        results.append(result)
                except Exception as e:
                    print(f"Errore nel caricamento di {filename}: {e}")
        
        return results

class PerformanceAnalyzer:
    """Analizza le prestazioni degli attacchi"""
    
    def __init__(self, results_manager: ResultsManager):
        self.results_manager = results_manager
    
    def generate_performance_report(self, save_plots: bool = True) -> Dict[str, Any]:
        """Genera un report delle prestazioni"""
        results = self.results_manager.load_results()
        
        if not results:
            return {"error": "Nessun risultato disponibile"}
        
        # Analisi per tipo di attacco
        attack_types = {}
        for result in results:
            attack_type = result.get('attack_type', 'Unknown')
            if attack_type not in attack_types:
                attack_types[attack_type] = {
                    'count': 0,
                    'successes': 0,
                    'total_attempts': 0,
                    'total_time': 0,
                    'attempts_list': [],
                    'time_list': []
                }
            
            attack_types[attack_type]['count'] += 1
            attack_types[attack_type]['total_attempts'] += result.get('attempts', 0)
            attack_types[attack_type]['total_time'] += result.get('time_elapsed', 0)
            attack_types[attack_type]['attempts_list'].append(result.get('attempts', 0))
            attack_types[attack_type]['time_list'].append(result.get('time_elapsed', 0))
            
            if result.get('success', False):
                attack_types[attack_type]['successes'] += 1
        
        # Calcola statistiche
        for attack_type, stats in attack_types.items():
            if stats['count'] > 0:
                stats['success_rate'] = stats['successes'] / stats['count']
                stats['avg_attempts'] = stats['total_attempts'] / stats['count']
                stats['avg_time'] = stats['total_time'] / stats['count']
                stats['attempts_per_second'] = stats['total_attempts'] / stats['total_time'] if stats['total_time'] > 0 else 0
        
        # Genera grafici se richiesto
        if save_plots:
            self._generate_plots(attack_types)
        
        return {
            "total_attacks": len(results),
            "attack_types": attack_types,
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    def _generate_plots(self, attack_types: Dict[str, Any]):
        """Genera grafici delle prestazioni"""
        if not attack_types:
            return
        
        # Imposta lo stile
        plt.style.use('default')
        
        # Grafico 1: Tasso di successo per tipo di attacco
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
        
        types = list(attack_types.keys())
        success_rates = [attack_types[t]['success_rate'] * 100 for t in types]
        
        ax1.bar(types, success_rates, color=['green' if rate > 50 else 'orange' if rate > 0 else 'red' for rate in success_rates])
        ax1.set_title('Tasso di Successo per Tipo di Attacco')
        ax1.set_ylabel('Tasso di Successo (%)')
        ax1.set_ylim(0, 100)
        
        # Grafico 2: Tempo medio per tipo di attacco
        avg_times = [attack_types[t]['avg_time'] for t in types]
        ax2.bar(types, avg_times, color='blue', alpha=0.7)
        ax2.set_title('Tempo Medio per Tipo di Attacco')
        ax2.set_ylabel('Tempo (secondi)')
        
        # Grafico 3: Tentativi medi per tipo di attacco
        avg_attempts = [attack_types[t]['avg_attempts'] for t in types]
        ax3.bar(types, avg_attempts, color='purple', alpha=0.7)
        ax3.set_title('Tentativi Medi per Tipo di Attacco')
        ax3.set_ylabel('Numero di Tentativi')
        
        # Grafico 4: Tentativi per secondo
        attempts_per_sec = [attack_types[t]['attempts_per_second'] for t in types]
        ax4.bar(types, attempts_per_sec, color='orange', alpha=0.7)
        ax4.set_title('Velocità di Attacco (Tentativi/secondo)')
        ax4.set_ylabel('Tentativi per secondo')
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.results_manager.results_dir, 'performance_analysis.png'), dpi=300, bbox_inches='tight')
        plt.close()
        
        # Grafico aggiuntivo: Distribuzione dei tempi
        fig, ax = plt.subplots(figsize=(10, 6))
        
        for attack_type, stats in attack_types.items():
            if stats['time_list']:
                ax.hist(stats['time_list'], alpha=0.7, label=attack_type, bins=20)
        
        ax.set_xlabel('Tempo (secondi)')
        ax.set_ylabel('Frequenza')
        ax.set_title('Distribuzione dei Tempi di Attacco')
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.results_manager.results_dir, 'time_distribution.png'), dpi=300, bbox_inches='tight')
        plt.close()

class HashAnalyzer:
    """Analizza le proprietà degli hash"""
    
    @staticmethod
    def analyze_hash_distribution(hash_function, sample_size: int = 10000) -> Dict[str, Any]:
        """Analizza la distribuzione degli hash"""
        import random
        import string
        
        hashes = []
        for _ in range(sample_size):
            # Genera stringa casuale
            length = random.randint(1, 20)
            random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
            hash_value = hash_function.hash_string(random_string)
            hashes.append(hash_value)
        
        unique_hashes = len(set(hashes))
        collision_rate = (sample_size - unique_hashes) / sample_size
        
        return {
            "sample_size": sample_size,
            "unique_hashes": unique_hashes,
            "collisions": sample_size - unique_hashes,
            "collision_rate": collision_rate,
            "hash_function": hash_function.name
        }
    
    @staticmethod
    def measure_hash_performance(hash_function, iterations: int = 100000) -> Dict[str, Any]:
        """Misura le prestazioni di una funzione hash"""
        import random
        import string
        
        test_string = "test_performance_string"
        
        # Misura tempo per singolo hash
        with Timer() as timer:
            for _ in range(iterations):
                hash_function.hash_string(test_string)
        
        single_time = timer.elapsed()
        
        # Misura tempo per stringhe casuali
        random_strings = []
        for _ in range(1000):
            length = random.randint(5, 50)
            random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
            random_strings.append(random_string)
        
        with Timer() as timer:
            for string in random_strings:
                hash_function.hash_string(string)
        
        random_time = timer.elapsed()
        
        return {
            "hash_function": hash_function.name,
            "single_string_iterations": iterations,
            "single_string_time": single_time,
            "hashes_per_second": iterations / single_time,
            "random_strings_count": len(random_strings),
            "random_strings_time": random_time,
            "random_hashes_per_second": len(random_strings) / random_time
        }

def setup_project_structure():
    """Configura la struttura del progetto"""
    directories = [
        "data/wordlists",
        "results",
        "src"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # Crea wordlist di base
    wordlist_manager = WordlistManager()
    
    # Wordlist password comuni
    common_count = wordlist_manager.create_common_passwords_wordlist("data/wordlists/common_passwords.txt")
    print(f"Creata wordlist password comuni: {common_count} entries")
    
    # Wordlist numerica
    numeric_count = wordlist_manager.create_numeric_wordlist("data/wordlists/numeric.txt", 1, 4)
    print(f"Creata wordlist numerica: {numeric_count} entries")
    
    # Wordlist alfabetica (solo per test rapidi)
    alpha_count = wordlist_manager.create_alpha_wordlist("data/wordlists/alpha_short.txt", 1, 3)
    print(f"Creata wordlist alfabetica: {alpha_count} entries")
    
    print("Setup del progetto completato!")

def print_project_info():
    """Stampa informazioni sul progetto"""
    print("=== HASH SECURITY PROJECT ===")
    print("Progetto per l'analisi della sicurezza delle funzioni hash")
    print("Sviluppato per l'esame di Sicurezza dell'Informazione")
    print()
    print("Struttura del progetto:")
    print("├── src/")
    print("│   ├── hash_functions.py   # Implementazioni hash")
    print("│   ├── attacks.py          # Algoritmi di attacco")
    print("│   ├── utils.py            # Utilities")
    print("│   └── main.py             # Demo principale")
    print("├── data/")
    print("│   └── wordlists/          # Dizionari per attacchi")
    print("├── results/                # Risultati degli attacchi")
    print("└── README.md               # Documentazione")
    print()

if __name__ == "__main__":
    print_project_info()
    setup_project_structure()