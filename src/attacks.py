import string
import itertools
import time
import threading
from typing import Generator, Optional, Dict, Any, List
from tqdm import tqdm
import os

class AttackResult:
    """Risultato di un attacco hash"""
    
    def __init__(self):
        self.success = False
        self.password_found = None
        self.attempts = 0
        self.time_elapsed = 0
        self.hash_target = None
        self.attack_type = None
        self.additional_info = {}
    
    def __str__(self):
        if self.success:
            return (f"✓ Password trovata: '{self.password_found}' "
                   f"dopo {self.attempts} tentativi in {self.time_elapsed:.2f}s")
        else:
            return (f"✗ Password non trovata dopo {self.attempts} tentativi "
                   f"in {self.time_elapsed:.2f}s")

class BaseAttack:
    """Classe base per tutti gli attacchi"""
    
    def __init__(self, hash_function, target_hash, verbose=True):
        self.hash_function = hash_function
        self.target_hash = target_hash
        self.verbose = verbose
        self.stop_attack = False
    
    def attack(self) -> AttackResult:
        """Esegue l'attacco e restituisce il risultato"""
        raise NotImplementedError
    
    def stop(self):
        """Ferma l'attacco in corso"""
        self.stop_attack = True

class BruteForceAttack(BaseAttack):
    """Attacco brute force che prova tutte le combinazioni possibili"""
    
    def __init__(self, hash_function, target_hash, charset=None, min_length=1, max_length=4, verbose=True):
        super().__init__(hash_function, target_hash, verbose)
        self.charset = charset or string.ascii_lowercase + string.digits
        self.min_length = min_length
        self.max_length = max_length
    
    def generate_passwords(self) -> Generator[str, None, None]:
        """Genera tutte le possibili password"""
        for length in range(self.min_length, self.max_length + 1):
            for combination in itertools.product(self.charset, repeat=length):
                if self.stop_attack:
                    return
                yield ''.join(combination)
    
    def attack(self) -> AttackResult:
        """Esegue l'attacco brute force"""
        result = AttackResult()
        result.attack_type = "Brute Force"
        result.hash_target = self.target_hash
        
        start_time = time.time()
        
        # Calcola il numero totale di combinazioni per la progress bar
        total_combinations = sum(len(self.charset) ** length 
                               for length in range(self.min_length, self.max_length + 1))
        
        if self.verbose:
            print(f"Iniziando attacco brute force...")
            print(f"Charset: {self.charset}")
            print(f"Lunghezza: {self.min_length}-{self.max_length}")
            print(f"Combinazioni totali: {total_combinations}")
            pbar = tqdm(total=total_combinations, desc="Brute Force")
        
        for password in self.generate_passwords():
            if self.stop_attack:
                break
            
            result.attempts += 1
            
            # Calcola l'hash della password candidata
            candidate_hash = self.hash_function.hash_string(password)
            
            if self.verbose and result.attempts % 1000 == 0:
                pbar.update(1000)
            
            # Controlla se abbiamo trovato la password
            if candidate_hash == self.target_hash:
                result.success = True
                result.password_found = password
                break
        
        result.time_elapsed = time.time() - start_time
        
        if self.verbose:
            pbar.close()
        
        return result

class DictionaryAttack(BaseAttack):
    """Attacco dizionario che usa una wordlist"""
    
    def __init__(self, hash_function, target_hash, wordlist_path, verbose=True):
        super().__init__(hash_function, target_hash, verbose)
        self.wordlist_path = wordlist_path
    
    def load_wordlist(self) -> List[str]:
        """Carica la wordlist da file"""
        if not os.path.exists(self.wordlist_path):
            raise FileNotFoundError(f"Wordlist non trovata: {self.wordlist_path}")
        
        with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    
    def attack(self) -> AttackResult:
        """Esegue l'attacco dizionario"""
        result = AttackResult()
        result.attack_type = "Dictionary"
        result.hash_target = self.target_hash
        
        start_time = time.time()
        
        try:
            wordlist = self.load_wordlist()
        except FileNotFoundError as e:
            result.additional_info['error'] = str(e)
            result.time_elapsed = time.time() - start_time
            return result
        
        if self.verbose:
            print(f"Iniziando attacco dizionario...")
            print(f"Wordlist: {self.wordlist_path}")
            print(f"Parole da testare: {len(wordlist)}")
            pbar = tqdm(wordlist, desc="Dictionary Attack")
        
        for password in wordlist:
            if self.stop_attack:
                break
            
            result.attempts += 1
            
            # Calcola l'hash della password candidata
            candidate_hash = self.hash_function.hash_string(password)
            
            if self.verbose:
                pbar.set_postfix({'current': password[:10]})
            
            # Controlla se abbiamo trovato la password
            if candidate_hash == self.target_hash:
                result.success = True
                result.password_found = password
                break
        
        result.time_elapsed = time.time() - start_time
        
        if self.verbose:
            pbar.close()
        
        return result

class HybridAttack(BaseAttack):
    """Attacco ibrido: dizionario + variazioni comuni"""
    
    def __init__(self, hash_function, target_hash, wordlist_path, verbose=True):
        super().__init__(hash_function, target_hash, verbose)
        self.wordlist_path = wordlist_path
    
    def generate_variations(self, word: str) -> Generator[str, None, None]:
        """Genera variazioni comuni di una parola"""
        variations = [
            word,                           # Parola originale
            word.lower(),                   # Tutto minuscolo
            word.upper(),                   # Tutto maiuscolo
            word.capitalize(),              # Prima lettera maiuscola
            word + "123",                   # Aggiunge numeri
            word + "!",                     # Aggiunge simboli
            word + "1",
            "123" + word,
            word + word,                    # Ripete la parola
            word[::-1],                     # Rovescia la parola
        ]
        
        # Sostituzioni comuni
        substitutions = {
            'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'
        }
        
        # Applica sostituzioni
        for original, replacement in substitutions.items():
            if original in word.lower():
                variations.append(word.lower().replace(original, replacement))
        
        return variations
    
    def attack(self) -> AttackResult:
        """Esegue l'attacco ibrido"""
        result = AttackResult()
        result.attack_type = "Hybrid"
        result.hash_target = self.target_hash
        
        start_time = time.time()
        
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except FileNotFoundError as e:
            result.additional_info['error'] = str(e)
            result.time_elapsed = time.time() - start_time
            return result
        
        if self.verbose:
            print(f"Iniziando attacco ibrido...")
            print(f"Wordlist: {self.wordlist_path}")
            print(f"Parole base: {len(wordlist)}")
            pbar = tqdm(wordlist, desc="Hybrid Attack")
        
        for base_word in wordlist:
            if self.stop_attack:
                break
            
            if self.verbose:
                pbar.set_postfix({'word': base_word[:10]})
            
            # Prova tutte le variazioni della parola
            for variation in self.generate_variations(base_word):
                if self.stop_attack:
                    break
                
                result.attempts += 1
                
                # Calcola l'hash della password candidata
                candidate_hash = self.hash_function.hash_string(variation)
                
                # Controlla se abbiamo trovato la password
                if candidate_hash == self.target_hash:
                    result.success = True
                    result.password_found = variation
                    result.additional_info['base_word'] = base_word
                    result.time_elapsed = time.time() - start_time
                    if self.verbose:
                        pbar.close()
                    return result
            
            if self.verbose:
                pbar.update(1)
        
        result.time_elapsed = time.time() - start_time
        
        if self.verbose:
            pbar.close()
        
        return result

class AttackManager:
    """Gestisce e coordina diversi tipi di attacchi"""
    
    def __init__(self, hash_function, target_hash):
        self.hash_function = hash_function
        self.target_hash = target_hash
        self.current_attack = None
        self.results = []
    
    def run_dictionary_attack(self, wordlist_path: str, verbose: bool = True) -> AttackResult:
        """Esegue un attacco dizionario"""
        attack = DictionaryAttack(self.hash_function, self.target_hash, wordlist_path, verbose)
        self.current_attack = attack
        result = attack.attack()
        self.results.append(result)
        return result
    
    def run_brute_force_attack(self, charset: str = None, min_length: int = 1, 
                             max_length: int = 4, verbose: bool = True) -> AttackResult:
        """Esegue un attacco brute force"""
        attack = BruteForceAttack(self.hash_function, self.target_hash, charset, 
                                min_length, max_length, verbose)
        self.current_attack = attack
        result = attack.attack()
        self.results.append(result)
        return result
    
    def run_hybrid_attack(self, wordlist_path: str, verbose: bool = True) -> AttackResult:
        """Esegue un attacco ibrido"""
        attack = HybridAttack(self.hash_function, self.target_hash, wordlist_path, verbose)
        self.current_attack = attack
        result = attack.attack()
        self.results.append(result)
        return result
    
    def stop_current_attack(self):
        """Ferma l'attacco corrente"""
        if self.current_attack:
            self.current_attack.stop()
    
    def get_attack_statistics(self) -> Dict[str, Any]:
        """Restituisce statistiche sugli attacchi eseguiti"""
        if not self.results:
            return {}
        
        stats = {
            'total_attacks': len(self.results),
            'successful_attacks': sum(1 for r in self.results if r.success),
            'total_attempts': sum(r.attempts for r in self.results),
            'total_time': sum(r.time_elapsed for r in self.results),
            'attacks_by_type': {}
        }
        
        for result in self.results:
            attack_type = result.attack_type
            if attack_type not in stats['attacks_by_type']:
                stats['attacks_by_type'][attack_type] = {
                    'count': 0,
                    'successes': 0,
                    'total_attempts': 0,
                    'total_time': 0
                }
            
            stats['attacks_by_type'][attack_type]['count'] += 1
            stats['attacks_by_type'][attack_type]['total_attempts'] += result.attempts
            stats['attacks_by_type'][attack_type]['total_time'] += result.time_elapsed
            if result.success:
                stats['attacks_by_type'][attack_type]['successes'] += 1
        
        return stats

# Funzione di test del modulo
def test_attacks():
    """Test delle funzioni di attacco"""
    from hash_functions import WeakSumHash, StandardHash
    
    print("=== TEST MODULO ATTACCHI ===\n")
    
    # Test con hash debole
    weak_hash = WeakSumHash(1000)
    target_password = "test"
    target_hash = weak_hash.hash_string(target_password)
    
    print(f"Target: '{target_password}' -> Hash: {target_hash}")
    print()
    
    # Test attacco brute force
    print("1. Test Brute Force Attack:")
    manager = AttackManager(weak_hash, target_hash)
    result = manager.run_brute_force_attack(
        charset=string.ascii_lowercase,
        min_length=1,
        max_length=5,
        verbose=True
    )
    print(result)
    print()
    
    # Crea wordlist temporanea per test
    test_wordlist = "data/wordlists/test.txt"
    os.makedirs(os.path.dirname(test_wordlist), exist_ok=True)
    with open(test_wordlist, 'w') as f:
        f.write("password\ntest\nadmin\n123456\nhello\n")
    
    # Test attacco dizionario
    print("2. Test Dictionary Attack:")
    result = manager.run_dictionary_attack(test_wordlist, verbose=True)
    print(result)
    print()
    
    # Statistiche
    stats = manager.get_attack_statistics()
    print("3. Statistiche:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    test_attacks()