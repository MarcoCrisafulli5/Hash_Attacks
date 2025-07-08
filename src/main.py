#!/usr/bin/env python3
"""
Main demo del progetto Hash Security
Dimostra vulnerabilità delle funzioni hash e tecniche di attacco
"""

import sys
import os
import time
from colorama import init, Fore, Back, Style

# Inizializza colorama per output colorato
init()

# Aggiunge src al path
sys.path.append(os.path.join(os.path.dirname(__file__), '.'))

from hash_functions import *
from attacks import *
from utils import *

class HashSecurityDemo:
    """Classe principale per la demo del progetto"""
    
    def __init__(self):
        self.results_manager = ResultsManager()
        self.performance_analyzer = PerformanceAnalyzer(self.results_manager)
        
        # Inizializza le funzioni hash
        self.hash_functions = {
            'weak_sum': WeakSumHash(1000),
            'weak_sum_large': WeakSumHash(65536),
            'simple_xor': SimpleXORHash(),
            'weak_multiply': WeakMultiplyHash(),
            'md5': StandardHash('md5'),
            'sha256': StandardHash('sha256')
        }
        
        # Password di test
        self.test_passwords = [
            "test", "admin", "password", "123456", "hello", 
            "abc", "key", "secret", "demo", "user"
        ]
    
    def print_header(self, title):
        """Stampa intestazione colorata"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{title.center(60)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    def print_success(self, message):
        """Stampa messaggio di successo"""
        print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")
    
    def print_error(self, message):
        """Stampa messaggio di errore"""
        print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")
    
    def print_info(self, message):
        """Stampa messaggio informativo"""
        print(f"{Fore.YELLOW}ℹ {message}{Style.RESET_ALL}")
    
    def demo_hash_functions(self):
        """Dimostra il funzionamento delle funzioni hash"""
        self.print_header("DIMOSTRAZIONE FUNZIONI HASH")
        
        print(f"{'Password':<15} {'WeakSum':<10} {'SimpleXOR':<12} {'MD5':<35} {'SHA256':<20}")
        print("-" * 100)
        
        for password in self.test_passwords:
            row = f"{password:<15} "
            row += f"{self.hash_functions['weak_sum'].hash_string(password):<10} "
            row += f"{self.hash_functions['simple_xor'].hash_string(password):<12} "
            row += f"{self.hash_functions['md5'].hash_string(password)[:32]:<35} "
            row += f"{str(self.hash_functions['sha256'].hash_string(password))[:20]:<20}"
            print(row)
        
        print()
        self.print_info("Nota: Gli hash deboli mostrano pattern prevedibili")
    
    def demo_collision_attacks(self):
        """Dimostra attacchi di collisione"""
        self.print_header("ATTACCHI DI COLLISIONE")
        
        weak_hashes = ['weak_sum', 'simple_xor', 'weak_multiply']
        
        for hash_name in weak_hashes:
            hash_func = self.hash_functions[hash_name]
            print(f"\nTestando {hash_func.name}...")
            
            collision_tester = HashCollisionTester(hash_func)
            result = collision_tester.find_collision(10000)
            
            if result['collision_found']:
                self.print_success(f"Collisione trovata dopo {result['attempts']} tentativi!")
                print(f"  '{result['string1']}' e '{result['string2']}' -> {result['hash_value']}")
            else:
                self.print_error(f"Nessuna collisione in {result['attempts']} tentativi")
                print(f"  Hash unici: {result['unique_hashes']}")
    
    def demo_dictionary_attack(self):
        """Dimostra attacco dizionario"""
        self.print_header("ATTACCO DIZIONARIO")
        
        # Seleziona password target
        target_password = "admin"
        hash_func = self.hash_functions['weak_sum']
        target_hash = hash_func.hash_string(target_password)
        
        print(f"Target: '{target_password}' -> Hash: {target_hash}")
        print(f"Funzione hash: {hash_func.name}")
        
        # Esegue attacco dizionario
        manager = AttackManager(hash_func, target_hash)
        
        wordlist_path = "data/wordlists/common_passwords.txt"
        if not os.path.exists(wordlist_path):
            self.print_error(f"Wordlist non trovata: {wordlist_path}")
            return
        
        print(f"\nEseguendo attacco dizionario...")
        result = manager.run_dictionary_attack(wordlist_path, verbose=False)
        
        if result.success:
            self.print_success(f"Password trovata: '{result.password_found}'")
            print(f"Tentativi: {result.attempts}")
            print(f"Tempo: {result.time_elapsed:.3f} secondi")
        else:
            self.print_error("Password non trovata nel dizionario")
        
        # Salva risultato
        self.results_manager.save_result(result)
    
    def demo_brute_force_attack(self):
        """Dimostra attacco brute force"""
        self.print_header("ATTACCO BRUTE FORCE")
        
        # Usa password corta per demo rapida
        target_password = "abc"
        hash_func = self.hash_functions['weak_sum']
        target_hash = hash_func.hash_string(target_password)
        
        print(f"Target: '{target_password}' -> Hash: {target_hash}")
        print(f"Funzione hash: {hash_func.name}")
        
        # Esegue attacco brute force
        manager = AttackManager(hash_func, target_hash)
        
        print(f"\nEseguendo attacco brute force...")
        result = manager.run_brute_force_attack(
            charset="abcdefghijklmnopqrstuvwxyz",
            min_length=1,
            max_length=4,
            verbose=False
        )
        
        if result.success:
            self.print_success(f"Password trovata: '{result.password_found}'")
            print(f"Tentativi: {result.attempts}")
            print(f"Tempo: {result.time_elapsed:.3f} secondi")
        else:
            self.print_error("Password non trovata con brute force")
        
        # Salva risultato
        self.results_manager.save_result(result)
    
    def demo_hybrid_attack(self):
        """Dimostra attacco ibrido"""
        self.print_header("ATTACCO IBRIDO")
        
        # Password con variazione comune
        target_password = "admin123"
        hash_func = self.hash_functions['weak_sum']
        target_hash = hash_func.hash_string(target_password)
        
        print(f"Target: '{target_password}' -> Hash: {target_hash}")
        print(f"Funzione hash: {hash_func.name}")
        
        # Esegue attacco ibrido
        manager = AttackManager(hash_func, target_hash)
        
        wordlist_path = "data/wordlists/common_passwords.txt"
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
    
    def demo_hybrid_attack_sha256(self):
        """Dimostra attacco ibrido"""
        self.print_header("ATTACCO IBRIDO")
        
        # Password con variazione comune
        target_password = "admin123"
        hash_func = self.hash_functions['sha256']
        target_hash = hash_func.hash_string(target_password)
        
        print(f"Target: '{target_password}' -> Hash: {target_hash}")
        print(f"Funzione hash: {hash_func.name}")
        
        # Esegue attacco ibrido
        manager = AttackManager(hash_func, target_hash)
        
        wordlist_path = "data/wordlists/common_passwords.txt"
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

    def demo_performance_comparison(self):
        """Confronta prestazioni delle funzioni hash"""
        self.print_header("CONFRONTO PRESTAZIONI")
        
        print(f"{'Hash Function':<20} {'Hashes/sec':<15} {'Collisions':<12} {'Collision Rate':<15}")
        print("-" * 70)
        
        for name, hash_func in self.hash_functions.items():
            # Misura prestazioni
            perf = HashAnalyzer.measure_hash_performance(hash_func, 10000)
            
            # Analizza collisioni
            collision_analysis = HashAnalyzer.analyze_hash_distribution(hash_func, 1000)
            
            print(f"{name:<20} {perf['hashes_per_second']:<15.0f} "
                  f"{collision_analysis['collisions']:<12} "
                  f"{collision_analysis['collision_rate']:<15.3f}")
    
    def demo_security_analysis(self):
        """Analisi della sicurezza"""
        self.print_header("ANALISI SICUREZZA")
        
        print("Vulnerabilità identificate:")
        print()
        
        # Analisi hash deboli
        print("1. Hash Deboli:")
        weak_hashes = ['weak_sum', 'simple_xor', 'weak_multiply']
        for hash_name in weak_hashes:
            hash_func = self.hash_functions[hash_name]
            print(f"   - {hash_func.name}: Alta probabilità di collisioni")
        
        print()
        print("2. Hash Sicuri:")
        secure_hashes = ['sha256']
        for hash_name in secure_hashes:
            hash_func = self.hash_functions[hash_name]
            print(f"   - {hash_func.name}: Resistente a collisioni")
        
        print()
        print("3. Hash Deprecati:")
        deprecated_hashes = ['md5']
        for hash_name in deprecated_hashes:
            hash_func = self.hash_functions[hash_name]
            print(f"   - {hash_func.name}: Vulnerabile, non usare in produzione")
        
        print()
        print("Raccomandazioni:")
        print("- Usare funzioni hash crittografiche sicure (SHA-256, SHA-3)")
        print("- Implementare salt per le password")
        print("- Utilizzare algoritmi di hashing specifici per password (bcrypt, scrypt)")
        print("- Considerare il tempo di calcolo negli attacchi brute force")
    
    def generate_final_report(self):
        """Genera report finale"""
        self.print_header("REPORT FINALE")
        
        # Genera report delle prestazioni
        report = self.performance_analyzer.generate_performance_report()
        
        if "error" in report:
            self.print_error(report["error"])
            return
        
        print(f"Attacchi eseguiti: {report['total_attacks']}")
        print()
        
        print("Statistiche per tipo di attacco:")
        for attack_type, stats in report['attack_types'].items():
            print(f"\n{attack_type}:")
            print(f"  - Attacchi: {stats['count']}")
            print(f"  - Successi: {stats['successes']}")
            print(f"  - Tasso successo: {stats['success_rate']*100:.1f}%")
            print(f"  - Tempo medio: {stats['avg_time']:.3f}s")
            print(f"  - Tentativi medi: {stats['avg_attempts']:.0f}")
            print(f"  - Velocità: {stats['attempts_per_second']:.0f} tentativi/sec")
        
        self.print_info("Grafici salvati in results/")
    
    def run_full_demo(self):
        """Esegue la demo completa"""
        print(f"{Fore.MAGENTA}")
        print("██╗  ██╗ █████╗ ███████╗██╗  ██╗    ███████╗███████╗ ██████╗")
        print("██║  ██║██╔══██╗██╔════╝██║  ██║    ██╔════╝██╔════╝██╔════╝")
        print("███████║███████║███████╗███████║    ███████╗█████╗  ██║     ")
        print("██╔══██║██╔══██║╚════██║██╔══██║    ╚════██║██╔══╝  ██║     ")
        print("██║  ██║██║  ██║███████║██║  ██║    ███████║███████╗╚██████╗")
        print("╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚══════╝ ╚═════╝")
        print(f"{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Hash Security Analysis Project{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Esame di Sicurezza dell'Informazione{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Marco Crisafulli{Style.RESET_ALL}")
        print()
        
        try:
            # Setup iniziale
            setup_project_structure()
            
            # Esegue le demo
            self.demo_hash_functions()
            time.sleep(2)
            
            self.demo_collision_attacks()
            time.sleep(2)
            
            self.demo_dictionary_attack()
            time.sleep(2)
            
            self.demo_brute_force_attack()
            time.sleep(2)
            
            self.demo_hybrid_attack()
            time.sleep(2)
            
            self.demo_hybrid_attack_sha256()
            time.sleep(2)

            self.demo_performance_comparison()
            time.sleep(2)
            
            self.demo_security_analysis()
            time.sleep(2)
            
            self.generate_final_report()
            
            self.print_header("DEMO COMPLETATA")
            self.print_success("Tutti i test sono stati eseguiti con successo!")
            print(f"Risultati salvati in: {self.results_manager.results_dir}")
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Demo interrotta dall'utente{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}Errore durante la demo: {e}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()

def interactive_menu():
    """Menu interattivo per la demo"""
    demo = HashSecurityDemo()
    
    while True:
        print(f"\n{Fore.CYAN}=== MENU INTERATTIVO ==={Style.RESET_ALL}")
        print("1. Demo completa")
        print("2. Solo funzioni hash")
        print("3. Solo attacchi di collisione")
        print("4. Solo attacco dizionario")
        print("5. Solo attacco brute force")
        print("6. Solo attacco ibrido")
        print("7. Confronto prestazioni")
        print("8. Analisi sicurezza")
        print("9. Report finale")
        print("0. Esci")
        
        try:
            choice = input(f"\n{Fore.YELLOW}Seleziona opzione: {Style.RESET_ALL}")
            
            if choice == '1':
                demo.run_full_demo()
            elif choice == '2':
                demo.demo_hash_functions()
            elif choice == '3':
                demo.demo_collision_attacks()
            elif choice == '4':
                demo.demo_dictionary_attack()
            elif choice == '5':
                demo.demo_brute_force_attack()
            elif choice == '6':
                demo.demo_hybrid_attack_sha256()
            elif choice == '7':
                demo.demo_performance_comparison()
            elif choice == '8':
                demo.demo_security_analysis()
            elif choice == '9':
                demo.generate_final_report()
            elif choice == '0':
                print(f"{Fore.GREEN}Arrivederci!{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Opzione non valida{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Arrivederci!{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}Errore: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        interactive_menu()
    else:
        demo = HashSecurityDemo()
        demo.run_full_demo()