import hashlib
import struct

class HashFunction:
    """Classe base per le funzioni hash"""
    
    def __init__(self, name):
        self.name = name
    
    def hash(self, data):
        """Calcola l'hash dei dati"""
        raise NotImplementedError
    
    def hash_string(self, string):
        """Calcola l'hash di una stringa"""
        return self.hash(string.encode('utf-8'))

class WeakSumHash(HashFunction):
    """Hash vulnerabile basato sulla somma dei caratteri"""
    
    def __init__(self, modulo=65536):
        super().__init__(f"WeakSum-{modulo}")
        self.modulo = modulo
    
    def hash(self, data):
        """Somma semplice dei byte modulo un valore"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return sum(data) % self.modulo
    
    def hash_string(self, string):
        return self.hash(string)

class SimpleXORHash(HashFunction):
    """Hash vulnerabile basato su XOR semplice"""
    
    def __init__(self):
        super().__init__("SimpleXOR")
    
    def hash(self, data):
        """XOR semplice di tutti i byte"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        result = 0
        for byte in data:
            result ^= byte
        return result
    
    def hash_string(self, string):
        return self.hash(string)

class WeakMultiplyHash(HashFunction):
    """Hash vulnerabile basato su moltiplicazione"""
    
    def __init__(self, multiplier=31, modulo=1000000):
        super().__init__(f"WeakMultiply-{multiplier}-{modulo}")
        self.multiplier = multiplier
        self.modulo = modulo
    
    def hash(self, data):
        """Hash basato su moltiplicazione con overflow"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        result = 0
        for byte in data:
            result = (result * self.multiplier + byte) % self.modulo
        return result
    
    def hash_string(self, string):
        return self.hash(string)

class StandardHash(HashFunction):
    """Wrapper per algoritmi hash standard"""
    
    def __init__(self, algorithm='md5'):
        super().__init__(algorithm.upper())
        self.algorithm = algorithm
    
    def hash(self, data):
        """Calcola hash usando algoritmi standard"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if self.algorithm == 'md5':
            return hashlib.md5(data).hexdigest()
        elif self.algorithm == 'sha1':
            return hashlib.sha1(data).hexdigest()
        elif self.algorithm == 'sha256':
            return hashlib.sha256(data).hexdigest()
        else:
            raise ValueError(f"Algoritmo non supportato: {self.algorithm}")
    
    def hash_string(self, string):
        return self.hash(string)

class HashCollisionTester:
    """Classe per testare collisioni negli hash"""
    
    def __init__(self, hash_function):
        self.hash_function = hash_function
        self.hash_table = {}
    
    def find_collision(self, max_attempts=100000):
        """Cerca collisioni testando stringhe casuali"""
        import random
        import string
        
        attempts = 0
        while attempts < max_attempts:
            # Genera stringa casuale
            length = random.randint(1, 10)
            test_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
            
            hash_value = self.hash_function.hash_string(test_string)
            
            if hash_value in self.hash_table:
                # Trovata collisione!
                original = self.hash_table[hash_value]
                if original != test_string:
                    return {
                        'collision_found': True,
                        'string1': original,
                        'string2': test_string,
                        'hash_value': hash_value,
                        'attempts': attempts + 1
                    }
            else:
                self.hash_table[hash_value] = test_string
            
            attempts += 1
        
        return {
            'collision_found': False,
            'attempts': attempts,
            'unique_hashes': len(self.hash_table)
        }

def demonstrate_hash_functions():
    """Dimostra il funzionamento delle diverse funzioni hash"""
    
    test_strings = ["password", "123456", "admin", "test", "hello", "world"]
    
    hash_functions = [
        WeakSumHash(1000),
        WeakSumHash(65536),
        SimpleXORHash(),
        WeakMultiplyHash(),
        StandardHash('md5'),
        StandardHash('sha256')
    ]
    
    print("=== DIMOSTRAZIONE FUNZIONI HASH ===\n")
    
    for hash_func in hash_functions:
        print(f"Algoritmo: {hash_func.name}")
        print("-" * 40)
        
        for test_str in test_strings:
            hash_value = hash_func.hash_string(test_str)
            print(f"'{test_str}' -> {hash_value}")
        
        print()

def test_collision_vulnerability():
    """Testa la vulnerabilità alle collisioni degli hash deboli"""
    
    print("=== TEST VULNERABILITÀ COLLISIONI ===\n")
    
    weak_hashes = [
        WeakSumHash(1000),
        SimpleXORHash(),
        WeakMultiplyHash(31, 10000)
    ]
    
    for hash_func in weak_hashes:
        print(f"Testando {hash_func.name}...")
        collision_tester = HashCollisionTester(hash_func)
        result = collision_tester.find_collision(50000)
        
        if result['collision_found']:
            print(f"✓ COLLISIONE TROVATA dopo {result['attempts']} tentativi!")
            print(f"  '{result['string1']}' e '{result['string2']}'")
            print(f"  entrambe producono hash: {result['hash_value']}")
        else:
            print(f"✗ Nessuna collisione trovata in {result['attempts']} tentativi")
            print(f"  Hash unici generati: {result['unique_hashes']}")
        
        print()

if __name__ == "__main__":
    demonstrate_hash_functions()
    test_collision_vulnerability()
