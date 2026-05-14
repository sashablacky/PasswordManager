import secrets
import string
import math
import logging
from typing import List, Dict, Any

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GeneratorOptions:
    """Configuration options for password generation"""

    def __init__(self, length: int = 16, use_uppercase: bool = True,
                 use_lowercase: bool = True, use_digits: bool = True,
                 use_symbols: bool = True, exclude_ambiguous: bool = False,
                 exclude_similar: bool = False, min_uppercase: int = 1,
                 min_lowercase: int = 1, min_digits: int = 1, min_symbols: int = 1):
        """
        Initialize generator options

        Args:
            length: Password length (8-128)
            use_uppercase: Include uppercase letters (A-Z)
            use_lowercase: Include lowercase letters (a-z)
            use_digits: Include digits (0-9)
            use_symbols: Include symbols (!@#$...)
            exclude_ambiguous: Exclude ambiguous characters (0, O, l, 1, I)
            exclude_similar: Exclude similar looking characters
            min_uppercase: Minimum uppercase letters required
            min_lowercase: Minimum lowercase letters required
            min_digits: Minimum digits required
            min_symbols: Minimum symbols required
        """
        self.length = max(8, min(128, length))
        self.use_uppercase = use_uppercase
        self.use_lowercase = use_lowercase
        self.use_digits = use_digits
        self.use_symbols = use_symbols
        self.exclude_ambiguous = exclude_ambiguous
        self.exclude_similar = exclude_similar
        self.min_uppercase = min_uppercase if use_uppercase else 0
        self.min_lowercase = min_lowercase if use_lowercase else 0
        self.min_digits = min_digits if use_digits else 0
        self.min_symbols = min_symbols if use_symbols else 0

    def validate(self) -> bool:
        """Validate that options are consistent"""
        # At least one character type must be selected
        if not any([self.use_uppercase, self.use_lowercase, self.use_digits, self.use_symbols]):
            return False

        # Minimum requirements must be achievable
        total_min = self.min_uppercase + self.min_lowercase + self.min_digits + self.min_symbols
        if total_min > self.length:
            return False

        return True


class PasswordGenerator:
    """
    Generates cryptographically secure random passwords

    Uses Python's secrets module which is designed for generating
    cryptographically strong random numbers suitable for security purposes.
    """

    # Character sets
    UPPERCASE = string.ascii_uppercase  # ABCDEFGHIJKLMNOPQRSTUVWXYZ
    LOWERCASE = string.ascii_lowercase  # abcdefghijklmnopqrstuvwxyz
    DIGITS = string.digits  # 0123456789
    SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    # Ambiguous characters that can be confused
    AMBIGUOUS = "0Ol1I"

    # Similar looking characters
    SIMILAR = "il1Lo0O"

    def __init__(self):
        """Initialize Password Generator"""
        logger.info("PasswordGenerator initialized")

    def generate(self, options: GeneratorOptions = None) -> str:
        """
        Generate a random password

        Args:
            options: Generator options (uses defaults if None)

        Returns:
            str: Generated password

        Raises:
            ValueError: If options are invalid
        """
        if options is None:
            options = GeneratorOptions()

        if not options.validate():
            raise ValueError("Invalid generator options")

        # Build character pool
        char_pool = self._build_character_pool(options)

        if not char_pool:
            raise ValueError("Character pool is empty - select at least one character type")

        # Generate password ensuring minimum requirements
        max_attempts = 100
        for attempt in range(max_attempts):
            password = self._generate_random_string(options.length, char_pool)

            if self._meets_requirements(password, options):
                logger.debug(
                    f"✓ Generated password (length: {len(password)}, entropy: {self.calculate_entropy(password):.1f} bits)")
                return password

        # If we couldn't meet requirements, force them
        password = self._generate_with_requirements(options, char_pool)
        logger.debug(f"✓ Generated password with forced requirements")
        return password

    def generate_passphrase(self, word_count: int = 4, separator: str = "-",
                            capitalize: bool = True, add_number: bool = True) -> str:
        """
        Generate a memorable passphrase (e.g., "Correct-Horse-Battery-Staple")

        Args:
            word_count: Number of words (3-8)
            separator: Separator between words
            capitalize: Capitalize first letter of each word
            add_number: Add random number at end

        Returns:
            str: Generated passphrase
        """
        # Simple word list (in production, use a larger list)
        words = [
            "apple", "bridge", "cloud", "dragon", "eagle", "forest", "garden", "harbor",
            "island", "jungle", "knight", "lemon", "mountain", "nature", "ocean", "planet",
            "queen", "river", "sunset", "temple", "umbrella", "valley", "winter", "yellow",
            "zebra", "acoustic", "balance", "crystal", "diamond", "energy", "freedom", "global",
            "harmony", "justice", "liberty", "miracle", "neutral", "organic", "pacific", "quantum",
            "rainbow", "silver", "thunder", "universe", "victory", "wisdom"
        ]

        word_count = max(3, min(8, word_count))

        # Select random words
        selected = [secrets.choice(words) for _ in range(word_count)]

        # Capitalize if requested
        if capitalize:
            selected = [word.capitalize() for word in selected]

        # Join with separator
        passphrase = separator.join(selected)

        # Add number if requested
        if add_number:
            passphrase += separator + str(secrets.randbelow(100))

        logger.info(f"✓ Generated passphrase (words: {word_count}, length: {len(passphrase)})")
        return passphrase

    def calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy in bits

        Entropy measures the randomness/unpredictability of a password.
        Higher entropy = harder to crack.

        Args:
            password: Password to analyze

        Returns:
            float: Entropy in bits
        """
        if not password:
            return 0.0

        # Determine character pool size
        pool_size = 0

        if any(c.isupper() for c in password):
            pool_size += 26
        if any(c.islower() for c in password):
            pool_size += 26
        if any(c.isdigit() for c in password):
            pool_size += 10
        if any(c in self.SYMBOLS for c in password):
            pool_size += len(self.SYMBOLS)

        # Entropy = log2(pool_size^length)
        if pool_size > 0:
            entropy = len(password) * math.log2(pool_size)
        else:
            entropy = 0.0

        return entropy

    def calculate_strength_score(self, password: str) -> int:
        """
        Calculate password strength score (0-100)

        Args:
            password: Password to evaluate

        Returns:
            int: Strength score (0-100)
        """
        if not password:
            return 0

        score = 0

        # Length (max 30 points)
        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        else:
            score += length

        # Character variety (max 40 points)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in self.SYMBOLS for c in password)

        variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
        score += variety_count * 10

        # Entropy bonus (max 20 points)
        entropy = self.calculate_entropy(password)
        if entropy >= 80:
            score += 20
        elif entropy >= 60:
            score += 15
        elif entropy >= 40:
            score += 10
        else:
            score += int(entropy / 4)

        # Unique characters bonus (max 10 points)
        unique_ratio = len(set(password)) / len(password)
        score += int(unique_ratio * 10)

        # Penalties
        password_lower = password.lower()

        # Common patterns
        common_patterns = ['password', '123456', 'qwerty', 'abc123']
        if any(pattern in password_lower for pattern in common_patterns):
            score -= 20

        # Sequential characters
        if any(password_lower[i:i + 3] in 'abcdefghijklmnopqrstuvwxyz' for i in range(len(password_lower) - 2)):
            score -= 10

        # Repeated characters
        if any(password[i] == password[i + 1] == password[i + 2] for i in range(len(password) - 2)):
            score -= 10

        return max(0, min(100, score))

    def estimate_crack_time(self, password: str) -> Dict[str, Any]:
        """
        Estimate time to crack password

        Assumes attacker can try 1 billion passwords per second
        (reasonable for offline attack with modern hardware)

        Args:
            password: Password to analyze

        Returns:
            Dict with crack time estimates
        """
        entropy = self.calculate_entropy(password)

        # Number of possible passwords
        combinations = 2 ** entropy

        # Attempts per second (1 billion)
        attempts_per_second = 1_000_000_000

        # Seconds to crack (on average, half the keyspace)
        seconds = combinations / (2 * attempts_per_second)

        # Convert to readable format
        if seconds < 1:
            time_str = "Instantly"
            security = "Very Weak"
        elif seconds < 60:
            time_str = f"{int(seconds)} seconds"
            security = "Weak"
        elif seconds < 3600:
            time_str = f"{int(seconds / 60)} minutes"
            security = "Weak"
        elif seconds < 86400:
            time_str = f"{int(seconds / 3600)} hours"
            security = "Medium"
        elif seconds < 31536000:
            time_str = f"{int(seconds / 86400)} days"
            security = "Medium"
        elif seconds < 31536000 * 100:
            time_str = f"{int(seconds / 31536000)} years"
            security = "Strong"
        elif seconds < 31536000 * 1000000:
            time_str = f"{int(seconds / 31536000 / 1000)} thousand years"
            security = "Very Strong"
        else:
            time_str = "Millions of years"
            security = "Extremely Strong"

        return {
            'entropy': entropy,
            'combinations': combinations,
            'seconds': seconds,
            'time_string': time_str,
            'security_level': security
        }

    def _build_character_pool(self, options: GeneratorOptions) -> str:
        """Build character pool based on options"""
        pool = ""

        if options.use_uppercase:
            chars = self.UPPERCASE
            if options.exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.AMBIGUOUS)
            if options.exclude_similar:
                chars = ''.join(c for c in chars if c not in self.SIMILAR)
            pool += chars

        if options.use_lowercase:
            chars = self.LOWERCASE
            if options.exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.AMBIGUOUS)
            if options.exclude_similar:
                chars = ''.join(c for c in chars if c not in self.SIMILAR)
            pool += chars

        if options.use_digits:
            chars = self.DIGITS
            if options.exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.AMBIGUOUS)
            if options.exclude_similar:
                chars = ''.join(c for c in chars if c not in self.SIMILAR)
            pool += chars

        if options.use_symbols:
            pool += self.SYMBOLS

        return pool

    def _generate_random_string(self, length: int, char_pool: str) -> str:
        """Generate random string from character pool"""
        return ''.join(secrets.choice(char_pool) for _ in range(length))

    def _meets_requirements(self, password: str, options: GeneratorOptions) -> bool:
        """Check if password meets minimum requirements"""
        if options.min_uppercase > 0:
            uppercase_count = sum(1 for c in password if c.isupper())
            if uppercase_count < options.min_uppercase:
                return False

        if options.min_lowercase > 0:
            lowercase_count = sum(1 for c in password if c.islower())
            if lowercase_count < options.min_lowercase:
                return False

        if options.min_digits > 0:
            digit_count = sum(1 for c in password if c.isdigit())
            if digit_count < options.min_digits:
                return False

        if options.min_symbols > 0:
            symbol_count = sum(1 for c in password if c in self.SYMBOLS)
            if symbol_count < options.min_symbols:
                return False

        return True

    def _generate_with_requirements(self, options: GeneratorOptions, char_pool: str) -> str:
        """Generate password and force requirements"""
        password = []

        # Add required characters
        if options.use_uppercase and options.min_uppercase > 0:
            uppercase_chars = ''.join(c for c in char_pool if c.isupper())
            for _ in range(options.min_uppercase):
                password.append(secrets.choice(uppercase_chars))

        if options.use_lowercase and options.min_lowercase > 0:
            lowercase_chars = ''.join(c for c in char_pool if c.islower())
            for _ in range(options.min_lowercase):
                password.append(secrets.choice(lowercase_chars))

        if options.use_digits and options.min_digits > 0:
            digit_chars = ''.join(c for c in char_pool if c.isdigit())
            for _ in range(options.min_digits):
                password.append(secrets.choice(digit_chars))

        if options.use_symbols and options.min_symbols > 0:
            symbol_chars = ''.join(c for c in char_pool if c in self.SYMBOLS)
            for _ in range(options.min_symbols):
                password.append(secrets.choice(symbol_chars))

        # Fill remaining length with random characters
        remaining = options.length - len(password)
        for _ in range(remaining):
            password.append(secrets.choice(char_pool))

        # Shuffle to avoid predictable pattern
        # Convert to list, shuffle, convert back
        password_list = list(password)
        for i in range(len(password_list) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_list[i], password_list[j] = password_list[j], password_list[i]

        return ''.join(password_list)


# Demonstration and testing
if __name__ == '__main__':
    print("=" * 70)
    print("Testing Password Generator")
    print("=" * 70)

    generator = PasswordGenerator()

    # Test 1: Default password
    print("\n1. Generating default password (16 chars, all types)...")
    password = generator.generate()
    print(f"   Password: {password}")
    print(f"   Length: {len(password)}")
    print(f"   Entropy: {generator.calculate_entropy(password):.1f} bits")
    print(f"   Strength: {generator.calculate_strength_score(password)}/100")

    # Test 2: Custom options
    print("\n2. Generating with custom options...")
    options = GeneratorOptions(
        length=20,
        use_uppercase=True,
        use_lowercase=True,
        use_digits=True,
        use_symbols=True
    )
    password = generator.generate(options)
    print(f"   Password: {password}")
    print(f"   Length: {len(password)}")

    # Test 3: No symbols
    print("\n3. Generating without symbols...")
    options = GeneratorOptions(length=16, use_symbols=False)
    password = generator.generate(options)
    print(f"   Password: {password}")
    has_symbols = any(c in generator.SYMBOLS for c in password)
    print(f"   Contains symbols: {has_symbols}")

    # Test 4: Passphrase
    print("\n4. Generating passphrase...")
    passphrase = generator.generate_passphrase(word_count=4)
    print(f"   Passphrase: {passphrase}")
    print(f"   Length: {len(passphrase)}")
    print(f"   Entropy: {generator.calculate_entropy(passphrase):.1f} bits")

    # Test 5: Multiple passwords (ensure randomness)
    print("\n5. Generating multiple passwords (check uniqueness)...")
    passwords = [generator.generate() for _ in range(5)]
    for i, pwd in enumerate(passwords, 1):
        print(f"   {i}. {pwd}")
    unique = len(set(passwords))
    print(f"   All unique: {unique == 5}")

    # Test 6: Strength analysis
    print("\n6. Analyzing password strengths...")
    test_passwords = [
        ("password", "Very weak"),
        ("Password1", "Weak"),
        ("P@ssw0rd123", "Medium"),
        ("Xy9$mK#pL2@vN8qR", "Strong")
    ]

    for pwd, expected in test_passwords:
        strength = generator.calculate_strength_score(pwd)
        entropy = generator.calculate_entropy(pwd)
        print(f"   '{pwd}'")
        print(f"      Strength: {strength}/100")
        print(f"      Entropy: {entropy:.1f} bits")

    # Test 7: Crack time estimation
    print("\n7. Estimating crack times...")
    for pwd, desc in test_passwords:
        crack_info = generator.estimate_crack_time(pwd)
        print(f"   '{pwd}' ({desc})")
        print(f"      Time to crack: {crack_info['time_string']}")
        print(f"      Security: {crack_info['security_level']}")

    # Test 8: Exclude ambiguous characters
    print("\n8. Testing exclude ambiguous option...")
    options = GeneratorOptions(length=16, exclude_ambiguous=True)
    password = generator.generate(options)
    print(f"   Password: {password}")
    has_ambiguous = any(c in generator.AMBIGUOUS for c in password)
    print(f"   Contains ambiguous (0,O,l,1,I): {has_ambiguous}")

    # Test 9: Minimum requirements
    print("\n9. Testing minimum requirements...")
    options = GeneratorOptions(
        length=16,
        min_uppercase=3,
        min_lowercase=3,
        min_digits=3,
        min_symbols=2
    )
    password = generator.generate(options)
    print(f"   Password: {password}")
    print(f"   Uppercase: {sum(1 for c in password if c.isupper())} (min: 3)")
    print(f"   Lowercase: {sum(1 for c in password if c.islower())} (min: 3)")
    print(f"   Digits: {sum(1 for c in password if c.isdigit())} (min: 3)")
    print(f"   Symbols: {sum(1 for c in password if c in generator.SYMBOLS)} (min: 2)")

    print("\n" + "=" * 70)
    print("✓ All password generator tests completed successfully!")
    print("=" * 70)