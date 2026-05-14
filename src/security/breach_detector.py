"""
Breach Detection Module
Checks passwords against known data breaches using HaveIBeenPwned API
and performs local breach analysis
"""

import hashlib
import requests
import logging
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class BreachResult:
    """Data class for breach check results"""
    password_id: int
    password_hash: str
    breach_count: int
    breach_found: bool
    check_date: datetime
    sources: List[str]
    compromised: bool
    risk_level: str  # 'low', 'medium', 'high', 'critical'
    recommendations: List[str]


class BreachDetector:
    """
    Detects if passwords have been exposed in data breaches
    Uses HaveIBeenPwned API v3 (k-anonymity model)
    """

    # API endpoint for HIBP (k-anonymity)
    HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

    # Common weak passwords to check locally
    COMMON_PASSWORDS = [
        "password", "123456", "12345678", "1234", "qwerty", "abc123",
        "password1", "admin", "letmein", "welcome", "monkey", "dragon",
        "baseball", "football", "master", "superman", "iloveyou", "trustno1",
        "shadow", "sunshine", "princess", "12345", "123456789", "1234567",
        "qwerty123", "passw0rd", "password123", "admin123", "login"
    ]

    # Breach sources for information
    BREACH_SOURCES = {
        "linkedin": "2016 LinkedIn breach (164M accounts)",
        "facebook": "2019 Facebook breach (530M accounts)",
        "adobe": "2013 Adobe breach (153M accounts)",
        "yahoo": "2013-2014 Yahoo breaches (3B accounts)",
        "equifax": "2017 Equifax breach (147M accounts)",
        "marriott": "2018 Marriott breach (500M accounts)",
        "myspace": "2016 MySpace breach (360M accounts)",
        "tumblr": "2013 Tumblr breach (65M accounts)",
        "dropbox": "2012 Dropbox breach (68M accounts)",
        "lastfm": "2012 Last.fm breach (43M accounts)",
        "linkedin_2021": "2021 LinkedIn breach (700M accounts)",
        "facebook_2021": "2021 Facebook leak (533M accounts)"
    }

    def __init__(self, db_manager=None):
        """
        Initialize breach detector

        Args:
            db_manager: Optional database manager for storing results
        """
        self.db = db_manager
        self.cache = {}  # Cache for API results
        self.cache_expiry = timedelta(hours=24)  # Cache for 24 hours
        self.last_check = {}

        logger.info("BreachDetector initialized")

    def check_password_hibp(self, password: str) -> Tuple[bool, int, List[str]]:
        """
        Check if password has been exposed using HIBP API

        Args:
            password: Password to check

        Returns:
            Tuple[bool, int, List[str]]: (breach_found, count, sources)
        """
        try:
            # Hash the password with SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            # Check cache first
            if prefix in self.cache:
                cache_time, cache_data = self.cache[prefix]
                if datetime.now() - cache_time < self.cache_expiry:
                    hashes = cache_data
                else:
                    # Cache expired, fetch again
                    hashes = self._fetch_hibp_hashes(prefix)
                    self.cache[prefix] = (datetime.now(), hashes)
            else:
                # Not in cache, fetch from API
                hashes = self._fetch_hibp_hashes(prefix)
                self.cache[prefix] = (datetime.now(), hashes)

            # Check if our hash suffix is in the results
            for line in hashes:
                if line.startswith(suffix):
                    count = int(line.split(':')[1])
                    sources = self._identify_breach_sources(password, count)
                    return True, count, sources

            return False, 0, []

        except Exception as e:
            logger.error(f"HIBP check failed: {e}")
            return False, 0, []

    def _fetch_hibp_hashes(self, prefix: str) -> List[str]:
        """
        Fetch hash suffixes from HIBP API

        Args:
            prefix: First 5 characters of SHA-1 hash

        Returns:
            List of hash suffixes with counts
        """
        try:
            url = self.HIBP_API_URL + prefix
            headers = {
                'User-Agent': 'Password-Manager/1.0'
            }

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                return response.text.strip().split('\r\n')
            else:
                logger.warning(f"HIBP API returned status {response.status_code}")
                return []

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch from HIBP: {e}")
            return []

    def _identify_breach_sources(self, password: str, count: int) -> List[str]:
        """
        Identify likely breach sources based on password patterns

        Args:
            password: The password
            count: Breach count from HIBP

        Returns:
            List of breach source descriptions
        """
        sources = []

        # Add general sources based on count
        if count > 1000000000:
            sources.append("Multiple major breaches (1B+ occurrences)")
        elif count > 100000000:
            sources.append("Major breaches (100M+ occurrences)")
        elif count > 10000000:
            sources.append("Significant breaches (10M+ occurrences)")
        elif count > 1000000:
            sources.append("Common breaches (1M+ occurrences)")

        # Add specific sources based on password patterns
        password_lower = password.lower()

        if re.search(r'(linkedin|linked in)', password_lower, re.IGNORECASE):
            sources.append(self.BREACH_SOURCES["linkedin"])

        if re.search(r'(facebook|fb)', password_lower, re.IGNORECASE):
            sources.append(self.BREACH_SOURCES["facebook"])

        if re.search(r'(adobe|photoshop)', password_lower, re.IGNORECASE):
            sources.append(self.BREACH_SOURCES["adobe"])

        if re.search(r'(yahoo|ymail)', password_lower, re.IGNORECASE):
            sources.append(self.BREACH_SOURCES["yahoo"])

        if password in self.COMMON_PASSWORDS:
            sources.append("Common/weak password used in multiple breaches")

        return sources if sources else ["Unknown breach source"]

    def analyze_password_risk(self, password: str) -> Dict[str, Any]:
        """
        Perform comprehensive risk analysis on a password

        Args:
            password: Password to analyze

        Returns:
            Dict with risk assessment
        """
        risk_assessment = {
            'breach_found': False,
            'breach_count': 0,
            'risk_level': 'low',
            'issues': [],
            'recommendations': [],
            'local_checks': {}
        }

        # Check local weaknesses
        local_checks = self._check_local_weaknesses(password)
        risk_assessment['local_checks'] = local_checks

        if local_checks['is_common']:
            risk_assessment['issues'].append("Password is too common")
            risk_assessment['risk_level'] = 'high'

        if local_checks['is_dictionary_word']:
            risk_assessment['issues'].append("Contains dictionary words")
            if risk_assessment['risk_level'] == 'low':
                risk_assessment['risk_level'] = 'medium'

        if local_checks['is_pattern']:
            risk_assessment['issues'].append("Contains predictable patterns")
            if risk_assessment['risk_level'] == 'low':
                risk_assessment['risk_level'] = 'medium'

        # Check HIBP
        breach_found, count, sources = self.check_password_hibp(password)

        if breach_found:
            risk_assessment['breach_found'] = True
            risk_assessment['breach_count'] = count
            risk_assessment['sources'] = sources

            if count > 10000000:
                risk_assessment['risk_level'] = 'critical'
                risk_assessment['issues'].append(f"Password found in {count:,} breaches")
            elif count > 1000000:
                risk_assessment['risk_level'] = 'high'
                risk_assessment['issues'].append(f"Password found in {count:,} breaches")
            elif count > 1000:
                risk_assessment['risk_level'] = 'medium'
                risk_assessment['issues'].append(f"Password found in {count:,} breaches")
            else:
                risk_assessment['issues'].append(f"Password found in {count} breaches")

        # Generate recommendations
        risk_assessment['recommendations'] = self._generate_recommendations(risk_assessment)

        return risk_assessment

    def _check_local_weaknesses(self, password: str) -> Dict[str, bool]:
        """
        Check for local password weaknesses

        Args:
            password: Password to check

        Returns:
            Dict with weakness flags
        """
        password_lower = password.lower()

        return {
            'is_common': password_lower in self.COMMON_PASSWORDS,
            'is_dictionary_word': self._is_dictionary_word(password_lower),
            'is_pattern': self._has_pattern(password),
            'is_short': len(password) < 8,
            'has_no_numbers': not any(c.isdigit() for c in password),
            'has_no_symbols': not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password),
            'has_no_uppercase': not any(c.isupper() for c in password),
            'has_repeated_chars': self._has_repeated_chars(password)
        }

    def _is_dictionary_word(self, word: str) -> bool:
        """Check if word is in common dictionary"""
        # Simple dictionary of common words (in production, use a proper word list)
        common_words = [
            'password', 'admin', 'user', 'login', 'welcome', 'secret',
            'master', 'key', 'access', 'secure', 'private', 'protected',
            'qwerty', 'asdf', 'zxcv', 'test', 'demo', 'sample',
            'summer', 'winter', 'spring', 'fall', 'autumn',
            'monday', 'tuesday', 'wednesday', 'thursday', 'friday',
            'january', 'february', 'march', 'april', 'may', 'june',
            'july', 'august', 'september', 'october', 'november', 'december'
        ]
        return word in common_words

    def _has_pattern(self, password: str) -> bool:
        """Check for predictable patterns"""
        password_lower = password.lower()

        # Check for sequential characters
        sequences = ['123', '234', '345', '456', '567', '678', '789',
                     'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi',
                     'qwe', 'wer', 'ert', 'rty', 'tyu', 'yui', 'uio']

        for seq in sequences:
            if seq in password_lower:
                return True

        # Check for repeated patterns
        if any(password[i] == password[i + 1] == password[i + 2] for i in range(len(password) - 2)):
            return True

        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', 'qwertyuiop', 'asdfghjkl']
        for pattern in keyboard_patterns:
            if pattern in password_lower:
                return True

        return False

    def _has_repeated_chars(self, password: str) -> bool:
        """Check for repeated characters"""
        for i in range(len(password) - 1):
            if password[i] == password[i + 1]:
                return True
        return False

    def _generate_recommendations(self, assessment: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on assessment"""
        recommendations = []

        if assessment['breach_found']:
            recommendations.append("⚠️ IMMEDIATE ACTION: Password found in data breaches!")
            recommendations.append("   • Change this password immediately")
            recommendations.append("   • Use a unique password for each account")
            recommendations.append("   • Enable two-factor authentication if available")

        if assessment['local_checks']['is_common']:
            recommendations.append("• Avoid using common passwords")

        if assessment['local_checks']['is_short']:
            recommendations.append("• Use at least 8 characters (longer is better)")

        if assessment['local_checks']['has_no_numbers']:
            recommendations.append("• Add numbers to increase complexity")

        if assessment['local_checks']['has_no_symbols']:
            recommendations.append("• Add special characters (!@#$%^&*)")

        if assessment['local_checks']['has_no_uppercase']:
            recommendations.append("• Include uppercase letters")

        if assessment['local_checks']['has_repeated_chars']:
            recommendations.append("• Avoid repeated characters")

        if not recommendations:
            recommendations.append("✓ Password appears secure")

        return recommendations

    def check_all_passwords(self, user_id: int, password_manager) -> List[BreachResult]:
        """
        Check all passwords for a user against breaches

        Args:
            user_id: User ID
            password_manager: PasswordManager instance

        Returns:
            List of BreachResult objects
        """
        results = []

        try:
            passwords = password_manager.get_all_passwords(user_id)

            for pwd in passwords:
                logger.info(f"Checking password: {pwd.title}")

                # Analyze the password
                assessment = self.analyze_password_risk(pwd.password)

                # Create result
                result = BreachResult(
                    password_id=pwd.password_id,
                    password_hash=hashlib.sha256(pwd.password.encode()).hexdigest()[:8],
                    breach_count=assessment.get('breach_count', 0),
                    breach_found=assessment['breach_found'],
                    check_date=datetime.now(),
                    sources=assessment.get('sources', []),
                    compromised=assessment['breach_found'] or assessment['risk_level'] in ['high', 'critical'],
                    risk_level=assessment['risk_level'],
                    recommendations=assessment['recommendations']
                )

                results.append(result)

                # Store in database if available
                if self.db:
                    self._store_breach_result(user_id, pwd.password_id, assessment)

            logger.info(f"Checked {len(passwords)} passwords for user {user_id}")

        except Exception as e:
            logger.error(f"Failed to check all passwords: {e}")

        return results

    def _ensure_breach_table_schema(self):
        """Ensure breach_checks table has the correct schema"""
        try:
            # Create table if it doesn't exist
            self.db.execute_query("""
                CREATE TABLE IF NOT EXISTS breach_checks (
                    check_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    check_date TIMESTAMP NOT NULL,
                    breach_found INTEGER DEFAULT 0,
                    breach_count INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'low',
                    breach_details TEXT,
                    recommendations TEXT,
                    FOREIGN KEY (password_id) REFERENCES passwords(password_id) ON DELETE CASCADE
                )
            """)
            logger.info("Ensured breach_checks table exists with correct schema")

        except Exception as e:
            logger.error(f"Failed to ensure breach table schema: {e}")

    def _store_breach_result(self, user_id: int, password_id: int, assessment: Dict[str, Any]) -> None:
        """Store breach check result in database"""
        try:
            # Ensure table exists
            self._ensure_breach_table_schema()

            # Delete old results for this password
            self.db.execute_query(
                "DELETE FROM breach_checks WHERE password_id = ?",
                (password_id,)
            )

            # Prepare data
            now = datetime.now()
            breach_found = 1 if assessment.get('breach_found', False) else 0
            breach_count = assessment.get('breach_count', 0)
            risk_level = assessment.get('risk_level', 'low')
            sources = json.dumps(assessment.get('sources', []))
            recommendations = json.dumps(assessment.get('recommendations', []))

            # Insert new result
            self.db.execute_query("""
                INSERT INTO breach_checks 
                (password_id, user_id, check_date, breach_found, breach_count, risk_level, breach_details, recommendations)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                password_id,
                user_id,
                now,
                breach_found,
                breach_count,
                risk_level,
                sources,
                recommendations
            ))

            logger.debug(f"Stored breach result for password {password_id}")

        except Exception as e:
            logger.error(f"Failed to store breach result: {e}")
            # Print more details for debugging
            import traceback
            traceback.print_exc()
            # Don't raise - this is a non-critical operation

    def get_breach_history(self, password_id: int) -> List[Dict[str, Any]]:
        """Get breach check history for a password"""
        try:
            results = self.db.fetch_all(
                "SELECT * FROM breach_checks WHERE password_id = ? ORDER BY check_date DESC",
                (password_id,)
            )

            for result in results:
                if result['breach_details']:
                    result['breach_details'] = json.loads(result['breach_details'])
                if result['recommendations']:
                    result['recommendations'] = json.loads(result['recommendations'])

            return results

        except Exception as e:
            logger.error(f"Failed to get breach history: {e}")
            return []

    def get_compromised_passwords(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all compromised passwords for a user"""
        try:
            # Check if breach_checks table exists
            table_exists = self.db.fetch_one(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='breach_checks'"
            )

            if not table_exists:
                return []

            results = self.db.fetch_all("""
                SELECT bc.*, p.encrypted_username
                FROM breach_checks bc
                JOIN passwords p ON bc.password_id = p.password_id
                WHERE bc.user_id = ? AND bc.breach_found = 1
                ORDER BY bc.breach_count DESC, bc.check_date DESC
            """, (user_id,))

            # Parse JSON fields
            for result in results:
                if result['breach_details']:
                    try:
                        result['breach_details'] = json.loads(result['breach_details'])
                    except:
                        result['breach_details'] = []
                else:
                    result['breach_details'] = []

                if result['recommendations']:
                    try:
                        result['recommendations'] = json.loads(result['recommendations'])
                    except:
                        result['recommendations'] = []
                else:
                    result['recommendations'] = []

            return results

        except Exception as e:
            logger.error(f"Failed to get compromised passwords: {e}")
            return []

    def get_breach_statistics(self, user_id: int) -> Dict[str, Any]:
        """Get breach statistics for a user"""
        try:
            # Check if table exists and has user_id column
            table_exists = self.db.fetch_one(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='breach_checks'"
            )

            if not table_exists:
                return {
                    'total_checked': 0,
                    'compromised': 0,
                    'risk_levels': {},
                    'last_check': None
                }

            # Check if user_id column exists
            columns = self.db.fetch_all("PRAGMA table_info(breach_checks)")
            column_names = [col['name'] for col in columns]

            if 'user_id' not in column_names:
                # Old schema - can't get accurate stats
                return {
                    'total_checked': 0,
                    'compromised': 0,
                    'risk_levels': {},
                    'last_check': None
                }

            total = self.db.fetch_one("""
                SELECT COUNT(DISTINCT password_id) as count
                FROM breach_checks
                WHERE user_id = ?
            """, (user_id,)) or {'count': 0}

            compromised = self.db.fetch_one("""
                SELECT COUNT(DISTINCT password_id) as count
                FROM breach_checks
                WHERE user_id = ? AND breach_found = 1
            """, (user_id,)) or {'count': 0}

            risk_levels = self.db.fetch_all("""
                SELECT risk_level, COUNT(*) as count
                FROM breach_checks
                WHERE user_id = ?
                GROUP BY risk_level
            """, (user_id,))

            last_check = self.db.fetch_one("""
                SELECT MAX(check_date) as last_check
                FROM breach_checks
                WHERE user_id = ?
            """, (user_id,))

            last_check_date = None
            if last_check and last_check['last_check']:
                try:
                    if isinstance(last_check['last_check'], str):
                        last_check_date = datetime.strptime(last_check['last_check'], '%Y-%m-%d %H:%M:%S.%f')
                    else:
                        last_check_date = last_check['last_check']
                except:
                    last_check_date = last_check['last_check']

            return {
                'total_checked': total['count'],
                'compromised': compromised['count'],
                'risk_levels': {r['risk_level']: r['count'] for r in risk_levels},
                'last_check': last_check_date
            }

        except Exception as e:
            logger.error(f"Failed to get breach statistics: {e}")
            return {
                'total_checked': 0,
                'compromised': 0,
                'risk_levels': {},
                'last_check': None
            }


# Example usage
if __name__ == '__main__':
    detector = BreachDetector()

    # Test passwords
    test_passwords = [
        "password123",
        "CorrectHorseBatteryStaple",
        "P@ssw0rd2024!",
        "123456",
        "MySecureP@ssw0rd2024!"
    ]

    print("=" * 70)
    print("Breach Detection Test")
    print("=" * 70)

    for pwd in test_passwords:
        print(f"\nChecking: {pwd}")
        print("-" * 40)

        result = detector.analyze_password_risk(pwd)

        print(f"Risk Level: {result['risk_level'].upper()}")
        print(f"Breach Found: {'YES' if result['breach_found'] else 'NO'}")

        if result['breach_found']:
            print(f"Breach Count: {result['breach_count']:,}")
            if 'sources' in result:
                print("Sources:")
                for source in result['sources']:
                    print(f"  • {source}")

        if result['issues']:
            print("Issues:")
            for issue in result['issues']:
                print(f"  • {issue}")

        print("Recommendations:")
        for rec in result['recommendations']:
            print(f"  {rec}")