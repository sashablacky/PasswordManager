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

from security.encryption import BREACH_RESULT_FIELD, record_aad

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

    def __init__(self, db_manager=None, encryption=None):
        """
        Initialize breach detector

        Args:
            db_manager: Optional database manager for storing results
            encryption: EncryptionEngine with the vault key; stored results are
                encrypted with it (without it they are stored in plain text)
        """
        self.db = db_manager
        self.encryption = encryption
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
            Tuple[Optional[bool], int, List[str]]: (breach_found, count, sources).
            breach_found is None when the check could not be done (e.g. no internet).
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
            else:
                # Not in cache, fetch from API
                hashes = self._fetch_hibp_hashes(prefix)

            if hashes is None:
                # Unknown result: do not report the password as safe
                return None, 0, []
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
            return None, 0, []

    def _fetch_hibp_hashes(self, prefix: str) -> Optional[List[str]]:
        """
        Fetch hash suffixes from HIBP API

        Args:
            prefix: First 5 characters of SHA-1 hash

        Returns:
            List of hash suffixes with counts, or None if the API could not be reached
        """
        try:
            url = self.HIBP_API_URL + prefix
            headers = {
                'User-Agent': 'Password-Manager/1.0'
            }

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                return response.text.strip().splitlines()
            else:
                logger.warning(f"HIBP API returned status {response.status_code}")
                return None

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch from HIBP: {e}")
            return None

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

        # HIBP's password range API only reports how often a password was seen,
        # not in which breach. Breach names used to be guessed from words in the
        # password (e.g. "fb" -> Facebook), which showed made-up information.
        if password.lower() in self.COMMON_PASSWORDS:
            sources.append("Common/weak password used in multiple breaches")

        return sources if sources else [f"Seen {count:,} times in known breaches (sources not reported)"]

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
            'check_failed': False,
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

        if breach_found is None:
            risk_assessment['check_failed'] = True
            risk_assessment['issues'].append(
                "Could not check online breach database (no internet connection?)"
            )
        elif breach_found:
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

        if assessment.get('check_failed'):
            recommendations.append("• Breach status unknown: check again when online")

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
                logger.info(f"Checking password {pwd.password_id}")

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

                # Store in database if available (keep the previous result if the check failed)
                if self.db and not assessment.get('check_failed'):
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
        """Store breach check result in database

        With an encryption engine the whole result is stored as one encrypted
        blob bound to the entry: whether a password was found in breaches and
        how risky it is would otherwise be readable without the master password.
        """
        try:
            # Ensure table exists
            self._ensure_breach_table_schema()

            result = {
                'breach_found': bool(assessment.get('breach_found', False)),
                'breach_count': assessment.get('breach_count', 0),
                'risk_level': assessment.get('risk_level', 'low'),
                'sources': assessment.get('sources', []),
                'recommendations': assessment.get('recommendations', []),
            }

            if self.encryption is not None:
                encrypted_result = self.encryption.encrypt(
                    json.dumps(result),
                    record_aad(self.encryption, password_id, BREACH_RESULT_FIELD)
                )
                # The plain columns only get neutral values
                row = (0, 0, 'unknown', None, None, encrypted_result)
            else:
                row = (int(result['breach_found']), result['breach_count'], result['risk_level'],
                       json.dumps(result['sources']), json.dumps(result['recommendations']), None)

            # Replace the previous result for this password
            self.db.execute_query(
                "DELETE FROM breach_checks WHERE password_id = ?",
                (password_id,)
            )
            self.db.execute_query("""
                INSERT INTO breach_checks
                (password_id, user_id, check_date, breach_found, breach_count, risk_level,
                 breach_details, recommendations, encrypted_result)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (password_id, user_id, datetime.now(), *row))

            logger.debug(f"Stored breach result for password {password_id}")

        except Exception as e:
            # Don't raise - this is a non-critical operation
            logger.error(f"Failed to store breach result: {e}")

    @staticmethod
    def _parse_json_list(value) -> list:
        if not value:
            return []
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (TypeError, ValueError):
            return []

    def _load_results(self, where: str, params: Tuple) -> List[Dict[str, Any]]:
        """Stored results as dicts, decrypting encrypted ones; unreadable rows are skipped"""
        table_exists = self.db.fetch_one(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='breach_checks'"
        )
        if not table_exists:
            return []

        results = []
        for row in self.db.fetch_all(f"SELECT * FROM breach_checks WHERE {where}", params):
            encrypted_result = row.get('encrypted_result')
            if encrypted_result:
                if self.encryption is None:
                    continue
                try:
                    data = json.loads(self.encryption.decrypt(
                        encrypted_result,
                        record_aad(self.encryption, row['password_id'], BREACH_RESULT_FIELD)
                    ))
                except Exception as e:
                    logger.warning(f"Could not read stored breach result {row['check_id']}: {e}")
                    continue
                breach_found = bool(data.get('breach_found'))
                breach_count = data.get('breach_count', 0)
                risk_level = data.get('risk_level', 'low')
                sources = data.get('sources', [])
                recommendations = data.get('recommendations', [])
            else:
                breach_found = bool(row['breach_found'])
                breach_count = row['breach_count']
                risk_level = row['risk_level']
                sources = self._parse_json_list(row['breach_details'])
                recommendations = self._parse_json_list(row['recommendations'])

            results.append({
                'check_id': row['check_id'],
                'password_id': row['password_id'],
                'user_id': row['user_id'],
                'check_date': row['check_date'],
                'breach_found': breach_found,
                'breach_count': breach_count,
                'risk_level': risk_level,
                'breach_details': sources,
                'recommendations': recommendations,
            })
        return results

    def get_breach_history(self, password_id: int) -> List[Dict[str, Any]]:
        """Get breach check history for a password"""
        try:
            results = self._load_results("password_id = ?", (password_id,))
            return sorted(results, key=lambda r: str(r['check_date']), reverse=True)

        except Exception as e:
            logger.error(f"Failed to get breach history: {e}")
            return []

    def get_compromised_passwords(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all compromised passwords for a user"""
        try:
            results = [r for r in self._load_results("user_id = ?", (user_id,)) if r['breach_found']]
            results.sort(key=lambda r: str(r['check_date']), reverse=True)
            results.sort(key=lambda r: r['breach_count'] or 0, reverse=True)
            return results

        except Exception as e:
            logger.error(f"Failed to get compromised passwords: {e}")
            return []

    def get_breach_statistics(self, user_id: int) -> Dict[str, Any]:
        """Get breach statistics for a user"""
        empty = {
            'total_checked': 0,
            'compromised': 0,
            'risk_levels': {},
            'last_check': None
        }
        try:
            results = self._load_results("user_id = ?", (user_id,))
            if not results:
                return empty

            risk_levels: Dict[str, int] = {}
            for r in results:
                risk_levels[r['risk_level']] = risk_levels.get(r['risk_level'], 0) + 1

            last_check = max(str(r['check_date']) for r in results)
            try:
                last_check_date = datetime.strptime(last_check, '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                last_check_date = last_check

            return {
                'total_checked': len({r['password_id'] for r in results}),
                'compromised': len({r['password_id'] for r in results if r['breach_found']}),
                'risk_levels': risk_levels,
                'last_check': last_check_date
            }

        except Exception as e:
            logger.error(f"Failed to get breach statistics: {e}")
            return empty


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