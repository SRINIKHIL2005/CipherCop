import sqlite3
import os
import hashlib
import secrets
from datetime import datetime, timedelta


class CipherCopDB:
    def __init__(self, db_path="ciphercop.db"):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login TEXT,
                is_active INTEGER DEFAULT 1,
                extension_id TEXT,
                settings TEXT DEFAULT '{}',
                total_scans INTEGER DEFAULT 0,
                threats_detected INTEGER DEFAULT 0
            )
        ''')

        # User sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # User scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                verdict TEXT,
                risk_score INTEGER,
                threat_sources TEXT,
                timestamp TEXT NOT NULL,
                ml_confidence REAL,
                heuristic_score REAL,
                safe_browsing_result TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # User analytics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                scans_count INTEGER DEFAULT 0,
                threats_blocked INTEGER DEFAULT 0,
                websites_scanned INTEGER DEFAULT 0,
                apks_scanned INTEGER DEFAULT 0,
                extension_warnings INTEGER DEFAULT 0,
                average_risk_score REAL DEFAULT 0,
                most_common_threat TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, date)
            )
        ''')

        # Threat logs table (existing, enhanced)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                timestamp TEXT NOT NULL,
                url TEXT NOT NULL,
                reason TEXT,
                action TEXT,
                user_agent TEXT,
                verdict TEXT,
                risk_score INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Blacklist table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                reason TEXT,
                added_date TEXT NOT NULL,
                added_by TEXT DEFAULT 'system'
            )
        ''')

        # Whitelist table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                reason TEXT,
                added_date TEXT NOT NULL,
                added_by TEXT DEFAULT 'user'
            )
        ''')

        # User reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                url TEXT NOT NULL,
                report_reason TEXT,
                timestamp TEXT NOT NULL,
                user_agent TEXT,
                status TEXT DEFAULT 'pending',
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Chrome extension browsing history
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS extension_browsing_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                title TEXT,
                visit_time TEXT NOT NULL,
                visit_count INTEGER DEFAULT 1,
                is_threat INTEGER DEFAULT 0,
                threat_type TEXT,
                risk_score INTEGER DEFAULT 0,
                blocked INTEGER DEFAULT 0,
                warning_shown INTEGER DEFAULT 0,
                user_action TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Extension threat detections
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS extension_threat_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                detection_method TEXT,
                confidence_score REAL,
                detected_at TEXT NOT NULL,
                action_taken TEXT,
                user_proceeded INTEGER DEFAULT 0,
                threat_details TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Extension settings and preferences
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS extension_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                setting_name TEXT NOT NULL,
                setting_value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, setting_name)
            )
        ''')

        # Extension usage statistics
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS extension_usage_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                pages_visited INTEGER DEFAULT 0,
                threats_detected INTEGER DEFAULT 0,
                threats_blocked INTEGER DEFAULT 0,
                warnings_shown INTEGER DEFAULT 0,
                user_overrides INTEGER DEFAULT 0,
                total_scan_time REAL DEFAULT 0,
                average_page_risk REAL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, date)
            )
        ''')

        conn.commit()
        conn.close()
        print("[INFO] Database initialized successfully")
        # Run lightweight migrations for older DBs
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Ensure user_reports has user_id column
            cursor.execute("PRAGMA table_info(user_reports)")
            cols = [r[1] for r in cursor.fetchall()]
            if 'user_id' not in cols:
                print('[INFO] Migrating: adding user_id to user_reports')
                cursor.execute('ALTER TABLE user_reports ADD COLUMN user_id INTEGER')

            # Ensure extension_browsing_history has user_id and user_action
            cursor.execute("PRAGMA table_info(extension_browsing_history)")
            cols = [r[1] for r in cursor.fetchall()]
            if 'user_id' not in cols:
                print('[INFO] Migrating: adding user_id to extension_browsing_history')
                cursor.execute('ALTER TABLE extension_browsing_history ADD COLUMN user_id INTEGER')
            if 'user_action' not in cols:
                print('[INFO] Migrating: adding user_action to extension_browsing_history')
                cursor.execute("ALTER TABLE extension_browsing_history ADD COLUMN user_action TEXT")

            conn.commit()
        except Exception as e:
            print('[WARN] Migration error:', e)
        finally:
            try: conn.close()
            except: pass

    def hash_password(self, password, salt=None):
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return password_hash.hex(), salt

    def create_user(self, name, email, password):
        """Create a new user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Check if user already exists by email
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                conn.close()
                # Indicate duplicate email
                return {'exists': 'email'}

            # Check if username already exists
            cursor.execute('SELECT id FROM users WHERE name = ?', (name,))
            if cursor.fetchone():
                conn.close()
                # Indicate duplicate username
                return {'exists': 'username'}

            # Hash password
            password_hash, salt = self.hash_password(password)

            # Insert user
            cursor.execute('''
                INSERT INTO users (name, email, password_hash, salt, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, email, password_hash, salt, datetime.now().isoformat()))

            user_id = cursor.lastrowid
            conn.commit()
            conn.close()

            # Return integer user_id on success (caller expects an id)
            return user_id
        except Exception as e:
            conn.close()
            # Return None on failure to create user
            return None

    def authenticate_user(self, login, password):
        """Authenticate user by email or username. Returns a dict with success and user info on success.

        Note: this function does NOT create a session. Callers should call create_session(user_id).
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Allow login by email OR username
            cursor.execute('SELECT id, name, email, password_hash, salt, created_at FROM users WHERE (email = ? OR name = ?) AND is_active = 1', (login, login))
            row = cursor.fetchone()

            if not row:
                conn.close()
                return {'success': False, 'error': 'Invalid credentials'}

            user_id, name, email, stored_hash, salt, created_at = row

            # Verify password
            password_hash, _ = self.hash_password(password, salt)
            if password_hash != stored_hash:
                conn.close()
                return {'success': False, 'error': 'Invalid credentials'}

            # Update last login timestamp
            try:
                cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now().isoformat(), user_id))
                conn.commit()
            except Exception:
                # non-fatal: ignore update failures
                pass

            conn.close()

            return {
                'success': True,
                'user': {
                    'id': user_id,
                    'username': name,
                    'email': email,
                    'created_at': created_at
                }
            }
        except Exception as e:
            conn.close()
            return {'success': False, 'error': str(e)}

    def validate_session(self, session_token):
        """Validate user session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT u.id, u.name, u.email, s.expires_at
                FROM users u
                JOIN user_sessions s ON u.id = s.user_id
                WHERE s.session_token = ? AND s.is_active = 1 AND u.is_active = 1
            ''', (session_token,))

            result = cursor.fetchone()
            if not result:
                conn.close()
                return None

            user_id, name, email, expires_at = result
            
            # Check if session expired
            if datetime.fromisoformat(expires_at) < datetime.now():
                # Deactivate expired session
                cursor.execute('UPDATE user_sessions SET is_active = 0 WHERE session_token = ?', (session_token,))
                conn.commit()
                conn.close()
                return None

            conn.close()
            return {'id': user_id, 'username': name, 'email': email}
        except Exception:
            conn.close()
            return None

    def create_session(self, user_id):
        """Create a new session for a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Generate session token
            session_token = secrets.token_urlsafe(32)
            expires_at = (datetime.now() + timedelta(days=7)).isoformat()
            
            # Insert session
            cursor.execute('''
                INSERT INTO user_sessions (user_id, session_token, created_at, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (user_id, session_token, datetime.now().isoformat(), expires_at))
            
            conn.commit()
            conn.close()
            return session_token
        except Exception as e:
            conn.close()
            raise e

    def log_user_scan(self, user_id, url, scan_type, verdict=None, risk_score=None, threat_sources=None, ml_confidence=None, heuristic_score=None, safe_browsing_result=None):
        """Log user scan activity"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT INTO user_scan_history (user_id, url, scan_type, verdict, risk_score, threat_sources, timestamp, ml_confidence, heuristic_score, safe_browsing_result)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, url, scan_type, verdict, risk_score, str(threat_sources) if threat_sources else None, 
                  datetime.now().isoformat(), ml_confidence, heuristic_score, str(safe_browsing_result) if safe_browsing_result else None))

            # Update user stats
            cursor.execute('UPDATE users SET total_scans = total_scans + 1 WHERE id = ?', (user_id,))
            
            if verdict in ['FRAUDULENT', 'SUSPICIOUS', 'MALWARE']:
                cursor.execute('UPDATE users SET threats_detected = threats_detected + 1 WHERE id = ?', (user_id,))

            # Update daily analytics
            today = datetime.now().date().isoformat()
            cursor.execute('''
                INSERT OR IGNORE INTO user_analytics (user_id, date) VALUES (?, ?)
            ''', (user_id, today))

            cursor.execute('''
                UPDATE user_analytics SET 
                    scans_count = scans_count + 1,
                    threats_blocked = threats_blocked + CASE WHEN ? IN ('FRAUDULENT', 'SUSPICIOUS', 'MALWARE') THEN 1 ELSE 0 END,
                    websites_scanned = websites_scanned + CASE WHEN ? = 'website' THEN 1 ELSE 0 END,
                    apks_scanned = apks_scanned + CASE WHEN ? = 'apk' THEN 1 ELSE 0 END
                WHERE user_id = ? AND date = ?
            ''', (verdict, scan_type, scan_type, user_id, today))

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            conn.close()
            print(f"[ERROR] Failed to log user scan: {e}")
            return False

    def get_user_dashboard_data(self, user_id):
        """Get dashboard data for user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # User stats
            cursor.execute('SELECT total_scans, threats_detected FROM users WHERE id = ?', (user_id,))
            user_stats = cursor.fetchone()

            # Recent scans
            cursor.execute('''
                SELECT url, scan_type, verdict, risk_score, timestamp
                FROM user_scan_history
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT 10
            ''', (user_id,))
            recent_scans = cursor.fetchall()

            # Daily analytics for last 7 days
            cursor.execute('''
                SELECT date, scans_count, threats_blocked, websites_scanned, apks_scanned
                FROM user_analytics
                WHERE user_id = ? AND date >= date('now', '-7 days')
                ORDER BY date DESC
            ''', (user_id,))
            weekly_analytics = cursor.fetchall()

            # Threat distribution
            cursor.execute('''
                SELECT verdict, COUNT(*) as count
                FROM user_scan_history
                WHERE user_id = ? AND verdict IS NOT NULL
                GROUP BY verdict
                ORDER BY count DESC
            ''', (user_id,))
            threat_distribution = cursor.fetchall()

            conn.close()

            return {
                'user_stats': {
                    'total_scans': user_stats[0] if user_stats else 0,
                    'threats_detected': user_stats[1] if user_stats else 0
                },
                'recent_scans': [
                    {
                        'url': row[0],
                        'scan_type': row[1],
                        'verdict': row[2],
                        'risk_score': row[3],
                        'timestamp': row[4]
                    }
                    for row in recent_scans
                ],
                'weekly_analytics': [
                    {
                        'date': row[0],
                        'scans_count': row[1],
                        'threats_blocked': row[2],
                        'websites_scanned': row[3],
                        'apks_scanned': row[4]
                    }
                    for row in weekly_analytics
                ],
                'threat_distribution': [
                    {'verdict': row[0], 'count': row[1]}
                    for row in threat_distribution
                ]
            }
        except Exception as e:
            conn.close()
            print(f"[ERROR] Failed to get dashboard data: {e}")
            return None

    def log_threat(self, url, reason, action, user_agent=None, verdict=None, risk_score=None, user_id=None):
        """Log a threat detection"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO threat_logs (user_id, timestamp, url, reason, action, user_agent, verdict, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, datetime.now().isoformat(), url, reason, action, user_agent, verdict, risk_score))

        conn.commit()
        conn.close()

    def add_to_blacklist(self, url, reason="User reported"):
        """Add URL to blacklist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT OR REPLACE INTO blacklist (url, reason, added_date)
                VALUES (?, ?, ?)
            ''', (url, reason, datetime.now().isoformat()))

            conn.commit()
            conn.close()
            return True
        except Exception:
            conn.close()
            return False

    def add_to_whitelist(self, url, reason="User trusted"):
        """Add URL to whitelist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT OR REPLACE INTO whitelist (url, reason, added_date)
                VALUES (?, ?, ?)
            ''', (url, reason, datetime.now().isoformat()))

            conn.commit()
            conn.close()
            return True
        except Exception:
            conn.close()
            return False

    def is_blacklisted(self, url):
        """Check if URL is blacklisted"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT 1 FROM blacklist WHERE url = ?', (url,))
        result = cursor.fetchone()

        conn.close()
        return result is not None

    def is_whitelisted(self, url):
        """Check if URL is whitelisted"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT 1 FROM whitelist WHERE url = ?', (url,))
        result = cursor.fetchone()

        conn.close()
        return result is not None

    def log_user_report(self, url, reason, user_agent=None, user_id=None):
        """Log user report of malicious site"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Check columns present in user_reports
            cursor.execute("PRAGMA table_info(user_reports)")
            cols = [r[1] for r in cursor.fetchall()]

            if 'user_id' in cols:
                cursor.execute('''
                    INSERT INTO user_reports (user_id, url, report_reason, timestamp, user_agent)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, url, reason, datetime.now().isoformat(), user_agent))
            else:
                # Older schema: insert without user_id
                cursor.execute('''
                    INSERT INTO user_reports (url, report_reason, timestamp, user_agent)
                    VALUES (?, ?, ?, ?)
                ''', (url, reason, datetime.now().isoformat(), user_agent))

            conn.commit()
        except Exception as e:
            print(f"[WARN] log_user_report failed: {e}")
        finally:
            try: conn.close()
            except: pass

    def get_recent_threats(self, limit=10, user_id=None):
        """Get recent threat logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if user_id:
            cursor.execute('''
                SELECT timestamp, url, reason, action, verdict, risk_score
                FROM threat_logs
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (user_id, limit))
        else:
            cursor.execute('''
                SELECT timestamp, url, reason, action, verdict, risk_score
                FROM threat_logs
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))

        results = cursor.fetchall()
        conn.close()

        return [
            {
                'timestamp': row[0],
                'url': row[1],
                'reason': row[2],
                'action': row[3],
                'verdict': row[4],
                'risk_score': row[5]
            }
            for row in results
        ]

    def get_stats(self, user_id=None):
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if user_id:
            # User-specific stats
            cursor.execute('SELECT COUNT(*) FROM threat_logs WHERE user_id = ?', (user_id,))
            total_threats = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM threat_logs WHERE user_id = ? AND action = "BLOCKED"', (user_id,))
            blocked_threats = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM user_reports WHERE user_id = ?', (user_id,))
            user_reports = cursor.fetchone()[0]

            blacklisted_sites = 0  # Global stat
        else:
            # Global stats
            cursor.execute('SELECT COUNT(*) FROM threat_logs')
            total_threats = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM threat_logs WHERE action = "BLOCKED"')
            blocked_threats = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM blacklist')
            blacklisted_sites = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM user_reports')
            user_reports = cursor.fetchone()[0]

        conn.close()

        return {
            'total_threats': total_threats,
            'blocked_threats': blocked_threats,
            'blacklisted_sites': blacklisted_sites,
            'user_reports': user_reports
        }

    def logout_user(self, session_token):
        """Logout user by deactivating session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('UPDATE user_sessions SET is_active = 0 WHERE session_token = ?', (session_token,))
            conn.commit()
            conn.close()
            return True
        except Exception:
            conn.close()
            return False

    def log_extension_visit(self, user_id, url, domain, title=None, is_threat=False, threat_type=None, risk_score=0, blocked=False, warning_shown=False, user_action=None):
        """Log a website visit from the Chrome extension"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if this URL was already visited today
            today = datetime.now().date().isoformat()
            # handle NULL user_id correctly in older DBs
            if user_id is None:
                cursor.execute('''
                    SELECT id, visit_count FROM extension_browsing_history 
                    WHERE user_id IS NULL AND url = ? AND DATE(visit_time) = ?
                ''', (url, today))
            else:
                cursor.execute('''
                    SELECT id, visit_count FROM extension_browsing_history 
                    WHERE user_id = ? AND url = ? AND DATE(visit_time) = ?
                ''', (user_id, url, today))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update visit count
                cursor.execute('''
                    UPDATE extension_browsing_history 
                    SET visit_count = visit_count + 1, visit_time = ?,
                        is_threat = ?, threat_type = ?, risk_score = ?, 
                        blocked = ?, warning_shown = ?, user_action = ?
                    WHERE id = ?
                ''', (datetime.now().isoformat(), int(is_threat), threat_type, risk_score, 
                     int(blocked), int(warning_shown), user_action, existing[0]))
            else:
                # Insert new visit
                # Determine if user_id column exists
                cursor.execute("PRAGMA table_info(extension_browsing_history)")
                cols = [r[1] for r in cursor.fetchall()]

                if 'user_id' in cols:
                    cursor.execute('''
                        INSERT INTO extension_browsing_history 
                        (user_id, url, domain, title, visit_time, is_threat, threat_type, 
                         risk_score, blocked, warning_shown, user_action)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (user_id, url, domain, title, datetime.now().isoformat(), 
                         int(is_threat), threat_type, risk_score, int(blocked), 
                         int(warning_shown), user_action))
                else:
                    cursor.execute('''
                        INSERT INTO extension_browsing_history 
                        (url, domain, title, visit_time, is_threat, threat_type, 
                         risk_score, blocked, warning_shown, user_action)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (url, domain, title, datetime.now().isoformat(), 
                         int(is_threat), threat_type, risk_score, int(blocked), 
                         int(warning_shown), user_action))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[WARN] log_extension_visit failed: {e}")
            try: conn.close()
            except: pass
            return False

    def log_extension_threat(self, user_id, url, domain, threat_type, detection_method, confidence_score, action_taken, user_proceeded=False, threat_details=None):
        """Log a threat detection from the Chrome extension"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO extension_threat_detections 
                (user_id, url, domain, threat_type, detection_method, confidence_score, 
                 detected_at, action_taken, user_proceeded, threat_details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, url, domain, threat_type, detection_method, confidence_score,
                 datetime.now().isoformat(), action_taken, int(user_proceeded), threat_details))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            conn.close()
            return False

    def update_extension_setting(self, user_id, setting_name, setting_value):
        """Update extension setting for a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO extension_settings 
                (user_id, setting_name, setting_value, updated_at)
                VALUES (?, ?, ?, ?)
            ''', (user_id, setting_name, setting_value, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            conn.close()
            return False

    def get_extension_dashboard_data(self, user_id):
        """Get comprehensive extension data for dashboard visualization"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Support both user-specific and global queries. When user_id is None, aggregate across all users.
            if user_id is None:
                stats_q = '''
                    SELECT 
                        COUNT(*) as total_visits,
                        COUNT(DISTINCT domain) as unique_domains,
                        SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END) as threat_sites,
                        SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_sites,
                        AVG(risk_score) as avg_risk_score
                    FROM extension_browsing_history
                '''

                recent_threats_q = '''
                    SELECT url, domain, threat_type, confidence_score, detected_at, action_taken
                    FROM extension_threat_detections
                    ORDER BY detected_at DESC
                    LIMIT 10
                '''

                daily_stats_q = '''
                    SELECT date, pages_visited, threats_detected, threats_blocked, warnings_shown
                    FROM extension_usage_stats
                    ORDER BY date DESC
                    LIMIT 30
                '''

                top_domains_q = '''
                    SELECT domain, COUNT(*) as visit_count,
                           SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END) as threat_count
                    FROM extension_browsing_history
                    GROUP BY domain
                    ORDER BY visit_count DESC
                    LIMIT 10
                '''

                settings_q = '''
                    SELECT setting_name, setting_value, updated_at
                    FROM extension_settings
                '''

                cursor.execute(stats_q)
                stats = cursor.fetchone()

                cursor.execute(recent_threats_q)
                recent_threats = cursor.fetchall()

                cursor.execute(daily_stats_q)
                daily_stats = cursor.fetchall()

                cursor.execute(top_domains_q)
                top_domains = cursor.fetchall()

                cursor.execute(settings_q)
                settings = cursor.fetchall()
            else:
                # User-specific queries
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total_visits,
                        COUNT(DISTINCT domain) as unique_domains,
                        SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END) as threat_sites,
                        SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_sites,
                        AVG(risk_score) as avg_risk_score
                    FROM extension_browsing_history 
                    WHERE user_id = ?
                ''', (user_id,))

                stats = cursor.fetchone()

                cursor.execute('''
                    SELECT url, domain, threat_type, confidence_score, detected_at, action_taken
                    FROM extension_threat_detections 
                    WHERE user_id = ? 
                    ORDER BY detected_at DESC 
                    LIMIT 10
                ''', (user_id,))
                recent_threats = cursor.fetchall()

                cursor.execute('''
                    SELECT date, pages_visited, threats_detected, threats_blocked, warnings_shown
                    FROM extension_usage_stats 
                    WHERE user_id = ? 
                    ORDER BY date DESC 
                    LIMIT 30
                ''', (user_id,))
                daily_stats = cursor.fetchall()

                cursor.execute('''
                    SELECT domain, COUNT(*) as visit_count, 
                           SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END) as threat_count
                    FROM extension_browsing_history 
                    WHERE user_id = ? 
                    GROUP BY domain 
                    ORDER BY visit_count DESC 
                    LIMIT 10
                ''', (user_id,))
                top_domains = cursor.fetchall()

                cursor.execute('''
                    SELECT setting_name, setting_value, updated_at
                    FROM extension_settings 
                    WHERE user_id = ?
                ''', (user_id,))

                settings = cursor.fetchall()
            
            conn.close()
            
            return {
                'stats': {
                    'total_visits': stats[0] or 0,
                    'unique_domains': stats[1] or 0,
                    'threat_sites': stats[2] or 0,
                    'blocked_sites': stats[3] or 0,
                    'avg_risk_score': round(stats[4] or 0, 2)
                },
                'recent_threats': [
                    {
                        'url': t[0], 'domain': t[1], 'threat_type': t[2],
                        'confidence': t[3], 'detected_at': t[4], 'action': t[5]
                    } for t in recent_threats
                ],
                'daily_stats': [
                    {
                        'date': d[0], 'pages_visited': d[1], 'threats_detected': d[2],
                        'threats_blocked': d[3], 'warnings_shown': d[4]
                    } for d in daily_stats
                ],
                'top_domains': [
                    {
                        'domain': d[0], 'visit_count': d[1], 'threat_count': d[2]
                    } for d in top_domains
                ],
                'settings': {s[0]: s[1] for s in settings}
            }
        except Exception as e:
            conn.close()
            return None

    def update_daily_extension_stats(self, user_id, pages_visited=0, threats_detected=0, threats_blocked=0, warnings_shown=0, user_overrides=0, scan_time=0, avg_risk=0):
        """Update daily extension usage statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            today = datetime.now().date().isoformat()
            
            cursor.execute('''
                INSERT OR REPLACE INTO extension_usage_stats 
                (user_id, date, pages_visited, threats_detected, threats_blocked, 
                 warnings_shown, user_overrides, total_scan_time, average_page_risk)
                VALUES (?, ?, 
                    COALESCE((SELECT pages_visited FROM extension_usage_stats WHERE user_id = ? AND date = ?), 0) + ?,
                    COALESCE((SELECT threats_detected FROM extension_usage_stats WHERE user_id = ? AND date = ?), 0) + ?,
                    COALESCE((SELECT threats_blocked FROM extension_usage_stats WHERE user_id = ? AND date = ?), 0) + ?,
                    COALESCE((SELECT warnings_shown FROM extension_usage_stats WHERE user_id = ? AND date = ?), 0) + ?,
                    COALESCE((SELECT user_overrides FROM extension_usage_stats WHERE user_id = ? AND date = ?), 0) + ?,
                    COALESCE((SELECT total_scan_time FROM extension_usage_stats WHERE user_id = ? AND date = ?), 0) + ?,
                    ?)
            ''', (user_id, today, 
                 user_id, today, pages_visited,
                 user_id, today, threats_detected,
                 user_id, today, threats_blocked,
                 user_id, today, warnings_shown,
                 user_id, today, user_overrides,
                 user_id, today, scan_time,
                 avg_risk))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            conn.close()
            return False


# Initialize database when imported
db = CipherCopDB()
