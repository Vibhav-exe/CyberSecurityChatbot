import sqlite3


def create_scan_history_table():
    """Create table to store scan results for learning"""
    conn = None
    try:
        conn = sqlite3.connect('brands.db', timeout=10)
        cursor = conn.cursor()

        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS scan_history
                       (
                           id INTEGER PRIMARY KEY AUTOINCREMENT,
                           url TEXT NOT NULL,
                           real_domain TEXT,
                           has_suspicious_keywords INTEGER,
                           is_impersonation INTEGER,
                           virustotal_malicious INTEGER,
                           virustotal_suspicious INTEGER,
                           google_safe_browsing_threat INTEGER,
                           is_shortened INTEGER,
                           final_verdict TEXT,
                           scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                       )
                       ''')

        conn.commit()
        print("✓ Scan history table initialized")
    except sqlite3.Error as e:
        print(f"Error creating scan history table: {e}")
    finally:
        if conn:
            conn.close()


def save_scan_result(url, scan_data):
    """Save scan results to database"""
    conn = None
    try:
        conn = sqlite3.connect('brands.db', timeout=10)
        cursor = conn.cursor()

        cursor.execute('''
                       INSERT INTO scan_history
                       (url, real_domain, has_suspicious_keywords, is_impersonation,
                        virustotal_malicious, virustotal_suspicious, google_safe_browsing_threat,
                        is_shortened, final_verdict)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ''', (
                           scan_data['url'],
                           scan_data.get('real_domain', ''),
                           scan_data.get('has_suspicious_keywords', 0),
                           scan_data.get('is_impersonation', 0),
                           scan_data.get('vt_malicious', 0),
                           scan_data.get('vt_suspicious', 0),
                           scan_data.get('gsb_threat', 0),
                           scan_data.get('is_shortened', 0),
                           scan_data.get('verdict', 'UNKNOWN')
                       ))

        conn.commit()
        print("✓ Scan result saved to database")
    except sqlite3.Error as e:
        print(f"Error saving scan result: {e}")
    finally:
        if conn:
            conn.close()


def get_scan_history(limit=50):
    """Get recent scan history for learning"""
    conn = None
    try:
        conn = sqlite3.connect('brands.db', timeout=10)
        cursor = conn.cursor()

        cursor.execute('''
                       SELECT * FROM scan_history
                       ORDER BY scan_date DESC 
                       LIMIT ?
                       ''', (limit,))

        results = cursor.fetchall()
        return results
    except sqlite3.Error as e:
        print(f"Error getting scan history: {e}")
        return []
    finally:
        if conn:
            conn.close()