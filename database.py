import sqlite3


def create_database():
    """Create database and brands table if it doesn't exist"""
    conn = None
    try:
        conn = sqlite3.connect('brands_new.db', timeout=10)
        cursor = conn.cursor()

        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS brands
                       (
                           id INTEGER PRIMARY KEY AUTOINCREMENT,
                           brand_name TEXT NOT NULL UNIQUE,
                           official_url TEXT NOT NULL
                       )
                       ''')

        # Insert initial brand data
        brands_data = [
            ('steam', 'store.steampowered.com'),
            ('facebook', 'facebook.com'),
            ('youtube', 'youtube.com'),
            ('google', 'google.com'),
            ('paypal', 'paypal.com'),
            ('amazon', 'amazon.com'),
            ('microsoft', 'microsoft.com'),
            ('apple', 'apple.com'),
            ('netflix', 'netflix.com'),
            ('ebay', 'ebay.com'),
            ('instagram', 'instagram.com'),
            ('twitter', 'twitter.com'),
            ('linkedin', 'linkedin.com'),
            ('github', 'github.com'),
            ('dropbox', 'dropbox.com'),
            ('reddit', 'reddit.com'),
            ('wordpress', 'wordpress.com'),
            ('blogger', 'blogger.com'),
            ('quora', 'quora.com'),
            ('vimeo', 'vimeo.com'),
            ('flickr', 'flickr.com'),
            ('spotify', 'spotify.com'),
            ('slack', 'slack.com'),
            ('twitch', 'twitch.tv'),
            ('discord', 'discord.com'),
            ('adobe', 'adobe.com'),
            ('flipkart', 'flipkart.com'),
            ('zoom', 'zoom.us'),
            ('tiktok', 'tiktok.com'),
            ('snapchat', 'snapchat.com'),
            ('whatsapp', 'whatsapp.com'),
            ('telegram', 'telegram.org'),
            ('wechat', 'wechat.com'),
            ('makemytrip', 'makemytrip.com'),
            ('uber', 'uber.com'),
            ('irctc', 'irctc.co.in'),
            ('goibibo', 'goibibo.com'),
            ('paytm', 'paytm.com'),
            ('shopify', 'shopify.com'),
            ('zillow', 'zillow.com'),
            ('primevideo', 'primevideo.com'),
            ('hotstar', 'hotstar.com'),
        ]

        cursor.executemany('INSERT OR IGNORE INTO brands (brand_name, official_url) VALUES (?, ?)', brands_data)

        conn.commit()
        print("✓ Database initialized")
    except sqlite3.Error as e:
        print(f"Error creating database: {e}")
    finally:
        if conn:
            conn.close()


def get_brands_from_db():
    """Retrieve all brands from database"""
    conn = None
    try:
        conn = sqlite3.connect('brands_new.db', timeout=10)
        cursor = conn.cursor()

        cursor.execute('SELECT brand_name, official_url FROM brands')
        brands = cursor.fetchall()
        return brands
    except sqlite3.Error as e:
        print(f"Error getting brands: {e}")
        return []
    finally:
        if conn:
            conn.close()


def add_brand(brand_name, official_url):
    """Add a new brand to the database"""
    conn = None
    try:
        conn = sqlite3.connect('brands_new.db', timeout=10)
        cursor = conn.cursor()

        cursor.execute('INSERT INTO brands (brand_name, official_url) VALUES (?, ?)',
                       (brand_name.lower(), official_url.lower()))
        conn.commit()
        print(f"✓ Added {brand_name} to database")
    except sqlite3.IntegrityError:
        print(f"⚠️ {brand_name} already exists in database")
    except sqlite3.Error as e:
        print(f"Error adding brand: {e}")
    finally:
        if conn:
            conn.close()


def delete_brand(brand_name):
    """Delete a brand from database"""
    conn = None
    try:
        conn = sqlite3.connect('brands_new.db', timeout=10)
        cursor = conn.cursor()

        cursor.execute('DELETE FROM brands WHERE brand_name = ?', (brand_name.lower(),))
        conn.commit()

        if cursor.rowcount > 0:
            print(f"✓ Deleted {brand_name} from database")
        else:
            print(f"⚠️ {brand_name} not found in database")
    except sqlite3.Error as e:
        print(f"Error deleting brand: {e}")
    finally:
        if conn:
            conn.close()


def list_all_brands():
    """List all brands in database"""
    brands = get_brands_from_db()
    print("\n=== Brands in Database ===")
    for brand_name, official_url in brands:
        print(f"{brand_name}: {official_url}")
    print(f"\nTotal: {len(brands)} brands")






    #Final Release Note: This module manages the brands database for storing brand information.