import sqlite3

def init_db():
    conn = sqlite3.connect('network_logs.db')
    c = conn.cursor()
    
    # Create packets table
    c.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dest_ip TEXT,
            protocol TEXT,
            details TEXT
        )
    ''')
    
    # Create alerts table
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            type TEXT,
            message TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully.")

if __name__ == "__main__":
    init_db()
