import sqlite3

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Create groups table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        )
    ''')

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            group_id INTEGER,
            FOREIGN KEY(group_id) REFERENCES groups(id)
        )
    ''')

    # Insert sample data
    cursor.execute("INSERT OR IGNORE INTO groups (id, name) VALUES (1, 'admin'), (2, 'user')")
    cursor.execute("INSERT OR IGNORE INTO users (username, password, group_id) VALUES ('alice', 'secret123', 1)")
    cursor.execute("INSERT OR IGNORE INTO users (username, password, group_id) VALUES ('bob', 'mypassword', 2)")

    conn.commit()
    conn.close()
    print("Database initialized with sample data.")

def check_login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    query = '''
        SELECT users.username, users.password, groups.name as group_name
        FROM users
        JOIN groups ON users.group_id = groups.id
        WHERE users.username = ? AND users.password = ?
    '''
    cursor.execute(query, (username, password))
    result = cursor.fetchone()

    if result:
        print(f"Login successful. User '{result[0]}' is in group '{result[2]}'.")
    else:
        print("Invalid username or password.")

    cursor.close()
    conn.close()

# Run initialization and test login
if __name__ == "__main__":
    init_db()
    check_login("alice", "secret123")   # Should succeed
    check_login("bob", "wrongpass")     # Should fail
