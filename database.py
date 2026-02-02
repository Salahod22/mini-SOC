import sqlite3
import os

DB_NAME = 'students.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # 1. Users Table (Admins/Staff)
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  role TEXT DEFAULT 'staff')''')
    
    # 2. Students Table (The Data)
    c.execute('''CREATE TABLE IF NOT EXISTS students
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  student_id TEXT UNIQUE,
                  name TEXT,
                  grade INTEGER,
                  gpa REAL,
                  email TEXT)''')
    
    # Check if empty, then populate
    c.execute('SELECT count(*) FROM users')
    if c.fetchone()[0] == 0:
        print("Initializing Database with Mock Data...")
        
        # Admin User
        c.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'password123', 'admin')")
        c.execute("INSERT INTO users (username, password, role) VALUES ('jdoe', 'securepass', 'staff')")

        # Mock Students
        students = [
            ('S1001', 'Alice Smith', 12, 3.8, 'alice@school.edu'),
            ('S1002', 'Bob Jones', 11, 2.5, 'bob@school.edu'),
            ('S1003', 'Charlie Day', 12, 3.1, 'charlie@school.edu'),
            ('S1004', 'Diana Prince', 10, 4.0, 'diana@school.edu'),
            ('S1005', 'Evan Wright', 11, 1.9, 'evan@school.edu')
        ]
        c.executemany("INSERT INTO students (student_id, name, grade, gpa, email) VALUES (?, ?, ?, ?, ?)", students)
        
        conn.commit()
    
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn
