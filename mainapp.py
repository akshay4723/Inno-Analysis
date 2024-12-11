from flask import Flask, render_template, request, jsonify
import sqlite3
import os

app = Flask(__name__)
DB_FILE = "scan_results.db"

# Initialize the database
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file TEXT,
                vulnerability TEXT,
                description TEXT
            )
        ''')
        conn.commit()

# Insert vulnerabilities into the database
def save_results(vulnerabilities):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        for vuln in vulnerabilities:
            cursor.execute('''
                INSERT INTO vulnerabilities (file, vulnerability, description)
                VALUES (?, ?, ?)
            ''', (vuln['file'], vuln['vulnerability'], vuln['description']))
        conn.commit()

# Fetch vulnerabilities from the database
def fetch_results():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT file, vulnerability, description FROM vulnerabilities')
        return cursor.fetchall()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_project():
    project_path = request.form.get('project_path')
    if not os.path.exists(project_path):
        return jsonify({'error': 'Project path does not exist.'}), 400

    # Here we mock the vulnerabilities for demonstration
    # Replace this with the actual analysis logic
    vulnerabilities = [
        {"file": "src/MainActivity.java", "vulnerability": "Hardcoded API Key", "description": "Found an API key."},
        {"file": "build.gradle", "vulnerability": "Outdated Library", "description": "Using an outdated library."}
    ]

    save_results(vulnerabilities)
    return jsonify({'message': 'Scan completed successfully.', 'results': vulnerabilities})

@app.route('/results')
def results():
    vulnerabilities = fetch_results()
    return jsonify({'vulnerabilities': vulnerabilities})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
