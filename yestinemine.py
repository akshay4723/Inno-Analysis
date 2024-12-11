from flask import Flask, render_template, request, jsonify
import sqlite3
import os

app = Flask(__name__)
DB_FILE = "static_analysis.db"

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

@app.route('/upload_report', methods=['POST'])
def upload_report():
    """Handle report upload and save vulnerabilities to the database."""
    if not request.is_json:
        return jsonify({'error': 'Invalid input. JSON data expected.'}), 400
    
    data = request.get_json()
    if 'vulnerabilities' not in data or not isinstance(data['vulnerabilities'], list):
        return jsonify({'error': 'Invalid input format. "vulnerabilities" field required.'}), 400

    # Save the uploaded vulnerabilities to the database
    save_results(data['vulnerabilities'])
    return jsonify({'message': 'Report uploaded and saved successfully.'})

@app.route('/results')
def results():
    vulnerabilities = fetch_results()
    return jsonify({'vulnerabilities': vulnerabilities})

if __name__ == '__main__':
    init_db()
    app.run(port=8000, debug=True)
