import os
import re
import sqlite3
import yaml
import json
import requests
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split

# Enhanced Configuration for vulnerability patterns
VULNERABILITY_CONFIG = '''
vulnerabilities:
  - name: Hardcoded API Key
    pattern: '(api_key|SECRET|api_secret|access_token|password)[^a-zA-Z0-9]'
    description: 'Detects hardcoded API keys in the source code.'
  - name: Insecure Cryptographic Algorithm
    pattern: '(md5|sha1|rc4|des|blowfish)'
    description: 'Detects insecure cryptographic algorithms.'
  - name: Insecure Dependency
    pattern: '(com.google.firebase|com.android.support|retrofit|okhttp|junit|commons-collections)'
    description: 'Detects use of insecure or outdated dependencies in build.gradle.'
  - name: Sensitive Information Exposure
    pattern: '(password|private_key|access_token|auth_secret)'
    description: 'Detects hardcoded sensitive information.'
'''

class StaticAnalyzer:
    def __init__(self, project_folder, db_name="scan_results.db"):
        self.project_folder = project_folder
        self.vulnerabilities = self.load_vulnerability_patterns()
        self.ml_model = None
        self.vectorizer = CountVectorizer()
        self.previous_scans = []  # Could load this from previous analysis if stored
        self.db_name = db_name
        self.db_connection = self.create_database()
        self.secure_versions = {
            'com.google.firebase': '30.0.0',  # Example version
            'com.android.support': '28.0.0',
            'retrofit': '2.9.0',
            'okhttp': '4.9.0',
            'junit': '4.13.2',
            'commons-collections': '3.2.2'
        }

    def load_vulnerability_patterns(self):
        """Load predefined vulnerability patterns from YAML configuration."""
        return yaml.safe_load(VULNERABILITY_CONFIG)["vulnerabilities"]

    def create_database(self):
        """Create SQLite database to store vulnerability results."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute(''' 
            CREATE TABLE IF NOT EXISTS vulnerabilities ( 
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                file_path TEXT NOT NULL, 
                vulnerability TEXT NOT NULL, 
                description TEXT NOT NULL, 
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP 
            ) 
        ''')
        conn.commit()
        return conn

    def store_results_in_db(self, vulnerabilities_found):
        """Store the scan results in the SQLite database."""
        cursor = self.db_connection.cursor()
        for issue in vulnerabilities_found:
            cursor.execute(''' 
                INSERT INTO vulnerabilities (file_path, vulnerability, description) 
                VALUES (?, ?, ?) 
            ''', (issue['file'], issue['vulnerability'], issue['description']))
        self.db_connection.commit()

    def analyze_code(self):
        """Analyze code in the given directory for vulnerabilities."""
        vulnerabilities_found = []
        for root, dirs, files in os.walk(self.project_folder):
            for file in files:
                file_path = os.path.join(root, file)
                # Scan Kotlin, Java, XML, and JSON files
                if file.endswith((".kt", ".java", ".xml", ".json")):
                    vulnerabilities_found += self.check_file_for_vulnerabilities(file_path)
                if file == 'build.gradle':  # Check for dependencies in build.gradle
                    vulnerabilities_found += self.check_dependencies(file_path)
        return vulnerabilities_found

    def check_file_for_vulnerabilities(self, file_path):
        """Check a single file for vulnerabilities based on patterns."""
        vulnerabilities_found = []
        with open(file_path, 'r', encoding='utf-8') as file:
            file_content = file.read()
            for vulnerability in self.vulnerabilities:
                if re.search(vulnerability["pattern"], file_content, re.IGNORECASE):
                    vulnerabilities_found.append({
                        "file": file_path,
                        "vulnerability": vulnerability["name"],
                        "description": vulnerability["description"]
                    })
                    self.provide_real_time_suggestions(file_path, vulnerability["name"])
        return vulnerabilities_found

    def check_dependencies(self, file_path):
        """Check for insecure or outdated dependencies in build.gradle."""
        vulnerabilities_found = []
        with open(file_path, 'r', encoding='utf-8') as file:
            gradle_content = file.read()
            # Regex for extracting library and version
            dependency_pattern = r"([a-zA-Z0-9\.\-]+):([a-zA-Z0-9\.\-]+)"
            dependencies = re.findall(dependency_pattern, gradle_content)
            
            for library, version in dependencies:
                if library in self.secure_versions:
                    secure_version = self.secure_versions[library]
                    if version != secure_version:
                        vulnerabilities_found.append({
                            "file": file_path,
                            "vulnerability": "Outdated Library",
                            "description": f"Use of outdated library: {library}. Current version: {version}, Secure version: {secure_version}."
                        })
                        self.provide_real_time_suggestions(file_path, "Outdated Library")
        return vulnerabilities_found

    def provide_real_time_suggestions(self, file_path, vulnerability_name):
        """Provide real-time suggestions to fix vulnerabilities."""
        suggestions = {
            "Hardcoded API Key": "Consider using secure key management solutions like Android Keystore.",
            "Insecure Cryptographic Algorithm": "Replace insecure algorithms with AES or SHA-256.",
            "Outdated Library": "Update your dependencies to the latest version for security fixes.",
            "Sensitive Information Exposure": "Remove hardcoded sensitive information and use encrypted storage."
        }
        suggestion = suggestions.get(vulnerability_name, 'No suggestion available.')
        print(f"Real-time suggestion for {file_path}: {suggestion}")

    def train_machine_learning_model(self):
        """Train a machine learning model to evolve security rules based on previous scans."""
        features = []
        labels = []
        for scan in self.previous_scans:
            for issue in scan:
                features.append(issue['file'])  # For better features, add the actual file content or metadata
                labels.append(issue['vulnerability'])

        if features and labels:
            X = self.vectorizer.fit_transform(features)
            y = labels

            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

            self.ml_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.ml_model.fit(X_train, y_train)
            print("Machine learning model trained successfully.")

    def make_prediction(self, new_file_content):
        """Use the trained machine learning model to predict vulnerabilities."""
        if self.ml_model:
            X_new = self.vectorizer.transform([new_file_content])
            prediction = self.ml_model.predict(X_new)
            return prediction[0]
        else:
            return None

    def generate_report(self, vulnerabilities_found):
        """Generate a report and send it to the backend."""
        if not vulnerabilities_found:
            print("No vulnerabilities found.")
            return

        # Store the results in the database
        self.store_results_in_db(vulnerabilities_found)

        # Display the report
        for issue in vulnerabilities_found:
            print(f"\nFile: {issue['file']}")
            print(f"Vulnerability: {issue['vulnerability']}")
            print(f"Description: {issue['description']}")

        # Send the full list of vulnerabilities to the backend
        payload = {
            "vulnerabilities": vulnerabilities_found  # Include the list of vulnerabilities here
        }
        try:
            response = requests.post("http://127.0.0.1:8000/upload_report", json=payload)
            if response.status_code == 200:
                print("Report sent successfully.")
            else:
                print(f"Failed to send report: {response.text}")
        except Exception as e:
            print(f"Error sending report: {e}")

if __name__ == "__main__":
    project_folder = "D:/MyAndroidProjects"

    analyzer = StaticAnalyzer(project_folder)
    vulnerabilities_found = analyzer.analyze_code()
    analyzer.generate_report(vulnerabilities_found)
