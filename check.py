import sqlite3

class ScanResultsDatabase:
    def __init__(self, db_name="static_analysis.db"):
        # Initialize the database connection
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()

    def fetch_all_scan_results(self):
        """Fetch all scan results from the vulnerabilities table."""
        try:
            query = "SELECT * FROM vulnerabilities"
            self.cursor.execute(query)
            results = self.cursor.fetchall()  # Fetch all rows
            return results
        except sqlite3.Error as e:
            print(f"Error fetching scan results: {e}")
            return []

    def fetch_scan_results_by_file(self, file_path):
        """Fetch scan results filtered by the file path."""
        try:
            query = "SELECT * FROM vulnerabilities WHERE file_path = ?"
            self.cursor.execute(query, (file_path,))
            results = self.cursor.fetchall()
            return results
        except sqlite3.Error as e:
            print(f"Error fetching scan results for file {file_path}: {e}")
            return []

    def insert_scan_result(self, file_path, vulnerability, description):
        """Insert a new scan result into the database."""
        try:
            query = ''' 
                INSERT INTO vulnerabilities (file_path, vulnerability, description)
                VALUES (?, ?, ?)
            '''
            self.cursor.execute(query, (file_path, vulnerability, description))
            self.conn.commit()
            print(f"Inserted scan result for file: {file_path}")
        except sqlite3.Error as e:
            print(f"Error inserting scan result: {e}")

    def close(self):
        """Close the database connection."""
        self.conn.close()

# Example usage
if __name__ == "__main__":
    # Initialize the database handler
    db_handler = ScanResultsDatabase()

    # Fetch all scan results
    scan_results = db_handler.fetch_all_scan_results()
    print("All Scan Results:")
    for result in scan_results:
        print(result)

    # Fetch scan results for a specific file
    file_results = db_handler.fetch_scan_results_by_file('path/to/your/file.kt')
    print("\nScan Results for specific file:")
    for result in file_results:
        print(result)

    # Example to insert a new scan result
    db_handler.insert_scan_result('path/to/your/file.kt', 'Hardcoded API Key', 'Detected hardcoded API key.')

    # Close the database connection
    db_handler.close()
