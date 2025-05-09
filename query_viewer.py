import sqlite3
import csv
import os
import platform

DB_NAME = "network_logs.db"
DEBUG_SQL = False  # Set to True if you want to see the queries and parameters printed

def view_alerts(filter_type=None, keyword=None):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    query = "SELECT * FROM alerts"
    conditions = []
    params = []

    if filter_type:
        conditions.append("UPPER(type) LIKE ?")
        params.append(f"%{filter_type.upper()}%")
    if keyword:
        conditions.append("UPPER(message) LIKE ?")
        params.append(f"%{keyword.upper()}%")

    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY timestamp DESC LIMIT 50"

    if DEBUG_SQL:
        print("DEBUG SQL:", query, "| PARAMS:", params)

    print("\n=== ALERT LOGS ===")
    c.execute(query, params)
    results = c.fetchall()
    if not results:
        print("No results found.")
    else:
        for row in results:
            print(f"[{row[0]}] {row[1]} | TYPE: {row[2]} | MESSAGE: {row[3]}")
    conn.close()

def view_packets(filter_protocol=None, keyword=None):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    query = "SELECT * FROM packets"
    conditions = []
    params = []

    if filter_protocol:
        conditions.append("UPPER(protocol) LIKE ?")
        params.append(f"%{filter_protocol.upper()}%")
    if keyword:
        conditions.append("UPPER(details) LIKE ?")
        params.append(f"%{keyword.upper()}%")

    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY timestamp DESC LIMIT 50"

    if DEBUG_SQL:
        print("DEBUG SQL:", query, "| PARAMS:", params)

    print("\n=== PACKET LOGS ===")
    c.execute(query, params)
    results = c.fetchall()
    if not results:
        print("No results found.")
    else:
        for row in results:
            print(f"[{row[0]}] {row[1]} | SRC: {row[2]} → DST: {row[3]} | PROTOCOL: {row[4]} | DETAILS: {row[5]}")
    conn.close()

def export_to_csv(table_name, output_file):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(f"SELECT * FROM {table_name}")
    rows = c.fetchall()
    headers = [desc[0] for desc in c.description]

    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    conn.close()
    print(f"[✓] Exported {table_name} to {output_file}")

    # Auto-open after export
    if platform.system() == "Windows":
        os.startfile(output_file)
    elif platform.system() == "Darwin":
        os.system(f"open {output_file}")
    elif platform.system() == "Linux":
        os.system(f"xdg-open {output_file}")

def main_menu():
    while True:
        print("\n--- QUERY VIEWER MENU ---")
        print("1. View Alerts")
        print("2. View Packets")
        print("3. Export Alerts to CSV")
        print("4. Export Packets to CSV")
        print("5. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            t = input("Filter by type (optional): ").strip()
            k = input("Filter by keyword/date (optional): ").strip()
            view_alerts(t if t else None, k if k else None)
        elif choice == "2":
            p = input("Filter by protocol (optional): ").strip()
            k = input("Filter by keyword/date (optional): ").strip()
            view_packets(p if p else None, k if k else None)
        elif choice == "3":
            export_to_csv("alerts", "alerts_export.csv")
        elif choice == "4":
            export_to_csv("packets", "packets_export.csv")
        elif choice == "5":
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main_menu()
