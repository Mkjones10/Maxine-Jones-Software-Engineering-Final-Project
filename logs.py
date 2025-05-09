import sqlite3

conn = sqlite3.connect("network_logs.db")
c = conn.cursor()
print("\n--- DISTINCT ALERT TYPES ---")
c.execute("SELECT DISTINCT type FROM alerts")
for row in c.fetchall():
    print("-", row[0])

print("\n--- DISTINCT PACKET PROTOCOLS ---")
c.execute("SELECT DISTINCT protocol FROM packets")
for row in c.fetchall():
    print("-", row[0])

print("\n--- SAMPLE UDP ALERTS ---")
c.execute("SELECT * FROM alerts WHERE UPPER(type) LIKE '%UDP%' LIMIT 5")
for row in c.fetchall():
    print(row)

print("\n--- SAMPLE UDP PACKETS ---")
c.execute("SELECT * FROM packets WHERE UPPER(protocol) = 'UDP' LIMIT 5")
for row in c.fetchall():
    print(row)
print("\n DISTINCT ALERT TYPES:")
c.execute("SELECT DISTINCT type FROM alerts")
types = c.fetchall()
if not types:
    print("No alert types found in database.")
else:
    for t in types:
        print("-", t[0])

print("\n SAMPLE ALERT RECORDS:")
c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5")
alerts = c.fetchall()
if not alerts:
    print("No alert records found.")
else:
    for a in alerts:
        print(a)

conn.close()
