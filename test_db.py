"""Check SmartHostel's MySQL connection using the current .env settings."""
import mysql.connector
import db


def main():
    try:
        conn = db.get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT DATABASE(), VERSION()")
            database, version = cur.fetchone()
            print("SUCCESS: Connected to MySQL.")
            print(f"Database: {database}")
            print(f"MySQL version: {version}")
        finally:
            conn.close()
    except mysql.connector.Error as exc:
        print("FAILED: SmartHostel could not connect to MySQL.")
        print(f"Details: {exc}")
        print("Check MySQL Workbench > Edit Connection > Port, then make DB_PORT in .env match exactly.")
        print("If the error says connection refused (10061), the server is not listening at that host/port; changing the password will not fix it.")
        print("If .env is missing, copy .env.example to .env and edit it before retrying.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
