"""MySQL helpers for SmartHostel."""
import os
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import pooling

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3307")),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", "root"),
    "database": os.getenv("DB_NAME", "smarthostel_management"),
    "connection_timeout": 5,
}
_pool = None


def get_pool():
    global _pool
    if _pool is None:
        _pool = pooling.MySQLConnectionPool(
            pool_name="smarthostel_pool", pool_size=5, **DB_CONFIG
        )
    return _pool


def get_conn():
    return get_pool().get_connection()


def query(sql, params=None, fetchone=False, commit=False):
    """Execute SQL safely and return dictionaries, inserted ID, or rows."""
    conn = get_conn()
    cur = None
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, params or ())
        if commit:
            conn.commit()
            return cur.lastrowid
        return cur.fetchone() if fetchone else cur.fetchall()
    except Exception:
        conn.rollback()
        raise
    finally:
        if cur is not None:
            cur.close()
        conn.close()


def allocate_room_safely(student_id, room_id):
    """Allocate only when both student and room remain eligible under row locks."""
    conn = get_conn()
    cur = None
    try:
        conn.start_transaction()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, lifecycle_status FROM students WHERE id=%s FOR UPDATE", (student_id,))
        student = cur.fetchone()
        if not student:
            raise ValueError("Selected student was not found.")
        if student.get("lifecycle_status") not in (None, "active"):
            raise ValueError("Archived or inactive students cannot be allocated to a room.")
        cur.execute("SELECT id, capacity, is_active FROM rooms WHERE id=%s FOR UPDATE", (room_id,))
        room = cur.fetchone()
        if not room:
            raise ValueError("Selected room was not found.")
        if not room.get("is_active", True):
            raise ValueError("This room is no longer active.")
        cur.execute("SELECT id FROM allocations WHERE student_id=%s AND is_active=TRUE LIMIT 1 FOR UPDATE", (student_id,))
        if cur.fetchone():
            raise ValueError("This student already has an active room.")
        cur.execute("SELECT COUNT(*) AS n FROM allocations WHERE room_id=%s AND is_active=TRUE", (room_id,))
        occupied = int(cur.fetchone()["n"] or 0)
        if occupied >= int(room["capacity"]):
            raise ValueError("Room is already full.")
        cur.execute("INSERT INTO allocations (student_id, room_id) VALUES (%s,%s)", (student_id, room_id))
        cur.execute("UPDATE rooms SET occupied=%s WHERE id=%s", (occupied + 1, room_id))
        conn.commit()
        return cur.lastrowid
    except Exception:
        conn.rollback()
        raise
    finally:
        if cur is not None:
            cur.close()
        conn.close()
