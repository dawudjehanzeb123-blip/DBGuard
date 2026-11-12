
import psycopg
import streamlit as st
from psycopg.rows import dict_row


def connect_to_database():
    """Connect to the PostgreSQL database."""
    return psycopg.connect(
        **st.secrets["database"],
        row_factory=dict_row
    )


def initialise_database():
    """Create the audit history table if it does not exist."""
    with connect_to_database() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_history (
                    id SERIAL PRIMARY KEY,
                    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    action VARCHAR(100) NOT NULL,
                    username VARCHAR(255),
                    details TEXT
                )
            """)
        conn.commit()


def get_database_data():
    """Retrieve users and expected role permissions."""

    with connect_to_database() as conn:
        with conn.cursor() as cursor:

            cursor.execute("""
                SELECT
                    u.id,
                    u.username,
                    u.role,
                    COALESCE(
                        ARRAY_REMOVE(ARRAY_AGG(p.permission), NULL),
                        ARRAY[]::VARCHAR[]
                    ) AS permissions
                FROM app_users u
                LEFT JOIN user_permissions p
                    ON u.id = p.user_id
                GROUP BY u.id, u.username, u.role
                ORDER BY u.username
            """)

            users = cursor.fetchall()

            cursor.execute("""
                SELECT role, permission
                FROM role_permissions
                ORDER BY role, permission
            """)

            permission_rows = cursor.fetchall()

    expected_permissions = {}

    for row in permission_rows:
        role = row["role"]
        permission = row["permission"]

        if role not in expected_permissions:
            expected_permissions[role] = []

        expected_permissions[role].append(permission)

    return users, expected_permissions


def add_user(username, role, permissions):
    """Add a new user and their permissions."""

    with connect_to_database() as conn:
        with conn.cursor() as cursor:

            cursor.execute("""
                INSERT INTO app_users (username, role)
                VALUES (%s, %s)
                RETURNING id
            """, (username, role))

            user_id = cursor.fetchone()["id"]

            for permission in permissions:
                cursor.execute("""
                    INSERT INTO user_permissions (user_id, permission)
                    VALUES (%s, %s)
                """, (user_id, permission))

        conn.commit()


def update_user(old_username, username, role, permissions):
    """Update a user's details and permissions."""

    with connect_to_database() as conn:
        with conn.cursor() as cursor:

            cursor.execute("""
                SELECT id
                FROM app_users
                WHERE username = %s
            """, (old_username,))

            user = cursor.fetchone()

            if user is None:
                raise ValueError("User not found.")

            user_id = user["id"]

            cursor.execute("""
                UPDATE app_users
                SET username = %s, role = %s
                WHERE id = %s
            """, (username, role, user_id))

            cursor.execute("""
                DELETE FROM user_permissions
                WHERE user_id = %s
            """, (user_id,))

            for permission in permissions:
                cursor.execute("""
                    INSERT INTO user_permissions (user_id, permission)
                    VALUES (%s, %s)
                """, (user_id, permission))

        conn.commit()


def delete_user(username):
    """Delete a user and their permissions."""

    with connect_to_database() as conn:
        with conn.cursor() as cursor:

            cursor.execute("""
                SELECT id
                FROM app_users
                WHERE username = %s
            """, (username,))

            user = cursor.fetchone()

            if user is None:
                raise ValueError("User not found.")

            user_id = user["id"]

            cursor.execute("""
                DELETE FROM user_permissions
                WHERE user_id = %s
            """, (user_id,))

            cursor.execute("""
                DELETE FROM app_users
                WHERE id = %s
            """, (user_id,))

        conn.commit()


def record_change(action, username, details):
    """Save an activity to PostgreSQL audit history."""

    with connect_to_database() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO audit_history (action, username, details)
                VALUES (%s, %s, %s)
            """, (action, username, details))

        conn.commit()


def get_change_history():
    """Retrieve activity history, newest first."""

    with connect_to_database() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT time, action, username, details
                FROM audit_history
                ORDER BY time DESC, id DESC
            """)

            history = cursor.fetchall()

    return history
