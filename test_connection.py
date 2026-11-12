import streamlit as st
from database import connect_to_database

try:
    connection = connect_to_database()

    st.success("DBGuard PostgreSQL connection successful!")

    with connection.cursor() as cursor:
        cursor.execute("SELECT current_database(), current_user;")
        result = cursor.fetchone()

    st.write("Database:", result[0])
    st.write("User:", result[1])

    connection.close()

except Exception as error:
    st.error(f"Connection failed: {error}")