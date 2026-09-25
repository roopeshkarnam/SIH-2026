import os

import psycopg
from dotenv import load_dotenv


# Load variables from .env
load_dotenv()

# Get database connection string
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL was not found in .env"
    )


print()
print("==========================================")
print(" SIH-2026 DATABASE CONNECTION TEST")
print("==========================================")
print()


try:
    with psycopg.connect(DATABASE_URL) as connection:

        with connection.cursor() as cursor:

            # Check database
            cursor.execute(
                "SELECT current_database();"
            )
            database = cursor.fetchone()[0]

            # Check current user
            cursor.execute(
                "SELECT current_user;"
            )
            user = cursor.fetchone()[0]

            # Check PostgreSQL version
            cursor.execute(
                "SELECT version();"
            )
            version = cursor.fetchone()[0]

            # Simple query test
            cursor.execute(
                "SELECT 1 + 1;"
            )
            result = cursor.fetchone()[0]

            print("DATABASE CONNECTION SUCCESSFUL")
            print("------------------------------------------")
            print(f"Database : {database}")
            print(f"User     : {user}")
            print(f"1 + 1    : {result}")
            print(f"Version  : {version}")
            print("------------------------------------------")
            print()
            print("PostgreSQL connection is working.")
            print()


except Exception as error:

    print("DATABASE CONNECTION FAILED")
    print("------------------------------------------")
    print(error)
    print("------------------------------------------")
    print()