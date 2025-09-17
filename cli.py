import asyncio
import asyncpg
import typer
from sqlalchemy import text

from app.models import Base
from app.session import engine
from settings import DATABASE_URL, DB_NAME

app = typer.Typer()


async def _create_database():
    system_db_url = DATABASE_URL.replace('+asyncpg', '')
    system_db_url = system_db_url.rsplit('/', 1)[0] + '/postgres'
    conn = None
    try:
        conn = await asyncpg.connect(dsn=system_db_url)
        await conn.execute(f'CREATE DATABASE "{DB_NAME}"')
        typer.secho(f'Database {DB_NAME} created successfully!', fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f'Error creating database: {e}', err=True, fg=typer.colors.RED)
        raise typer.Exit(1)
    finally:
        if conn:
            await conn.close()


async def _create_tables():
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        typer.secho('Tables created successfully.', fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f'Error creating tables: {e}', err=True, fg=typer.colors.RED)
        raise typer.Exit(1)


async def _drop_tables():
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        typer.secho('Tables dropped successfully!', fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f'Error dropping tables: {e}', err=True, fg=typer.colors.RED)
        raise typer.Exit(1)


async def _check_connection():
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            result.fetchone()
        typer.secho('Database connection successful!', fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f'Database connection failed: {e}', err=True, fg=typer.colors.RED)
        raise typer.Exit(1)


@app.command()
def create_db():
    """Create the PostgreSQL database."""
    asyncio.run(_create_database())


@app.command()
def create_tables():
    """Create all tables in the database."""
    asyncio.run(_create_tables())


@app.command()
def drop_tables():
    """Drop all tables in the database."""
    asyncio.run(_drop_tables())


@app.command()
def check_connection():
    """Check database connection."""
    asyncio.run(_check_connection())


@app.command()
def init_db():
    """Initialize database (create database and tables)."""

    async def _init():
        await _create_database()
        await _create_tables()
        typer.secho('Database initialization completed!', fg=typer.colors.GREEN)

    asyncio.run(_init())


@app.command()
def reset_db():
    """Reset database (drop and recreate everything)."""

    async def _reset():
        await _drop_tables()
        await _create_tables()
        typer.secho('Database reset completed!', fg=typer.colors.GREEN)

    asyncio.run(_reset())


if __name__ == '__main__':
    app()
