import typer
from typing import Optional

app = typer.Typer()

@app.command()
def hunt(
    phone_number: str = typer.Argument(..., help="Target phone number in international format"),
    capture_time: int = typer.Option(5, "--seconds", "-t", help="Capture duration in seconds"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface to use")
):
    """Main IP hunting command"""
    typer.echo(f"Hunting IP for {phone_number}")

@app.command()
def interfaces():
    """List available network interfaces"""
    typer.echo("Listing network interfaces...")

if __name__ == "__main__":
    app()