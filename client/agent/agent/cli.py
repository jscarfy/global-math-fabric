import os, time, requests, typer

app = typer.Typer(no_args_is_help=True)

def api_url() -> str:
    return os.getenv("GMF_API", "http://localhost:8000")

@app.command()
def health():
    r = requests.get(f"{api_url()}/health", timeout=10)
    typer.echo(r.json())

@app.command()
def run(poll_s: float = 5.0):
    """
    Stub client loop: later will (1) lease tasks, (2) run sandbox, (3) report result.
    """
    typer.echo(f"gmf client running; API={api_url()}")
    while True:
        try:
            r = requests.get(f"{api_url()}/health", timeout=10)
            typer.echo(r.json())
        except Exception as e:
            typer.echo(f"health check failed: {e}")
        time.sleep(poll_s)
