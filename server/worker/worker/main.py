import os, time

API_URL = os.getenv("API_URL", "http://api:8000")
POLL_S = float(os.getenv("WORKER_POLL_S", "3"))

def main():
    print("gmf-worker starting (stub loop)")
    while True:
        # TODO: dequeue submitted results, run verification, update DB
        time.sleep(POLL_S)

if __name__ == "__main__":
    main()
