"""Fire many transfers at the same instant (attacks A1 and A2 of docs/DECISIONS.md, E4).

    python scripts/race_transfers.py --base-url http://localhost:8080 --token <customer token> \
        --from-account <uuid> --to-account <uuid> --amount 100.00 -n 50 --expect-success 1

--same-key sends one Idempotency-Key in every request (A2: exactly one transfer may result).
Exit code 1 if more requests succeeded than --expect-success. Then check the ledger sums to zero
(reconciliation) and the balance never went negative.

Adjust PATH and the body fields if the API in docs/DECISIONS.md changes. Run it against your own
docker compose stack only, never against the platform before the freeze.
"""

import argparse
import collections
import sys
import threading
import uuid

import httpx

PATH = "/api/v1/transfers"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", required=True)
    p.add_argument("--token", required=True, help="bearer token of the account owner")
    p.add_argument("--from-account", required=True)
    p.add_argument("--to-account", required=True)
    p.add_argument("--amount", required=True, help='decimal string with 2 places, e.g. "100.00"')
    p.add_argument("-n", type=int, default=50, help="number of parallel requests")
    p.add_argument("--same-key", action="store_true", help="reuse one Idempotency-Key (replay test)")
    p.add_argument("--expect-success", type=int, default=1, help="most 2xx responses that are acceptable")
    args = p.parse_args()

    shared_key = str(uuid.uuid4())
    barrier = threading.Barrier(args.n)
    results: list[int | str] = []
    lock = threading.Lock()

    def fire() -> None:
        headers = {"Authorization": f"Bearer {args.token}", "Idempotency-Key": shared_key if args.same_key else str(uuid.uuid4())}
        body = {"from_account_id": args.from_account, "to_account_id": args.to_account, "amount": args.amount}
        with httpx.Client(base_url=args.base_url, timeout=30) as client:
            barrier.wait()  # all requests leave together
            try:
                status: int | str = client.post(PATH, json=body, headers=headers).status_code
            except httpx.HTTPError as exc:
                status = type(exc).__name__
        with lock:
            results.append(status)

    threads = [threading.Thread(target=fire) for _ in range(args.n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    histogram = collections.Counter(results)
    print("status codes:", dict(sorted(histogram.items(), key=lambda kv: str(kv[0]))))
    succeeded = sum(count for status, count in histogram.items() if isinstance(status, int) and 200 <= status < 300)
    server_errors = sum(count for status, count in histogram.items() if not isinstance(status, int) or status >= 500)
    print(f"{succeeded} succeeded (allowed {args.expect_success}), {server_errors} server errors or timeouts")
    if succeeded > args.expect_success:
        print("FAIL: more transfers went through than the balance or the idempotency key allows")
        return 1
    if server_errors:
        print("WARN: server errors under load; check the logs for ledger.deadlock or ledger.lock_timeout")
    return 0


if __name__ == "__main__":
    sys.exit(main())
