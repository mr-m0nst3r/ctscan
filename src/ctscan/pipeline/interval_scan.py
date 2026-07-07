"""Parallel interval scan grouped by CT operator."""

from __future__ import annotations

import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from rich.console import Console

from ctscan.pipeline.scanner import ScanOptions, Scanner
from ctscan.storage.db import Database


@dataclass(frozen=True)
class ScanLogTarget:
    uri: str
    label: str
    operator: str


def group_targets_by_operator(
    targets: list[ScanLogTarget],
) -> dict[str, list[ScanLogTarget]]:
    grouped: dict[str, list[ScanLogTarget]] = defaultdict(list)
    for target in targets:
        grouped[target.operator].append(target)
    return dict(sorted(grouped.items()))


def resolve_operator_concurrency(
    operator_count: int,
    concurrency: int | None,
) -> int:
    if operator_count <= 0:
        return 1
    if concurrency is None or concurrency <= 0:
        return operator_count
    return max(1, min(concurrency, operator_count))


class IntervalScanCoordinator:
    def __init__(
        self,
        db: Database,
        console: Console,
        *,
        session_id: int,
        global_target: int,
        global_known: set[str],
    ):
        self.db = db
        self.console = console
        self.session_id = session_id
        self.global_target = global_target
        self.global_known = global_known
        self.global_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.print_lock = threading.Lock()

        if len(self.global_known) >= global_target:
            self.stop_event.set()

    def global_hit_count(self) -> int:
        with self.global_lock:
            return len(self.global_known)

    def run_operator(
        self,
        operator: str,
        targets: list[ScanLogTarget],
        base_opts: ScanOptions,
    ) -> int:
        scanner = Scanner(db=self.db, console=self.console)
        local_new = 0
        for target in targets:
            if self.stop_event.is_set():
                break
            if self.db.get_completed_job_for_log_in_session(
                target.uri, self.session_id
            ):
                continue

            opts = ScanOptions(
                log_uri=target.uri,
                target_count=self.global_target,
                batch_size=base_opts.batch_size,
                delay=base_opts.delay,
                query=base_opts.query,
                job_query=base_opts.job_query,
                rules_file=base_opts.rules_file,
                nxdomain_mode=base_opts.nxdomain_mode,
                after_date=base_opts.after_date,
                save_cert=base_opts.save_cert,
                resume=base_opts.resume,
                verbose=base_opts.verbose,
                trust_env=base_opts.trust_env,
                proxy=base_opts.proxy,
                require_br_icann=base_opts.require_br_icann,
                session_id=self.session_id,
                global_known=self.global_known,
                global_lock=self.global_lock,
                stop_event=self.stop_event,
                global_target=self.global_target,
                operator_label=operator,
                log_label=target.label,
                quiet_done=True,
                print_lock=self.print_lock,
            )
            with self.print_lock:
                self.console.print(
                    f"[bold]{operator}[/] → {target.label}\n[dim]{target.uri}[/]"
                )
            before = self.global_hit_count()
            try:
                scanner.run(opts)
            except SystemExit:
                raise
            local_new += self.global_hit_count() - before
        return local_new

    def run(
        self,
        by_operator: dict[str, list[ScanLogTarget]],
        base_opts: ScanOptions,
        concurrency: int | None,
    ) -> int:
        if self.stop_event.is_set():
            self.console.print(
                f"[green]Session #{self.session_id} already has "
                f"{self.global_hit_count()} unique hit(s).[/]"
            )
            self.db.complete_running_jobs_for_session(self.session_id)
            self.db.complete_session(self.session_id)
            return self.global_hit_count()

        workers = resolve_operator_concurrency(len(by_operator), concurrency)
        self.console.print(
            f"Parallel scan: [bold]{workers}[/] operator worker(s), "
            f"[bold]{len(by_operator)}[/] operator(s), "
            f"session [cyan]#{self.session_id}[/], "
            f"unique target [bold]{self.global_target}[/] "
            f"({self.global_hit_count()} so far)\n"
        )

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self.run_operator, op, logs, base_opts): op
                for op, logs in by_operator.items()
            }
            for future in as_completed(futures):
                op = futures[future]
                try:
                    future.result()
                except SystemExit:
                    raise
                except Exception as exc:
                    with self.print_lock:
                        self.console.print(
                            f"[red]Operator {op} failed:[/] {exc}"
                        )

        total = self.global_hit_count()
        self.db.complete_running_jobs_for_session(self.session_id)
        self.db.complete_session(self.session_id)
        self.console.print(
            f"[green]Interval scan done.[/] {total} unique hit(s) "
            f"(session #{self.session_id}), database: {self.db.path}"
        )
        return total
