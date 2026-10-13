"""Reproduce tests, labelled micro-corpus results and fixture benchmark.

These measurements describe the bundled synthetic data, not Juice Shop.
"""
import io
import json
import platform
import statistics
import threading
import time
import unittest
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from juicesec.core import analyze_source, scan, html_report
from tests.fixture_server import Fixture

ROOT=Path(__file__).resolve().parent
PY_IDS={"H-DES-A","H-XXE-A","H-XXE-B"}


def measure(items, suffix=".js"):
    """Score the analyzer over a corpus, returning the confusion matrix and rows."""
    matrix={"tp":0,"fp":0,"tn":0,"fn":0};records=[]
    for item in items:
        name=item["id"]+(".py" if item["id"] in PY_IDS else suffix)
        findings=analyze_source(item["source"],name)
        predicted=bool(findings);actual=item["positive"]
        category=("tp" if actual else "fp") if predicted else ("fn" if actual else "tn")
        matrix[category]+=1
        records.append(dict(item,predicted=predicted,category=category,rule_ids=[f["rule_id"] for f in findings]))
    return matrix,records


def main():
    out=ROOT/"evidence";out.mkdir(exist_ok=True)
    stream=io.StringIO()
    suite=unittest.defaultTestLoader.discover(str(ROOT/"tests"))
    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    (out/"tests.txt").write_text(stream.getvalue(),encoding="utf-8")
    corpus=json.loads((ROOT/"data"/"corpus.json").read_text(encoding="utf-8"))
    holdout=json.loads((ROOT/"data"/"holdout.json").read_text(encoding="utf-8"))
    matrix,records=measure(corpus)
    hold_matrix,hold_records=measure(holdout)

    def metrics(m):
        tp,fp,tn,fn=[m[k] for k in ("tp","fp","tn","fn")]
        precision=tp/(tp+fp) if tp+fp else None
        recall=tp/(tp+fn) if tp+fn else None
        return {"count":tp+fp+tn+fn,**m,"precision":precision,"recall":recall,
                "f1":2*precision*recall/(precision+recall) if precision and recall else None}

    server=ThreadingHTTPServer(("127.0.0.1",0),Fixture)
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    target=f"http://127.0.0.1:{server.server_port}"
    try:
        scan(target)  # one excluded warm-up
        timings=[]
        for _ in range(20):
            start=time.perf_counter();sample=scan(target);timings.append((time.perf_counter()-start)*1000)
        active=scan(target,True)
    finally:
        server.shutdown();server.server_close();worker.join()
    summary={"generated_at":datetime.now(timezone.utc).isoformat(),"python":platform.python_version(),
             "platform":platform.platform(),"scope":"Synthetic fixtures only; Juice Shop not executed",
             "engine":"line_regex + stdlib-AST taint union (see juicesec/astscan.py)",
             "unit_tests":{"run":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),"successful":result.wasSuccessful()},
             "corpus":metrics(matrix),"holdout":metrics(hold_matrix),
             "benchmark":{"runs":20,"warmups_excluded":1,"requests_per_run":5,"unit":"ms",
                          "median":statistics.median(timings),"minimum":min(timings),"maximum":max(timings),
                          "p95_nearest_rank":sorted(timings)[18],"raw":timings}}
    for name,data in [("validation.json",summary),("corpus-results.json",records),
                      ("holdout-results.json",hold_records),("fixture-report.json",active)]:
        (out/name).write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding="utf-8")

    (out/"fixture-report.html").write_text(html_report(active),encoding="utf-8")
    print(json.dumps(summary,ensure_ascii=False,indent=2))
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__": main()
