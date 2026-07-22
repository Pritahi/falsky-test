"""
Falsky — Seed 20 CI runs with realistic flaky/stable/broken test data.
"""
import sys, os, random, xml.etree.ElementTree as ET
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from engine.trust_engine import process_test_run, get_dashboard_data, get_quarantined_tests

random.seed(42)
REPO = "test-org/sample-project"

def make_junit(tests):
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite", name="pytest", tests=str(len(tests)))
    for t in tests:
        attrs = {"name": t["name"], "classname": t.get("classname", "tests"), "time": str(t["duration"])}
        tc = ET.SubElement(suite, "testcase", **attrs)
        if t["status"] == "failed":
            ET.SubElement(tc, "failure", message=t.get("error_msg", "AssertionError"))
        elif t["status"] == "skipped":
            ET.SubElement(tc, "skipped")
    return ET.tostring(root, encoding="unicode")

def gen_run(n):
    tests = []
    # Flaky: timing (~65% pass)
    dur = round(random.uniform(0.1, 5.0), 2) if random.random() < 0.65 else round(random.uniform(5.0, 30.0), 2)
    st = "passed" if random.random() < 0.65 else "failed"
    tests.append({"name": "test_api_response_time", "classname": "tests.test_api", "status": st, "duration": dur,
        "error_msg": "AssertionError: Expected response in <2000ms, got 12340ms" if st == "failed" else ""})
    # Flaky: shared_state (~70% pass)
    st = "passed" if random.random() < 0.70 else "failed"
    tests.append({"name": "test_database_connection_pool", "classname": "tests.test_db", "status": st,
        "duration": round(random.uniform(0.5, 2.0), 2), "error_msg": "OperationalError: database is locked" if st == "failed" else ""})
    # Flaky: order_dependency
    st = "passed" if n % 2 == 0 else "failed"
    tests.append({"name": "test_user_auth_flow", "classname": "tests.test_auth", "status": st,
        "duration": round(random.uniform(0.3, 1.5), 2), "error_msg": "AssertionError: User session not found" if st == "failed" else ""})
    # Flaky: non_deterministic_data (~60% pass, random errors)
    st = "passed" if random.random() < 0.60 else "failed"
    errs = ["KeyError: 'timestamp'", "TypeError: expected str, got None", "ValueError: invalid literal", "AttributeError: 'NoneType'"]
    tests.append({"name": "test_data_pipeline_transform", "classname": "tests.test_pipeline", "status": st,
        "duration": round(random.uniform(1.0, 3.0), 2), "error_msg": random.choice(errs) if st == "failed" else ""})
    # Stable
    for nm in ["test_utils_format_date", "test_utils_parse_json", "test_utils_validate_email"]:
        tests.append({"name": nm, "classname": "tests.test_utils", "status": "passed", "duration": round(random.uniform(0.01, 0.1), 3), "error_msg": ""})
    # Broken
    tests.append({"name": "test_deprecated_endpoint", "classname": "tests.test_api", "status": "failed",
        "duration": round(random.uniform(0.5, 1.0), 2), "error_msg": "ConnectionRefusedError: Connection refused to localhost:9000"})
    return tests

def main():
    print("Seeding 20 CI runs...")
    for i in range(1, 21):
        xml = make_junit(gen_run(i))
        r = process_test_run(xml_content=xml, repo_name=REPO, run_id=f"ci_run_{i:03d}", branch="main", commit_sha=f"abc{i:04d}x"*6)
        print(f"  Run {i:2d}: {r['passed']}p {r['failed']}f | trust: {r['avg_trust_score']}%")
    print("\nFlaky tests:")
    for t in get_dashboard_data(REPO)['flaky_tests']:
        print(f"  {t['test_name']} — trust: {round(t['trust_score'])}, cat: {t['flaky_category']}")
    print("Done!")

if __name__ == "__main__":
    main()