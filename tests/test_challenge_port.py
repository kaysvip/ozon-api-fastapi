"""
Python 移植 vs JS 参考实现的差分测试。

覆盖整条链路：挑战页解析 -> 字节码走位 -> 工作量证明 -> CRC32/browser_2
-> fp 组装 -> XOR -> KDF 加密。两侧喂同一份输入，产物必须逐字节一致。

需要 node + crypto-js：cd tests/reference && npm install
"""

import json
import random
import subprocess

import pytest

from services.ozon_challenge.dynamic import build_dynamic
from services.ozon_challenge.fingerprint import apply_profile, build_fp, load_fp_base
from services.ozon_challenge.page import parse_page, read_browser2_template
from services.ozon_challenge.profile import BASELINE_PROFILE
from services.ozon_challenge.proof import build_browser_2, crc32, solve_pow
from tests import fixture_builder as fb
from tests.conftest import REFERENCE_DIR, requires_node

HREF = "https://www.ozon.ru/product/some-thing-2857830919/?__rr=2"
N_CASES = 40


@pytest.fixture(scope="module")
def page_fixture():
    return fb.build_page()


@pytest.fixture(scope="module")
def bytecode_cases():
    return fb.build_bytecode_cases()


@pytest.fixture(scope="module")
def cases():
    """每个 case 钉死 random_key 与 KDF salt，两侧才可比对"""
    out = []
    for i in range(N_CASES):
        r = random.Random(1000 + i)
        out.append({
            "dyn": build_dynamic(pow_ms=r.randint(1, 900),
                                 collect_start=1770000000000 + i * 7919, rng=r),
            "random_key": r.random(),
            "salt_hex": bytes(r.randrange(256) for _ in range(8)).hex(),
        })
    return out


@pytest.fixture(scope="module")
def reference(page_fixture, bytecode_cases, cases, tmp_path_factory):
    payload = {
        "html": page_fixture["html"],
        "href": HREF,
        "user_agent": BASELINE_PROFILE.user_agent,
        "template": page_fixture["template"],
        "cases": cases,
        "bytecode_scripts": [c["script"] for c in bytecode_cases],
    }
    path = tmp_path_factory.mktemp("ref") / "input.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    proc = subprocess.run(["node", "run_ref.js", str(path)],
                          cwd=REFERENCE_DIR, capture_output=True, text=True)
    assert proc.returncode == 0, f"参考实现执行失败:\n{proc.stderr}"
    return json.loads(proc.stdout)


# ── 不需要 Node 的不变量 ──

def test_baseline_profile_is_identity_on_fp_base():
    """
    底板档案套用到 fp_base 必须是恒等变换。
    这条守住了「随机档案改写的字段」和「底板实际结构」不会悄悄错位。
    """
    base = load_fp_base()
    probe = load_fp_base()
    apply_profile(probe, BASELINE_PROFILE)

    # user_agent 在底板里是 null 占位符，运行时才填
    assert base.pop("user_agent") is None
    assert probe.pop("user_agent") == BASELINE_PROFILE.user_agent
    assert probe == base


def test_parse_page_finds_everything(page_fixture):
    page = parse_page(page_fixture["html"])
    assert page.challenge == page_fixture["challenge"]
    assert page.template == page_fixture["template"]
    assert page.script_line > 0
    assert all(c > 0 for c in page.cols), f"栈帧列号没全找到: {page.cols}"


def test_bytecode_walker_finds_expected(bytecode_cases):
    for i, c in enumerate(bytecode_cases):
        got = read_browser2_template(c["script"])
        assert (got is not None) == c["has_template"], f"case {i}: {got!r}"


def test_pow_satisfies_difficulty(page_fixture):
    from services.ozon_challenge.proof import challenge_difficulty, _leading_zero_bits_ok
    import hashlib

    page = parse_page(page_fixture["html"])
    res = solve_pow(page)
    dis = challenge_difficulty(res.token)
    digest = hashlib.md5(f"{res.pzs}{res.pzc}".encode()).digest()
    assert _leading_zero_bits_ok(digest, dis), "PoW 结果不满足难度要求"
    # 必须是最小的 n
    for n in range(res.pzc):
        assert not _leading_zero_bits_ok(
            hashlib.md5(f"{res.pzs}{n}".encode()).digest(), dis), f"{n} 才是更小的解"


# ── 与 JS 参考实现逐字节比对 ──

@requires_node
def test_page_parsing_matches(reference, page_fixture):
    page = parse_page(page_fixture["html"])
    assert page.challenge == reference["page"]["challenge"]
    assert page.script_line == reference["page"]["scriptLine"]
    assert page.cols == reference["page"]["cols"]
    assert page.template == reference["page"]["template"]


@requires_node
def test_bytecode_walker_matches(reference, bytecode_cases):
    ours = [read_browser2_template(c["script"]) for c in bytecode_cases]
    assert ours == reference["bytecode"]


@requires_node
def test_pow_matches(reference, page_fixture):
    res = solve_pow(parse_page(page_fixture["html"]))
    ref = reference["pow"]
    assert res.pzc == ref["pzc"]
    assert res.pzs == ref["pzs"]
    assert res.token == ref["token"]
    assert res.version == ref["version"]
    assert res.id == ref["id"]
    assert res.cols == ref["cols"]
    assert res.script_line == ref["scriptLine"]


@requires_node
def test_crc32_and_browser_2_match(reference, page_fixture):
    ua = BASELINE_PROFILE.user_agent
    assert crc32(ua + "3") == reference["crc32"]
    assert build_browser_2(page_fixture["template"], ua, "3") == reference["browser_2"]


@requires_node
def test_fp_ciphertext_matches(reference, page_fixture, cases):
    """最关键的一条：完整 fp 密文逐字节一致"""
    res = solve_pow(parse_page(page_fixture["html"]))
    for i, (case, ref_case) in enumerate(zip(cases, reference["cases"])):
        got = build_fp(res, BASELINE_PROFILE, HREF, case["dyn"],
                       random_key=case["random_key"],
                       salt=bytes.fromhex(case["salt_hex"]))
        assert got["fp"] == ref_case["fp"], f"case {i} 的 fp 密文不一致"
        assert got["token"] == ref_case["token"]
        assert got["browser_2"] == ref_case["browser_2"]
        assert got["timings"] == ref_case["timings"]
