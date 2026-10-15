"""S3 lists & heuristics suite (PRD 13.3)."""
from core.lists_check import ListsDB, check_lists
from helpers import load_json

FX = load_json("fixtures.json")


def db_with(disposable=(), blocklist=(), ok=True):
    db = ListsDB()
    db.disposable = set(disposable)
    db.blocklist = set(blocklist)
    db.ok = ok
    return db


def test_disposable_mailinator():
    stop, flags, dym, advice = check_lists(
        "x@mailinator.com", db=db_with(disposable={"mailinator.com"}))
    assert stop.code == "E301"


def test_disposable_bundled_file_has_50_plus():
    db = ListsDB()
    assert db.load() is True
    assert len(db.disposable) >= 50
    assert "mailinator.com" in db.disposable
    assert "tempmail.com" in db.disposable


def test_role_account():
    stop, *_ = check_lists("info@company.com", db=db_with())
    assert stop.code == "E303"


def test_role_accounts_all_listed():
    for role in ("admin", "support", "sales", "abuse", "postmaster", "noreply"):
        stop, *_ = check_lists(f"{role}@anything.io", db=db_with())
        assert stop.code == "E303", role


def test_typo_gmial():
    stop, flags, dym, advice = check_lists("user@gmial.com", db=db_with())
    assert stop.code == "E304"
    assert dym == "gmail.com"


def test_typo_table_from_fixtures():
    db = ListsDB()
    assert db.load()  # use the real bundled list, as the pipeline does
    for case in FX["lists"]:
        stop, flags, dym, advice = check_lists(case["input"], db=db)
        got = None if stop is None else stop.code
        assert got == case["code"], case["input"]
        if case.get("did_you_mean"):
            assert dym == case["did_you_mean"]


def test_blocklist_beats_everything():
    stop, *_ = check_lists("x@blocked.example",
                           db=db_with(blocklist={"blocked.example"}))
    assert stop.code == "E302"


def test_blocklist_full_address():
    stop, *_ = check_lists("spammy@ok.example",
                           db=db_with(blocklist={"spammy@ok.example"}))
    assert stop.code == "E302"


def test_free_provider_flag():
    stop, flags, dym, advice = check_lists("someone@gmail.com", db=db_with())
    assert stop is None
    assert "free_provider" in flags


def test_list_unavailable_e305():
    stop, *_ = check_lists("a@b.com", db=db_with(ok=False))
    assert stop.code == "E305"


def test_clean_address_passes():
    stop, flags, dym, advice = check_lists("someone@company.example",
                                           db=db_with())
    assert stop is None
    assert flags == []
