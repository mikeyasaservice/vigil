from services.reasoner.contracts import TriageOutput


def test_reasoner_cannot_invent_evidence_or_execute_actions() -> None:
    try:
        TriageOutput(("h",), ("foreign",), 0.8, (), ("propose:review",)).validate({"local"})
    except ValueError as exc:
        assert "evidence" in str(exc)
    else:
        raise AssertionError("foreign evidence should be refused")

    try:
        TriageOutput(("h",), (), 0.8, (), ("delete:everything",)).validate(set())
    except ValueError as exc:
        assert "proposal" in str(exc)
    else:
        raise AssertionError("executable action should be refused")
