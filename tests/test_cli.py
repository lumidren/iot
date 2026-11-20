from guardian.cli import main


def test_demo_prints_a_contained_attack(capsys):
    main(["demo", "--device", "plug-1", "--attack", "scan", "--learn-hours", "6"])
    out = capsys.readouterr().out
    assert "Network scanning" in out
    assert "Final tier: BLOCK" in out or "Final tier: QUARANTINE" in out


def test_export_then_check_a_capture(tmp_path, capsys):
    learn, check = tmp_path / "learn.pcap", tmp_path / "check.pcap"
    main(["export", str(learn), "--hours", "6", "--seed", "3"])
    main(["export", str(check), "--hours", "0.5", "--start-hour", "6", "--seed", "3",
          "--attack", "scan", "--device", "plug-1", "--attack-at", "10"])
    models = tmp_path / "models"
    main(["pcap", "--learn", str(learn), "--check", str(check),
          "--device", "plug=192.168.50.104", "--save-models", str(models)])
    out = capsys.readouterr().out
    assert "Wrote" in out and "alert(s)" in out
    assert "Network scanning" in out
    assert (models / "manifest.json").exists()
