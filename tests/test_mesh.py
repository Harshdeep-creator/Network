from netdrive.sim.mesh import Node, accept_notice, make_notice_key, propagate, purge_held, run_mesh, signed_notice
from netdrive.sim.radio import path_report


def test_mesh_relays_and_notices():
    loops, _count, blind = propagate()
    assert loops == 0 and blind
    assert run_mesh() == "mesh: 20 nodes, 0 loops, relays blind"
    private, public = make_notice_key()
    text, signature = signed_notice(private, b"board")
    assert accept_notice(public, text, signature)
    assert not accept_notice(public, text, None)
    node = Node()
    node.relay = False
    node.held.append((b"x", 0.0, 0.0))
    purge_held(node, now=13 * 3600)
    assert node.held == []
    report = path_report()
    assert "waited 10s after lan" in report
    assert "ble-gatt" in report
