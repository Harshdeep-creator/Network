from netdrive.sim.mesh import accept_notice, make_notice_key, propagate, purge_held, run_mesh, signed_notice
from netdrive.sim.mesh import Node
from netdrive.sim.radio import choose_path, path_report


def test_paths_and_mesh():
    assert choose_path(set()) == "lan"
    assert choose_path({"lan"}) == "hotspot"
    assert choose_path({"lan", "hotspot", "wifi-direct"}) == "ble-l2cap"
    assert "ble-gatt" in path_report()
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
    assert node.relay is False
