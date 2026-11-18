"""Loop and depth guards for the Windows registry key traversal.

Both key traversal paths in ``symbols/windows/extensions/registry.py`` used to
recurse with no loop protection: ``CM_KEY_NODE._get_subkeys_recursive`` follows
``ri``/``lh``/``lf`` index cells, and ``CM_KEY_NODE.get_key_path`` walks the
``Parent`` chain.  A corrupt or deliberately crafted hive could turn either into
an unbounded recursion, and because ``RecursionError`` derives from
``RuntimeError`` rather than ``VolatilityException``, it escaped the plugins'
controlled capture lists and aborted the whole run.
"""

from types import SimpleNamespace

from volatility3.framework import constants
from volatility3.framework.layers import registry as registry_layer
from volatility3.framework.symbols.windows.extensions import registry
from volatility3.plugins.windows.registry import hivelist, printkey

ROOT_CELL = 0x20


class FakeLayers:
    def __init__(self, layer):
        self._layer = layer

    def __getitem__(self, name):
        return self._layer


class FakeHive(registry_layer.RegistryHive):
    """Minimal stand-in for a RegistryHive, addressable by cell offset."""

    root_cell_offset = ROOT_CELL
    maximum_address = 0x7FFFFFFF

    def __init__(self, cells=None, name="HIVE"):
        self.cells = cells if cells is not None else {}
        self._name = name

    def get_node(self, cell_offset):
        return self.cells[cell_offset]

    def get_cell(self, cell_offset):
        # get_subkeys reaches through a cell union to its KeyIndex member
        return SimpleNamespace(u=SimpleNamespace(KeyIndex=self.cells[cell_offset]))

    def get_name(self):
        return self._name


def make_key(hive, cell_offset, name, parent=None):
    """Build a CM_KEY_NODE whose only real behaviour is its parent link."""
    node = object.__new__(registry.CM_KEY_NODE)
    node._vol = {
        "type_name": "nt" + constants.BANG + "_CM_KEY_NODE",
        "offset": cell_offset + 4,
        "layer_name": "hive",
    }
    node._context = SimpleNamespace(layers=FakeLayers(hive))
    node.get_name = lambda: name
    node.Parent = parent
    hive.cells[cell_offset] = node
    return node


class FakeIndexList:
    """Stands in for the Array member, which allows its count to be set."""

    def __init__(self, entries):
        self._entries = list(entries)
        self.count = len(entries)

    def __getitem__(self, index):
        return self._entries[index]


class FakeIndex:
    """Stand-in for a _CM_KEY_INDEX that reports a given signature."""

    def __init__(self, hive, cell_offset, signature, offsets):
        self.List = FakeIndexList(offsets)
        self.Count = len(offsets)
        self.vol = SimpleNamespace(
            type_name="nt" + constants.BANG + "_CM_KEY_INDEX",
            offset=cell_offset + 4,
            layer_name="hive",
        )
        self._signature = signature
        hive.cells[cell_offset] = self

    def cast(self, type_name, **kwargs):
        return self._signature


def make_key_node(hive, cell_offset, name):
    """Build a key node that can also be the target of a key index."""
    node = object.__new__(registry.CM_KEY_NODE)
    node._vol = {
        "type_name": "nt" + constants.BANG + "_CM_KEY_NODE",
        "offset": cell_offset + 4,
        "layer_name": "hive",
    }
    node._context = SimpleNamespace(layers=FakeLayers(hive))
    node.get_name = lambda: name
    # The real object reads the "nk" cell signature through cast()
    node.cast = lambda type_name, **kwargs: "nk"
    hive.cells[cell_offset] = node
    return node


def make_parent_key(hive, cell_offset, index_cells):
    """Return a key node whose two SubKeyLists point at the given cells."""
    key = object.__new__(registry.CM_KEY_NODE)
    key._vol = {
        "type_name": "nt" + constants.BANG + "_CM_KEY_NODE",
        "offset": cell_offset + 4,
        "layer_name": "hive",
    }
    key._context = SimpleNamespace(layers=FakeLayers(hive))
    key.SubKeyLists = list(index_cells)
    hive.cells[cell_offset] = key
    return key


class TestKeyPathLoopGuard:
    def test_self_parent_yields_truncated_path(self):
        """A key that is its own parent must not recurse into itself."""
        hive = FakeHive()
        node = make_key(hive, 0x100, "Loop", parent=0x100)

        path = node.get_key_path()

        assert path.endswith("Loop")
        assert path.startswith(registry.KEY_PATH_TRUNCATION_MARKER)

    def test_parent_cycle_yields_truncated_path(self):
        """Two keys pointing at each other must terminate."""
        hive = FakeHive()
        first = make_key(hive, 0x100, "First")
        make_key(hive, 0x200, "Second", parent=0x100)
        first.Parent = 0x200

        path = first.get_key_path()

        assert path.startswith(registry.KEY_PATH_TRUNCATION_MARKER)
        assert "First" in path

    def test_long_parent_chain_is_capped(self):
        """A chain longer than the depth cap truncates instead of overflowing."""
        hive = FakeHive()
        previous = ROOT_CELL
        deepest = None
        for index in range(registry.MAX_KEY_PATH_DEPTH + 20):
            cell_offset = 0x1000 + (index * 0x100)
            deepest = make_key(hive, cell_offset, f"K{index}", parent=previous)
            previous = cell_offset

        path = deepest.get_key_path()

        assert path.startswith(registry.KEY_PATH_TRUNCATION_MARKER)

    def test_healthy_parent_chain_is_unchanged(self):
        """A normal chain still produces the same fully qualified path."""
        hive = FakeHive()
        make_key(hive, ROOT_CELL, "ROOT")
        make_key(hive, 0x100, "Child", parent=ROOT_CELL)
        leaf = make_key(hive, 0x200, "Leaf", parent=0x100)

        assert leaf.get_key_path() == "HIVE\\Child\\Leaf"

    def test_root_node_path_is_hive_name(self):
        """The root node still resolves to the hive name alone."""
        hive = FakeHive(name="C:\\Windows\\System32\\config\\SYSTEM")
        root = make_key(hive, ROOT_CELL, "ROOT")

        assert root.get_key_path() == "SYSTEM"


class TestSubkeyIndexLoopGuard:
    def test_self_referencing_index_terminates(self):
        """An index root listing its own cell must not recurse forever."""
        hive = FakeHive()
        FakeIndex(hive, 0x100, "ri", [0x100])
        key = make_parent_key(hive, 0x300, [0x100, 0x200])
        FakeIndex(hive, 0x200, "ri", [])

        assert list(key.get_subkeys()) == []

    def test_mutually_referencing_indexes_terminate(self):
        """Two index roots pointing at each other must not recurse forever."""
        hive = FakeHive()
        FakeIndex(hive, 0x100, "ri", [0x200])
        FakeIndex(hive, 0x200, "ri", [0x100])
        key = make_parent_key(hive, 0x300, [0x100, 0x400])
        FakeIndex(hive, 0x400, "ri", [])

        assert list(key.get_subkeys()) == []

    def test_long_index_chain_is_capped(self):
        """An index chain deeper than the cap stops instead of overflowing."""
        hive = FakeHive()
        depth = registry.MAX_KEY_INDEX_DEPTH + 20
        for index in range(depth):
            cell_offset = 0x1000 + (index * 0x100)
            next_offset = 0x1000 + ((index + 1) * 0x100)
            offsets = [next_offset] if index + 1 < depth else []
            FakeIndex(hive, cell_offset, "ri", offsets)
        key = make_parent_key(hive, 0x300, [0x1000, 0x400])
        FakeIndex(hive, 0x400, "ri", [])

        assert list(key.get_subkeys()) == []

    def test_healthy_indexes_yield_subkeys_in_order(self):
        """A well formed ri -> lf tree still yields every key in order."""
        hive = FakeHive()
        first = make_key_node(hive, 0x500, "Alpha")
        second = make_key_node(hive, 0x600, "Beta")
        # lf entries interleave the key name after each cell offset
        FakeIndex(hive, 0x400, "lf", [0x500, 0, 0x600, 0])
        FakeIndex(hive, 0x100, "ri", [0x400])
        key = make_parent_key(hive, 0x300, [0x100, 0x200])
        FakeIndex(hive, 0x200, "ri", [])

        assert list(key.get_subkeys()) == [first, second]

    def test_key_node_index_yields_the_node_itself(self):
        """An index that resolves straight to a key node yields that node."""
        hive = FakeHive()
        child = make_key_node(hive, 0x500, "Child")
        key = make_parent_key(hive, 0x300, [0x100, 0x200])
        hive.cells[0x100] = child
        FakeIndex(hive, 0x200, "ri", [])

        assert list(key.get_subkeys()) == [child]


class FakeWalkerNode:
    """Key node double for the printkey walker."""

    def __init__(self, offset, name, children=()):
        self.vol = SimpleNamespace(
            offset=offset,
            type_name="nt" + constants.BANG + "_CM_KEY_NODE",
            layer_name="hive",
        )
        self.LastWriteTime = SimpleNamespace(QuadPart=0)
        self._name = name
        self._children = list(children)

    def get_name(self):
        return self._name

    def get_volatile(self):
        return False

    def get_subkeys(self):
        return iter(self._children)

    def get_values(self):
        return iter(())


class TestPrintkeyDepthAndCapture:
    def test_key_iterator_caps_key_depth(self):
        """Recursion stops at the depth cap instead of descending further."""
        chain = [
            FakeWalkerNode(index, f"K{index}")
            for index in range(registry.MAX_KEY_PATH_DEPTH + 5)
        ]
        for parent, child in zip(chain, chain[1:]):
            parent._children = [child]

        results = list(
            printkey.PrintKey.key_iterator(
                FakeHive(), node_path=[chain[0]], recurse=True
            )
        )

        names = [node.get_name() for _, _, _, _, _, node in results]
        assert len(names) == registry.MAX_KEY_PATH_DEPTH
        assert names[:3] == ["K1", "K2", "K3"]
        assert names[-1] == f"K{registry.MAX_KEY_PATH_DEPTH}"

    def test_key_iterator_skips_ancestor_cycle(self):
        """A subkey equal to an ancestor is reported but never descended into."""
        root = FakeWalkerNode(0x100, "Root")
        child = FakeWalkerNode(0x200, "Child")
        root._children = [child]
        child._children = [root]
        sibling = FakeWalkerNode(0x300, "Sibling")
        root._children.append(sibling)

        results = list(
            printkey.PrintKey.key_iterator(FakeHive(), node_path=[root], recurse=True)
        )

        names = [node.get_name() for _, _, _, _, _, node in results]
        # The back reference is yielded once as Child's subkey, then dropped
        assert names == ["Child", "Root", "Sibling"]

    def test_walker_turns_recursion_error_into_a_row(self, monkeypatch):
        """A RecursionError from a hive must not abort the whole plugin run."""
        node = FakeWalkerNode(0, "Root")

        def raising_subkeys():
            raise RecursionError("maximum recursion depth exceeded")
            yield  # pragma: no cover - keeps this an iterator function

        node.get_subkeys = raising_subkeys

        class Hive:
            hive_offset = 0x1000
            root_cell_offset = ROOT_CELL

            def get_name(self):
                return "HIVE"

            def get_node(self, cell_offset):
                return node

            def get_key(self, key, return_list=False):
                return [node]

        monkeypatch.setattr(
            hivelist.HiveList,
            "list_hives",
            classmethod(lambda cls, **kwargs: iter([Hive()])),
        )

        plugin = object.__new__(printkey.PrintKey)
        plugin._context = SimpleNamespace()
        plugin._config_path = "plugins.PrintKey"
        plugin._config_cache = {"kernel": "kernel"}

        results = list(plugin._registry_walker(hive_offsets=None, key=None))

        assert len(results) == 1
        _depth, row = results[0]
        assert row[2] == "Key"
        assert row[3] == "HIVE\\"
