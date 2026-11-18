# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import contextlib
import enum
import logging
import struct
from typing import FrozenSet, Iterator, Optional, Union, cast

from volatility3.framework import constants, exceptions, interfaces, objects
from volatility3.framework.layers import registry

vollog = logging.getLogger(__name__)

BIG_DATA_MAXLEN = 0x3FD8

# Healthy hives nest at most a handful of index levels (ri -> ri -> lh) and
# key depths measured in the dozens, so a structure crossing these bounds is
# looping (self references or cycles) or was crafted to exhaust the
# interpreter stack.  Both limits keep traversal bounded without truncating
# any key that a real hive can produce.
MAX_KEY_INDEX_DEPTH = 64
MAX_KEY_PATH_DEPTH = 128

# Prepended to a key path whose parent chain looped or ran too deep, so that
# the partial result on its own cannot be mistaken for a complete path.
KEY_PATH_TRUNCATION_MARKER = "[Truncated]"


class RegValueTypes(enum.Enum):
    REG_NONE = 0
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_BINARY = 3
    REG_DWORD = 4
    REG_DWORD_BIG_ENDIAN = 5
    REG_LINK = 6
    REG_MULTI_SZ = 7
    REG_RESOURCE_LIST = 8
    REG_FULL_RESOURCE_DESCRIPTOR = 9
    REG_RESOURCE_REQUIREMENTS_LIST = 10
    REG_QWORD = 11
    REG_UNKNOWN = 99999

    @classmethod
    def _missing_(cls, value):
        return cls(RegValueTypes.REG_UNKNOWN)


INTEGER_TYPES = [
    RegValueTypes.REG_DWORD,
    RegValueTypes.REG_QWORD,
    RegValueTypes.REG_DWORD_BIG_ENDIAN,
    RegValueTypes.REG_DWORD_BIG_ENDIAN,
]

STRING_TYPES = [
    RegValueTypes.REG_SZ,
    RegValueTypes.REG_MULTI_SZ,
    RegValueTypes.REG_EXPAND_SZ,
    RegValueTypes.REG_LINK,
]

BINARY_TYPES = [
    RegValueTypes.REG_RESOURCE_LIST,
    RegValueTypes.REG_BINARY,
    RegValueTypes.REG_FULL_RESOURCE_DESCRIPTOR,
    RegValueTypes.REG_RESOURCE_REQUIREMENTS_LIST,
    RegValueTypes.REG_NONE,
]


class RegKeyFlags(enum.IntEnum):
    KEY_IS_VOLATILE = 0x01
    KEY_HIVE_EXIT = 0x02
    KEY_HIVE_ENTRY = 0x04
    KEY_NO_DELETE = 0x08
    KEY_SYM_LINK = 0x10
    KEY_COMP_NAME = 0x20
    KEY_PREFEF_HANDLE = 0x40
    KEY_VIRT_MIRRORED = 0x80
    KEY_VIRT_TARGET = 0x100
    KEY_VIRTUAL_STORE = 0x200


class HMAP_ENTRY(objects.StructType):
    def get_block_offset(self) -> int:
        try:
            return (
                self.PermanentBinAddress ^ (self.PermanentBinAddress & 0xF)
            ) + self.BlockOffset
        except AttributeError:
            return self.BlockAddress


class CMHIVE(objects.StructType):
    def is_valid(self) -> bool:
        """Determine if the object is valid."""
        try:
            return self.Hive.Signature == 0xBEE0BEE0
        except exceptions.InvalidAddressException:
            return False

    def get_name(self) -> Optional[interfaces.objects.ObjectInterface]:
        """Determine a name for the hive.

        Note that some attributes are unpredictably blank across
        different OS versions while others are populated, so we check
        all possibilities and take the first one that's not empty
        """

        for attr in ["FileFullPath", "FileUserName", "HiveRootPath"]:
            with contextlib.suppress(
                AttributeError,
                exceptions.InvalidAddressException,
                registry.RegistryException,
            ):
                name = getattr(self, attr)
                if name.Length > 0:
                    return name.get_string()

        return None

    name = property(get_name)


class CM_KEY_BODY(objects.StructType):
    """This represents an open handle to a registry key and is not tied to the
    registry hive file format on disk."""

    def _skip_key_hive_entry_path(self, kcb_flags):
        """Win10 14393 introduced an extra path element that it skips over by
        checking for Flags that contain KEY_HIVE_ENTRY."""

        # _CM_KEY_BODY.Trans introduced in Win10 14393
        if (
            hasattr(self, "Trans")
            and RegKeyFlags.KEY_HIVE_ENTRY & kcb_flags == RegKeyFlags.KEY_HIVE_ENTRY
        ):
            return True

        return False

    def get_full_key_name(self) -> str:
        output = []
        seen = set()

        kcb = self.KeyControlBlock
        while kcb.ParentKcb:
            if kcb.ParentKcb.vol.offset in seen:
                return None
            seen.add(kcb.ParentKcb.vol.offset)

            if len(output) > 128:
                return None

            if kcb.NameBlock.Name is None:
                break

            if self._skip_key_hive_entry_path(kcb.Flags):
                kcb = kcb.ParentKcb
                if not kcb:
                    break

            output.append(
                kcb.NameBlock.Name.cast(
                    "string",
                    encoding="utf8",
                    max_length=kcb.NameBlock.NameLength,
                    errors="replace",
                )
            )
            kcb = kcb.ParentKcb
        return "\\".join(reversed(output))


class CM_KEY_NODE(objects.StructType):
    """Extension to allow traversal of registry keys."""

    def get_volatile(self) -> bool:
        """
        Returns a bool indicating whether or not the key is volatile.

        Raises TypeError if the key was not instantiated on a RegistryHive layer
        """
        if not isinstance(
            self._context.layers[self.vol.layer_name], registry.RegistryHive
        ):
            raise TypeError("CM_KEY_NODE was not instantiated on a RegistryHive layer")
        return bool(self.vol.offset & 0x80000000)

    def get_subkeys(self) -> Iterator["CM_KEY_NODE"]:
        """Returns a list of the key nodes.

        Raises TypeError if the key was not instantiated on a RegistryHive layer
        """
        hive = self._context.layers[self.vol.layer_name]
        if not isinstance(hive, registry.RegistryHive):
            raise TypeError("CM_KEY_NODE was not instantiated on a RegistryHive layer")
        for index in range(2):
            # Use get_cell because it should *always* be a KeyIndex
            subkey_node = hive.get_cell(self.SubKeyLists[index]).u.KeyIndex
            yield from self._get_subkeys_recursive(hive, subkey_node)

    def _get_subkeys_recursive(
        self,
        hive: "registry.RegistryHive",
        node: interfaces.objects.ObjectInterface,
        seen: Optional[FrozenSet[int]] = None,
        depth: int = 0,
    ) -> Iterator["CM_KEY_NODE"]:
        """Recursively descend a node returning subkeys.

        Index cells can reference themselves or form cycles, either through
        corruption or deliberately crafted structures, so each index node is
        descended into at most once and the descent is capped.  Without those
        two guards a cycle recurses until the interpreter stack is exhausted,
        and a RecursionError is not a RegistryException, so it escapes every
        caller's error handling.

        Args:
            hive: The registry hive the nodes belong to
            node: The index (or key) node to descend
            seen: Offsets of the index nodes already descended into
            depth: Number of index levels descended so far
        """
        # The keylist appears to include 4 bytes of key name after each value
        # We can either double the list and only use the even items, or
        # We could change the array type to a struct with both parts
        if seen is None:
            seen = frozenset()
        try:
            signature = node.cast("string", max_length=2, encoding="latin-1")
        except (
            exceptions.InvalidAddressException,
            registry.RegistryException,
        ):
            return None

        listjump = None
        if signature == "ri":
            listjump = 1
        elif signature == "lh" or signature == "lf":
            listjump = 2
        elif node.vol.type_name.endswith(constants.BANG + "_CM_KEY_NODE"):
            yield cast("CM_KEY_NODE", node)
        else:
            vollog.debug(
                f"Unexpected node type encountered when traversing subkeys: {node.vol.type_name}, signature: {signature}"
            )

        if listjump:
            node_offset = node.vol.offset
            if node_offset in seen:
                vollog.debug(
                    f"Loop detected in the key index at {hex(node_offset)}, not descending any further"
                )
                return None
            if depth >= MAX_KEY_INDEX_DEPTH:
                vollog.debug(
                    f"Key index at {hex(node_offset)} exceeds the maximum index depth "
                    f"of {MAX_KEY_INDEX_DEPTH}, not descending any further"
                )
                return None
            seen = seen | {node_offset}
            node.List.count = node.Count * listjump
            for subnode_offset in node.List[::listjump]:
                if (subnode_offset & 0x7FFFFFFF) > hive.maximum_address:
                    vollog.log(
                        constants.LOGLEVEL_VVV,
                        f"Node found with address outside the valid Hive size: {hex(subnode_offset)}",
                    )
                else:
                    try:
                        subnode = hive.get_node(subnode_offset)
                    except (
                        exceptions.InvalidAddressException,
                        registry.RegistryException,
                    ):
                        vollog.log(
                            constants.LOGLEVEL_VVV,
                            f"Failed to get node at {hex(subnode_offset)}, skipping",
                        )
                        continue
                    yield from self._get_subkeys_recursive(
                        hive, subnode, seen=seen, depth=depth + 1
                    )

    def get_values(self) -> Iterator["CM_KEY_VALUE"]:
        """Returns a list of the Value nodes for a key.

        Raises TypeError if the key was not instantiated on a RegistryHive layer
        """
        hive = self._context.layers[self.vol.layer_name]
        if not isinstance(hive, registry.RegistryHive):
            raise TypeError("CM_KEY_NODE was not instantiated on a RegistryHive layer")

        try:
            child_list = hive.get_cell(self.ValueList.List).u.KeyList
            child_list.count = self.ValueList.Count

            for v in child_list:
                if v != 0:
                    try:
                        node = hive.get_node(v)
                    except (registry.RegistryException,) as excp:
                        vollog.debug(f"Invalid address {excp}")
                        continue
                    if isinstance(node, CM_KEY_VALUE):
                        yield node

        except (
            exceptions.InvalidAddressException,
            registry.RegistryException,
        ) as excp:
            vollog.debug(f"Invalid address in get_values iteration: {excp}")
            return None

    def get_name(self) -> interfaces.objects.ObjectInterface:
        """Gets the name for the current key node"""
        namelength = self.NameLength
        self.Name.count = namelength
        return self.Name.cast("string", max_length=namelength, encoding="latin-1")

    def get_key_path(self) -> str:
        """
        Returns the full path to this registry key.

        The parent chain is walked with a seen set and a depth cap, matching
        the loop protection used by CM_KEY_BODY.get_full_key_name.  A crafted
        or corrupt hive can point a key at itself (or build a parent cycle),
        which would otherwise recurse until the interpreter stack is
        exhausted.  A looping chain is cut off and the partial path is
        returned with KEY_PATH_TRUNCATION_MARKER in place of the missing
        ancestors, so the caller still gets a string it can display.

        Raises TypeError if the key was not instantiated on a RegistryHive layer
        """
        reg = self._context.layers[self.vol.layer_name]
        if not isinstance(reg, registry.RegistryHive):
            raise TypeError("Key was not instantiated on a RegistryHive layer")
        # Using the offset adds a significant delay (since it cannot be cached easily)
        # if self.vol.offset == reg.get_node(reg.root_cell_offset).vol.offset:
        root_offset = reg.root_cell_offset + 4
        names = []
        seen = set()
        node = self
        while True:
            node_offset = node.vol.offset
            if node_offset == root_offset:
                # The hive name takes the place of the root entry's own name
                names.append(reg.get_name().split("\\")[-1])
                break
            if node_offset in seen or len(names) >= MAX_KEY_PATH_DEPTH:
                vollog.debug(
                    f"Loop detected walking the parent chain at {hex(node_offset)}, "
                    f"truncating the key path after {len(names)} levels"
                )
                names.append(KEY_PATH_TRUNCATION_MARKER)
                break
            seen.add(node_offset)
            names.append(node.get_name())
            node = reg.get_node(node.Parent)
        return "\\".join(reversed(names))


class CM_KEY_VALUE(objects.StructType):
    """Extensions to extract data from CM_KEY_VALUE nodes."""

    def get_name(self) -> interfaces.objects.ObjectInterface:
        """Gets the name for the current key value"""
        namelength = self.NameLength
        self.Name.count = namelength
        return self.Name.cast("string", max_length=namelength, encoding="latin-1")

    def get_type(self) -> RegValueTypes:
        """Get the type of the registry value"""
        return RegValueTypes(self.Type)

    def decode_data(self) -> Union[int, bytes]:
        """
        Properly decodes the data associated with the value node.

        If an InvalidAddressException occurs when reading data from the
        underlying RegistryHive layer, the data will be padded with null bytes
        of the same length.

        Raises ValueError if the data cannot be read
        Raises TypeError if the class was not instantiated on a RegistryHive layer
        """
        # Determine if the data is stored inline
        datalen = self.DataLength
        data = b""
        # Check if the data is stored inline
        layer = self._context.layers[self.vol.layer_name]
        if not isinstance(layer, registry.RegistryHive):
            raise TypeError("Key value was not instantiated on a RegistryHive layer")

        # If the high-bit is set
        if datalen & 0x80000000:
            # Remove the high bit
            datalen = datalen & 0x7FFFFFFF
            if 0 > datalen or datalen > 4:
                raise ValueError(
                    f"Unable to read inline registry value with excessive length: {datalen}"
                )
            else:
                data = layer.read(self.Data.vol.offset, datalen)
        elif layer.hive.Version == 5 and datalen > 0x4000:
            # We're bigdata
            big_data = layer.get_node(self.Data).cast("_CM_BIG_DATA")
            # Oddly, we get a list of addresses, at which are addresses, which then point to data blocks
            for i in range(big_data.Count):
                # The value 4 should actually be unsigned-int.size, but since it's a file format that shouldn't change
                # the direct value 4 can be used instead
                block_offset = layer.get_cell(big_data.List + (i * 4)).cast(
                    "unsigned int"
                )
                if (
                    isinstance(block_offset, int)
                    and block_offset < layer.maximum_address
                ):
                    amount = min(BIG_DATA_MAXLEN, datalen)
                    try:
                        data += layer.read(
                            offset=layer.get_cell(block_offset).vol.offset,
                            length=amount,
                        )
                    except (
                        exceptions.InvalidAddressException,
                        registry.RegistryException,
                    ):
                        vollog.debug(
                            f"Failed to read {amount:x} bytes of data, padding with {amount:x}"
                        )
                    datalen -= amount
        else:
            # Suspect Data actually points to a Cell,
            # but the length at the start could be negative so just adding 4 to jump past it
            try:
                data = layer.read(self.Data + 4, datalen)
            except (exceptions.InvalidAddressException, registry.RegistryException):
                vollog.debug(
                    f"Failed to read {datalen:x} bytes of data, returning {datalen:x} null bytes"
                )
                data = b"\x00" * datalen

        if self.get_type() == RegValueTypes.REG_DWORD:
            if len(data) != struct.calcsize("<L"):
                raise ValueError(
                    f"Size of data does not match the type of registry value {self.get_name()}"
                )
            (res,) = struct.unpack("<L", data)
            return res
        if self.get_type() == RegValueTypes.REG_DWORD_BIG_ENDIAN:
            if len(data) != struct.calcsize(">L"):
                raise ValueError(
                    f"Size of data does not match the type of registry value {self.get_name()}"
                )
            (res,) = struct.unpack(">L", data)
            return res
        if self.get_type() == RegValueTypes.REG_QWORD:
            if len(data) != struct.calcsize("<Q"):
                raise ValueError(
                    f"Size of data does not match the type of registry value {self.get_name()}"
                )
            (res,) = struct.unpack("<Q", data)
            return res
        if self.get_type() in [
            RegValueTypes.REG_SZ,
            RegValueTypes.REG_EXPAND_SZ,
            RegValueTypes.REG_LINK,
            RegValueTypes.REG_MULTI_SZ,
            RegValueTypes.REG_BINARY,
            RegValueTypes.REG_FULL_RESOURCE_DESCRIPTOR,
            RegValueTypes.REG_RESOURCE_LIST,
            RegValueTypes.REG_RESOURCE_REQUIREMENTS_LIST,
        ]:
            return data
        if self.get_type() == RegValueTypes.REG_NONE:
            return b""

        # Fall back if it's something weird
        vollog.debug(f"Unknown registry value type encountered: {self.Type}")
        return data
