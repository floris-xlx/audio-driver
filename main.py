import argparse
import json
import winreg
from pycaw.pycaw import AudioUtilities
from pycaw.utils import AudioDeviceState
from colorama import init, Fore, Style

init(autoreset=True)


def get_registry_value(key, value_name):
    """Retrieve a value from the Windows registry key."""
    try:
        value, _ = winreg.QueryValueEx(key, value_name)
        return value
    except Exception:
        return None


def extract_device_info(inst_key):
    """Extract relevant device information from a registry key."""
    info = {}
    fields = {
        "driver": "Driver",
        "manufacturer": "Mfg",
        "description": "DeviceDesc",
        "service": "Service",
    }
    for key, reg_name in fields.items():
        value = get_registry_value(inst_key, reg_name)
        if value:
            info[key] = value
    return info


def device_instance_matches(inst_key, device_id):
    """Check if the registry device instance matches the given device_id."""
    reg_device_id = get_registry_value(inst_key, "DeviceInstanceId")
    return bool(reg_device_id and reg_device_id.lower() in device_id.lower())


def iter_subkeys(parent_key):
    """Yield all subkey names of a given registry key."""
    try:
        num_subkeys = winreg.QueryInfoKey(parent_key)[0]
        for i in range(num_subkeys):
            try:
                yield winreg.EnumKey(parent_key, i)
            except Exception:
                continue
    except Exception:
        return


def find_device_info_in_registry(enum_root, device_id):
    """Search the registry for device info matching the device_id."""
    for class_key_name in iter_subkeys(enum_root):
        try:
            class_key = winreg.OpenKey(enum_root, class_key_name)
        except Exception:
            continue
        with class_key:
            for subkey_name in iter_subkeys(class_key):
                try:
                    subkey = winreg.OpenKey(class_key, subkey_name)
                except Exception:
                    continue
                with subkey:
                    for inst_key_name in iter_subkeys(subkey):
                        try:
                            inst_key = winreg.OpenKey(subkey, inst_key_name)
                        except Exception:
                            continue
                        with inst_key:
                            if device_instance_matches(inst_key, device_id):
                                return extract_device_info(inst_key)
    return {}


def get_device_registry_info(device_id):
    """
    Attempts to get driver and hardware info from registry for a given device id.
    """
    enum_path = r"SYSTEM\CurrentControlSet\Enum"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, enum_path) as enum_root:
            return find_device_info_in_registry(enum_root, device_id)
    except Exception:
        return {}


def get_device_flow(device):
    """
    Determine if the device is input or output.
    pycaw does not expose this directly, so we infer from the device's properties.
    Devices with "Render" in their id are output, "Capture" are input.
    """
    device_id = getattr(device, "id", "") or ""
    device_id_lower = device_id.lower()
    if "render" in device_id_lower:
        return "output"
    if "capture" in device_id_lower:
        return "input"

    # Fallback: try to guess from name
    name = getattr(device, "FriendlyName", "").lower()
    if any(term in name for term in ("microphone", "mic", "input")):
        return "input"
    if any(term in name for term in ("speaker", "headphone", "output")):
        return "output"
    return "unknown"


def list_audio_devices(only_input=False, only_output=False, sort_by_status=False):
    """
    List audio devices, optionally filtering by input/output and sorting by status.
    Also prints device info and writes it to audio_devices.json.
    """
    devices = AudioUtilities.GetAllDevices()
    device_list = []

    for device in devices:
        name = device.FriendlyName
        state = device.state
        dev_type = "Enabled" if state == AudioDeviceState.Active else "Disabled"
        device_id = getattr(device, "id", None)
        device_flow = get_device_flow(device)

        # Filtering
        if only_input and device_flow != "input":
            continue
        if only_output and device_flow != "output":
            continue

        device_info = {
            "name": name,
            "state": dev_type,
            "id": device_id,
            "interface": getattr(device, "InterfaceFriendlyName", None),
            "device_path": getattr(device, "DevicePath", None),
            "flow": device_flow,
        }

        # Try to get registry info (driver, manufacturer, etc.)
        if device_id:
            reg_info = get_device_registry_info(device_id)
            device_info.update(reg_info)

        device_list.append(device_info)

    if sort_by_status:
        # Enabled first, then disabled
        device_list.sort(key=lambda d: d["state"] != "Enabled")

    print(Fore.CYAN + "=== Audio Devices ===" + Style.RESET_ALL)
    for device_info in device_list:
        color = Fore.GREEN if device_info["state"] == "Enabled" else Fore.RED
        flow_str = (
            f" ({device_info['flow']})"
            if device_info["flow"] in ("input", "output")
            else ""
        )
        print(
            f"{color}- {device_info['name']} [{device_info['state']}] {flow_str}{Style.RESET_ALL}"
        )
        print(f"  ID: {device_info['id']}")
        if device_info.get("interface"):
            print(f"  Interface: {device_info['interface']}")
        if device_info.get("device_path"):
            print(f"  Device Path: {device_info['device_path']}")
        if device_info.get("driver"):
            print(f"  Driver: {device_info['driver']}")
        if device_info.get("manufacturer"):
            print(f"  Manufacturer: {device_info['manufacturer']}")
        if device_info.get("description"):
            print(f"  Description: {device_info['description']}")
        if device_info.get("service"):
            print(f"  Service: {device_info['service']}")

    with open("audio_devices.json", "w", encoding="utf-8") as f:
        json.dump(device_list, f, indent=2, ensure_ascii=False)


def list_bluetooth_devices():
    """
    List Bluetooth devices from the Windows registry and save to bluetooth_devices.json.
    """
    bluetooth_devices = []
    # The registry path for Bluetooth devices
    bt_base_path = r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bt_base_path) as bt_root:
            for i in range(winreg.QueryInfoKey(bt_root)[0]):
                try:
                    device_addr = winreg.EnumKey(bt_root, i)
                    with winreg.OpenKey(bt_root, device_addr) as dev_key:
                        device_info = {"address": device_addr}
                        # Try to get the device name
                        name = get_registry_value(dev_key, "Name")
                        if name:
                            # Name may be bytes, decode if needed
                            if isinstance(name, bytes):
                                try:
                                    name = name.decode("utf-8", errors="replace")
                                except Exception:
                                    name = str(name)
                            device_info["name"] = name
                        # Try to get other info (optional)
                        class_val = get_registry_value(dev_key, "Class")
                        if class_val is not None:
                            device_info["class"] = class_val
                        lmp_subver = get_registry_value(dev_key, "LMPSubversion")
                        if lmp_subver is not None:
                            device_info["lmp_subversion"] = lmp_subver
                        manufacturer = get_registry_value(dev_key, "Manufacturer")
                        if manufacturer is not None:
                            device_info["manufacturer"] = manufacturer
                        bluetooth_devices.append(device_info)
                except Exception:
                    continue
    except Exception:
        # Could not open Bluetooth registry key, likely no Bluetooth or no permissions
        pass

    print(Fore.CYAN + "=== Bluetooth Devices ===" + Style.RESET_ALL)
    if not bluetooth_devices:
        print(
            Fore.YELLOW
            + "No Bluetooth devices found or access denied."
            + Style.RESET_ALL
        )
    else:
        for dev in bluetooth_devices:
            print(
                Fore.BLUE
                + f"- {dev.get('name', '(unknown name)')} [{dev['address']}]"
                + Style.RESET_ALL
            )
            if "manufacturer" in dev:
                print(f"  Manufacturer: {dev['manufacturer']}")
            if "class" in dev:
                print(f"  Class: {dev['class']}")
            if "lmp_subversion" in dev:
                print(f"  LMP Subversion: {dev['lmp_subversion']}")

    with open("bluetooth_devices.json", "w", encoding="utf-8") as f:
        json.dump(bluetooth_devices, f, indent=2, ensure_ascii=False)


def parse_args():
    """Parse command-line arguments for filtering and sorting audio devices."""
    parser = argparse.ArgumentParser(
        description="List audio devices with optional filtering and sorting."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--only-input-devices",
        action="store_true",
        help="Show only input (recording) devices",
    )
    group.add_argument(
        "--only-output-devices",
        action="store_true",
        help="Show only output (playback) devices",
    )
    parser.add_argument(
        "--sort-by-status",
        action="store_true",
        help="Sort devices by status (enabled first)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    list_audio_devices(
        only_input=args.only_input_devices,
        only_output=args.only_output_devices,
        sort_by_status=args.sort_by_status,
    )
    list_bluetooth_devices()


if __name__ == "__main__":
    main()
