from pycaw.pycaw import AudioUtilities
from pycaw.utils import AudioDeviceState
from colorama import init, Fore, Style
import json
import winreg

init(autoreset=True)


def get_registry_value(key, value_name):
    try:
        value, _ = winreg.QueryValueEx(key, value_name)
        return value
    except Exception:
        return None


def extract_device_info(inst_key):
    info = {}
    driver = get_registry_value(inst_key, "Driver")
    if driver:
        info["driver"] = driver
    mfg = get_registry_value(inst_key, "Mfg")
    if mfg:
        info["manufacturer"] = mfg
    desc = get_registry_value(inst_key, "DeviceDesc")
    if desc:
        info["description"] = desc
    service = get_registry_value(inst_key, "Service")
    if service:
        info["service"] = service
    return info


def device_instance_matches(inst_key, device_id):
    reg_device_id = get_registry_value(inst_key, "DeviceInstanceId")
    if reg_device_id and reg_device_id.lower() in device_id.lower():
        return True
    return False


def iter_subkeys(parent_key):
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
            info = find_device_info_in_registry(enum_root, device_id)
            return info
    except Exception:
        return {}


def list_audio_devices():
    devices = AudioUtilities.GetAllDevices()
    print(Fore.CYAN + "=== Audio Devices ===" + Style.RESET_ALL)
    device_list = []
    for device in devices:
        name = device.FriendlyName
        state = device.state
        dev_type = "Enabled" if state == AudioDeviceState.Active else "Disabled"
        color = Fore.GREEN if dev_type == "Enabled" else Fore.RED
        device_id = getattr(device, "id", None)
        device_info = {
            "name": name,
            "state": dev_type,
            "id": device_id,
            "interface": getattr(device, "InterfaceFriendlyName", None),
            "device_path": getattr(device, "DevicePath", None),
        }
        # Try to get registry info (driver, manufacturer, etc.)
        if device_id:
            reg_info = get_device_registry_info(device_id)
            device_info.update(reg_info)
        print(f"{color}- {name} [{dev_type}]{Style.RESET_ALL}")
        print(f"  ID: {device_id}")
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
        device_list.append(device_info)
    with open("audio_devices.json", "w", encoding="utf-8") as f:
        json.dump(device_list, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    list_audio_devices()
