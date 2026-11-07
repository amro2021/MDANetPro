"""Tiny UI driver for the emulator test: find on-screen text via uiautomator and tap it."""
import base64, re, subprocess, sys, time

def adb(*args, check=True):
    return subprocess.run(["adb", *args], capture_output=True, text=True, check=check).stdout

def nodes():
    adb("shell", "uiautomator", "dump", "/sdcard/ui.xml", check=False)
    xml = adb("shell", "cat", "/sdcard/ui.xml", check=False)
    out = []
    for m in re.finditer(r'<node [^>]*?text="([^"]*)"[^>]*?content-desc="([^"]*)"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml):
        text, desc, x1, y1, x2, y2 = m.groups()
        out.append((text or desc, (int(x1) + int(x2)) // 2, (int(y1) + int(y2)) // 2))
    return out

def find(label, timeout=30, exact=False):
    end = time.time() + timeout
    while time.time() < end:
        for text, x, y in nodes():
            if (text == label) if exact else (label.lower() in text.lower()):
                return x, y
        time.sleep(1)
    return None

def tap(label, timeout=30, exact=False):
    pos = find(label, timeout, exact)
    if not pos:
        raise SystemExit(f"FAIL: '{label}' not on screen. Visible: {[t for t, _, _ in nodes() if t][:40]}")
    adb("shell", "input", "tap", str(pos[0]), str(pos[1]))
    time.sleep(1.2)

def type_text(text):
    adb("shell", "input", "text", text.replace(" ", "%s"))
    time.sleep(0.8)

def screenshot(name):
    png = subprocess.run(["adb", "exec-out", "screencap", "-p"], capture_output=True, check=True).stdout
    open(f"{name}.png", "wb").write(png)
    print(f"=====SCREENSHOT {name} BEGIN=====")
    print(base64.b64encode(png).decode())
    print(f"=====SCREENSHOT {name} END=====", flush=True)

if __name__ == "__main__":
    cmd, *rest = sys.argv[1:]
    {"tap": lambda: tap(rest[0]), "type": lambda: type_text(rest[0]), "shot": lambda: screenshot(rest[0]),
     "wait": lambda: print("PASS" if find(rest[0], int(rest[1]) if len(rest) > 1 else 60) else "FAIL", "see", rest[0])}[cmd]()
