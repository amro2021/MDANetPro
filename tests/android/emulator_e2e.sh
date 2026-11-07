#!/bin/bash
# Real Android app in an emulator (behind the emulator's NAT, like a phone on mobile data)
# joins a network run by the Python PC app on the host, through a relay, and chats.
set -u
UI="python3 tests/android/ui.py"
SHARE=$(mktemp -d)
FAIL=0
step() { echo "::group::$1"; }
end() { echo "::endgroup::"; }

adb install -r android/app/build/outputs/apk/debug/app-debug.apk
adb shell pm grant com.mdanetpro.app android.permission.POST_NOTIFICATIONS || true

# Python seed on the host. 10.0.2.2 is the host as seen from the emulator.
MEMBER=Droid PUBLIC=10.0.2.2:50404 xvfb-run -a python3 tests/interop/py_node.py seed "$SHARE" > "$SHARE/py.log" 2>&1 &
PY=$!
for i in $(seq 1 60); do [ -f "$SHARE/py_seed.ready" ] && break; sleep 1; done

adb shell am start -n com.mdanetpro.app/.MainActivity
sleep 8
$UI shot 01-setup
step "setup"
$UI tap "Your name"; $UI type "Droid"; $UI tap "Next"
$UI tap "Join a network nearby"
end
sleep 3
$UI shot 02-home
step "join by address"
$UI tap "Networks"
$UI shot 03-networks
$UI tap "By address"; $UI tap "e.g."; $UI type "10.0.2.2"; $UI tap "Find networks"
sleep 4; $UI tap "OK" || true
end
if [ "$($UI wait 'You joined' 120)" = "PASS see You joined" ]; then echo "PASS app joined the PC network (approved through relay)"; else echo "FAIL app did not get the approval"; FAIL=1; fi
$UI shot 04-joined
$UI tap "OK" || true
step "chat"
$UI tap "Chats"
if [ "$($UI wait 'welcome Droid' 90)" = "PASS see welcome Droid" ]; then echo "PASS app received chat from the PC"; else echo "FAIL no chat from the PC"; FAIL=1; fi
$UI shot 05-chats
$UI tap "Amr"
$UI tap "Message"; $UI type "thanks from Droid"; $UI tap "Send"
sleep 3
$UI shot 06-chat
adb shell input keyevent KEYCODE_BACK; sleep 1
end
step "status"
$UI tap "Status"; $UI tap "Test connection"
sleep 25
$UI shot 07-status
end
wait $PY || FAIL=1
echo "----- Python seed -----"; grep -v "received:" "$SHARE/py.log" | tail -40
echo "----- app log -----"; adb logcat -d -s AndroidRuntime:E | tail -30
exit $FAIL
