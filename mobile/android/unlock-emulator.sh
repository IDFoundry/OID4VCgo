#!/bin/sh
# Gives the emulator a PIN and unlocks it with it, keeping the screen on:
# holder keys need a secure lock screen, and every key needs the device
# unlocked. Entering the PIN races the lock screen's animation, so it
# tries a few times.
set -u
PIN="${1:-1111}"
adb shell locksettings set-pin "$PIN" >/dev/null 2>&1 || true
adb shell svc power stayon true
for attempt in 1 2 3 4 5 6; do
	adb shell input keyevent KEYCODE_WAKEUP
	adb shell wm dismiss-keyguard
	sleep 2
	adb shell input text "$PIN"
	adb shell input keyevent KEYCODE_ENTER
	sleep 2
	if adb shell dumpsys window | grep -q 'isKeyguardShowing=false'; then
		echo "unlocked (attempt $attempt)"
		exit 0
	fi
done
echo "the emulator didn't unlock" >&2
exit 1
