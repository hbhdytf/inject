adb push inj /dev/
adb shell chmod 777 /dev/inj
adb push inj_dalvik /dev/
adb shell chmod 777 /dev/inj_dalvik
adb push libmynet.so /dev/
adb shell chmod 777 /dev/libmynet.so
adb shell ./dev/inj_dalvik 
