adb push inj /dev/
adb shell chmod 777 /dev/inj
adb push inj_dalvik /dev/
adb shell chmod 777 /dev/inj_dalvik
adb push libhook.so /dev/
adb shell chmod 777 /dev/libhook.so

adb push libmynet.so /dev/
adb push libnewfunc.so /dev/
adb shell chmod 777 /dev/libmynet.so
adb shell ./dev/inj_dalvik 
