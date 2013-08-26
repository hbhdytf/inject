LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:=  elf.c inject.c ptrace.c
LOCAL_MODULE := inj
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -DANDROID -DTHUMB
#LOCAL_C_INCLUDES := 
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog
LOCAL_SRC_FILES:=  elf.c inj_dalvik.c ptrace.c
LOCAL_MODULE := inj_dalvik
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -DANDROID -DTHUMB
#LOCAL_C_INCLUDES := 
include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)
LOCAL_SRC_FILES:=  testapp.c
LOCAL_MODULE := testapp
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES += libdl
#LOCAL_C_INCLUDES := 
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog
LOCAL_SRC_FILES:=  test.c
LOCAL_MODULE := test
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES += libdl
#LOCAL_C_INCLUDES := 
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog
LOCAL_SRC_FILES:=  libmynet.c
LOCAL_MODULE := libmynet
LOCAL_MODULE_TAGS := optional
#LOCAL_C_INCLUDES := 
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -lcrypto
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -lssl
LOCAL_SRC_FILES:=  hook.c
LOCAL_MODULE := libhook
LOCAL_MODULE_TAGS := optional
#LOCAL_C_INCLUDES := 
include $(BUILD_SHARED_LIBRARY)


