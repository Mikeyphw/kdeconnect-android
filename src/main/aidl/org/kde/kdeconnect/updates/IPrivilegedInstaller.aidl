package org.kde.kdeconnect.updates;

import android.content.IntentSender;

interface IPrivilegedInstaller {
    void begin(String packageName, long size) = 1;
    void chunk(in byte[] bytes) = 2;
    void commit(in IntentSender receiver) = 3;
    void abort() = 4;
    void destroy() = 16777114;
}
