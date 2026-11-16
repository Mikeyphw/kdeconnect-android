package org.kde.kdeconnect.updates;

import android.content.IntentSender;

interface IPrivilegedInstaller {
    void begin(String packageName, long size);
    void chunk(in byte[] bytes);
    void commit(in IntentSender receiver);
    void abort();
    void destroy() = 16777114;
}
