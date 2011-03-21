#ifndef DBUS_SERVER_VMCI_H
#define DBUS_SERVER_VMCI_H
#include <dbus/dbus-internals.h>
#include <dbus/dbus-server-protected.h>

DBusServer*
_dbus_server_new_for_vmci (const char     *cid,
                           const char     *port,
                           DBusError      *error);

DBusServerListenResult _dbus_server_listen_vmci (DBusAddressEntry  *entry,
                                                   DBusServer       **server_p,
                                                   DBusError         *error);
#endif
