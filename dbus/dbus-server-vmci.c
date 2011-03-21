#include <config.h>
#include "dbus-internals.h"
#include "dbus-server-socket.h"
#include "dbus-server-vmci.h"
#include "dbus-string.h"
#include "dbus-sysdeps-unix.h"

#include <vmci_sockets.h>

#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#if 0
REVERSE CALL CHAIN:
_dbus_server_new_for_socket
_dbus_listen_tcp_socket
	<- _dbus_server_new_for_tcp_socket
		<- _dbus_server_listen_socket
#endif

static dbus_bool_t
_dbus_open_socket (int              *fd_p,
                   int               domain,
                   int               type,
                   int               protocol,
                   DBusError        *error)
{
#ifdef SOCK_CLOEXEC
  dbus_bool_t cloexec_done;

  *fd_p = socket (domain, type | SOCK_CLOEXEC, protocol);
  cloexec_done = *fd_p >= 0;

  /* Check if kernel seems to be too old to know SOCK_CLOEXEC */
  if (*fd_p < 0 && errno == EINVAL)
#endif
    {
      *fd_p = socket (domain, type, protocol);
    }

  if (*fd_p >= 0)
    {
#ifdef SOCK_CLOEXEC
      if (!cloexec_done)
#endif
        {
          _dbus_fd_set_close_on_exec(*fd_p);
        }

      _dbus_verbose ("socket fd %d opened\n", *fd_p);
      return TRUE;
    }
  else
    {
      dbus_set_error(error,
                     _dbus_error_from_errno (errno),
                     "Failed to open socket: %s",
                     _dbus_strerror (errno));
      return FALSE;
    }
}

/**
 * Creates a VMCI stream socket and binds it to the given cid and port, then listens on
 * the socket. The socket is set to be nonblocking.  If cid is 0,
 * VMADDR_CID_ANY is used. If port is 0, VMADDR_PORT_ANY is used.
 *
 * @param cid the VM context id to listen on
 * @param port the port to listen on
 * @param retport string to return the actual port listened on
 * @param fds_p location to store returned file descriptors
 * @param error return location for errors
 * @returns the number of listening file descriptors or -1 on error
 */

static int
_dbus_listen_vmci_socket (const char     *cid,
                          const char     *port,
                          DBusString     *retcid,
                          DBusString     *retport,
                          int           **fds_p,
                          DBusError      *error)
{
  int af_vmci;
  int *listen_fds = NULL;
  int listen_fd = -1;
  unsigned int reuseaddr;
  uint64_t bufsize;
  struct sockaddr_vm my_addr = {0};
  char t[50];
  socklen_t size;

  af_vmci = VMCISock_GetAFValue();
  if (af_vmci < 0) {
    dbus_set_error (error, _dbus_error_from_errno (errno),
        "VMCISock_GetAFValue() failed: %s",
        _dbus_strerror (errno));
    return -1;
  }
  listen_fds = dbus_new(int, 1);
  if (!listen_fds) {
        dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
        goto failed;
  }
  if (!_dbus_open_socket (&listen_fd, af_vmci, SOCK_STREAM, 0, error)) {
          _DBUS_ASSERT_ERROR_IS_SET(error);
          return -1;
  }
  bufsize = 32768;
  if (setsockopt(listen_fd, af_vmci, SO_VMCI_BUFFER_SIZE, &bufsize, sizeof(bufsize)) == -1)  {
    _dbus_warn ("Failed to set socket option 0x%08x: \"%s:%s\": %s",
        SO_VMCI_BUFFER_SIZE, cid ? cid : "*", port, _dbus_strerror (errno));
  }

  reuseaddr = 1;
  if (setsockopt (listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) == -1) {
    _dbus_warn ("Failed to set socket option 0x%08x: \"%s:%s\": %s",
        SO_REUSEADDR, cid ? cid : "*", port, _dbus_strerror (errno));
  }

  my_addr.svm_family = af_vmci;
  my_addr.svm_cid = cid ? atoi(cid) : VMADDR_CID_ANY;
  my_addr.svm_port = port ? atoi(port) : VMADDR_PORT_ANY;
  if (bind (listen_fd, (struct sockaddr*)&my_addr, sizeof(my_addr)) < 0) {
    dbus_set_error (error, _dbus_error_from_errno (errno),
        "Failed to bind socket \"%s:%s\": %s",
        cid ? cid : "*", port, _dbus_strerror (errno));
    goto failed;
  }
  if (listen (listen_fd, 30 /* backlog */) < 0) {
    dbus_set_error (error, _dbus_error_from_errno (errno),
        "Failed to listen on socket \"%s:%s\": %s",
        cid ? cid : "*", port, _dbus_strerror (errno));
    goto failed;
  }

  size = sizeof(my_addr);
  if (getsockname(listen_fd, (struct sockaddr *)&my_addr, &size) == -1) {
    dbus_set_error (error, _dbus_error_from_errno (errno),
        "getsockname failed: \"%s:%s\": %s",
        cid ? cid : "*", port, _dbus_strerror (errno));
    goto failed;
  }

  if (!_dbus_string_get_length(retcid)) {
    /* the user didn't specify a CID */
    if (!cid || !strcmp(cid, "0")) {
      snprintf(t, sizeof(t), "%d", my_addr.svm_cid);
      if (!_dbus_string_append(retcid, t)) {
        dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
        goto failed;
      }
    } else {
      if (!_dbus_string_append(retcid, cid)) {
        dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
        goto failed;
      }
    }
  }
  if (!_dbus_string_get_length(retport)) {
          /* If the user didn't specify a port, or used 0, then
             the kernel chooses a port. After the first address
             is bound to, we need to force all remaining addresses
             to use the same port */
    if (!port || !strcmp(port, "0")) {
      snprintf(t, sizeof(t), "%d", my_addr.svm_port);
      if (!_dbus_string_append(retport, t)) {
        dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
        goto failed;
      }
    } else {
      if (!_dbus_string_append(retport, port)) {
        dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
        goto failed;
      }
    }
  }
  if (!_dbus_set_fd_nonblocking (listen_fd, error)) {
    goto failed;
  }
  *listen_fds = listen_fd;
  *fds_p = listen_fds;
  return 1;

failed:
  if (listen_fds)
    dbus_free(listen_fds);
  if (listen_fd >= 0)
    _dbus_close(listen_fd, NULL);
  return -1;
}

/*
 * Creates a new server listening on a VMCI stream socket.
 * If host is NULL, it will default to localhost.
 * If bind is NULL, it will default to the value for the host
 * parameter, and if that is NULL, then localhost
 * If bind is a hostname, it will be resolved and will listen
 * on all returned addresses.
 * If family is NULL, hostname resolution will try all address
 * families, otherwise it can be ipv4 or ipv6 to restrict the
 * addresses considered.
 *
 * @param host the hostname to report for the listen address
 * @param bind the hostname to listen on
 * @param port the port to listen on or 0 to let the OS choose
 * @param family
 * @param error location to store reason for failure.
 * @param use_nonce whether to use a nonce for low-level authentication (nonce-tcp transport) or not (tcp transport)
 * @returns the new server, or #NULL on failure.
 */
  DBusServer*
_dbus_server_new_for_vmci (const char     *bind,
    const char     *port,
    DBusError      *error)
{
  DBusServer *server;
  int *listen_fds = NULL;
  int nlisten_fds = 0, i;
  DBusString address;
  DBusString cid_str;
  DBusString port_str;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  if (!_dbus_string_init (&address))
  {
    dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
    return NULL;
  }

  if (!_dbus_string_init (&cid_str))
  {
    dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
    goto failed_0;
  }

  if (!_dbus_string_init (&port_str))
  {
    dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
    goto failed_1;
  }
  nlisten_fds = _dbus_listen_vmci_socket (bind, port,
      &cid_str, &port_str, &listen_fds, error);
  if (nlisten_fds <= 0)
  {
    _DBUS_ASSERT_ERROR_IS_SET(error);
    goto failed;
  }


  if (!_dbus_string_append(&address, "vmci:cid=") ||
      !_dbus_string_append(&address, _dbus_string_get_const_data(&cid_str)) ||
      !_dbus_string_append(&address, ",port=") ||
      !_dbus_string_append(&address, _dbus_string_get_const_data(&port_str))) {
    dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
    goto failed;
  }

  server = _dbus_server_new_for_socket (listen_fds, nlisten_fds, &address, NULL);
  if (server == NULL)
  {
    dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
    goto failed;
  }

  _dbus_string_free (&port_str);
  _dbus_string_free (&cid_str);
  _dbus_string_free (&address);
  dbus_free(listen_fds);
  return server;

failed:
  for (i = 0 ; i < nlisten_fds ; i++)
    _dbus_close_socket (listen_fds[i], NULL);
  if (listen_fds)
    dbus_free(listen_fds);
failed_2:
  _dbus_string_free(&port_str);
failed_1:
  _dbus_string_free(&cid_str);
failed_0:
  _dbus_string_free(&address);
  return NULL;
}

  DBusServerListenResult
_dbus_server_listen_vmci (DBusAddressEntry *entry,
    DBusServer      **server_p,
    DBusError        *error)
{
  const char *method;
  const char *bind;
  const char *port;

  method = dbus_address_entry_get_method (entry);
  if (strcmp (method, "vmci") != 0) {
    _DBUS_ASSERT_ERROR_IS_CLEAR(error);
    return DBUS_SERVER_LISTEN_NOT_HANDLED;
  }

  bind = dbus_address_entry_get_value (entry, "bind");
  port = dbus_address_entry_get_value (entry, "port");
  *server_p = _dbus_server_new_for_vmci (bind, port, error);
  if (*server_p) {
    _DBUS_ASSERT_ERROR_IS_CLEAR(error);
    return DBUS_SERVER_LISTEN_OK;
  } else {
    _DBUS_ASSERT_ERROR_IS_SET(error);
    return DBUS_SERVER_LISTEN_DID_NOT_CONNECT;
  }
}
