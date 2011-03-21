/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-transport-unix.c UNIX socket subclasses of DBusTransport
 *
 * Copyright (C) 2002, 2003, 2004  Red Hat Inc.
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <assert.h>
#include <stdlib.h>
#include <errno.h>

#include <config.h>
#include "dbus-internals.h"
#include "dbus-connection-internal.h"
#include "dbus-transport-socket.h"
#include "dbus-transport-protected.h"
#include "dbus-watch.h"
#include "dbus-transport-vmci.h"

#include <vmci_sockets.h>

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
 * @defgroup DBusTransportVMCI DBusTransport implementations for the VMWare Communication Interface
 * @ingroup  DBusInternals
 * @brief Implementation details of DBusTransport on VMCI
 *
 * @{
 */

dbus_bool_t
_dbus_close (int        fd, DBusError *error);
/**
 * Creates a VMCI stream socket connected to the given cid and port.
 * The connection fd is returned, and is set up as nonblocking.
 *
 * This will set FD_CLOEXEC for the socket returned.
 *
 * @param path the path to UNIX domain socket
 * @param abstract #TRUE to use abstract namespace
 * @param error return location for error code
 * @returns connection file descriptor or -1 on error
 */
static int
_dbus_connect_vmci (const char     *cid_str,
                    const char     *port_str,
                    DBusError      *error)
{
  int fd;
  size_t path_len;
  struct sockaddr_vm addr;
  unsigned int af_vmci, cid, port;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  _dbus_verbose ("connecting to VMCI stream socket %s:%s\n", cid_str, port_str);
  cid = atoi(cid_str);
  port = atoi(port_str);
  if ((af_vmci = VMCISock_GetAFValue()) < 0) {
    assert(0);
  }
  if (_dbus_open_socket(&fd, af_vmci, SOCK_STREAM, 0, error) < 0) {
    return fd;
  }
  _DBUS_ZERO (addr);
  addr.svm_family = af_vmci;
  addr.svm_cid = cid;
  addr.svm_port = port;
  if (connect (fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
    dbus_set_error (error,
        _dbus_error_from_errno (errno),
        "Failed to connect to VMCI (cid, port): %s:%s: %s",
        cid_str, port_str, _dbus_strerror (errno));

    _dbus_close (fd, NULL);
    fd = -1;

    return -1;
  }
  if (!_dbus_set_fd_nonblocking (fd, error))
    {
      _DBUS_ASSERT_ERROR_IS_SET (error);

      _dbus_close (fd, NULL);
      fd = -1;

      return -1;
    }

  return fd;
}



/**
 * Creates a new transport for the given VMWare Communication Interface
 * CID and port. This creates a client-side of a transport.
 *
 * @param cid the virtual machine context ID to connect to
 * @param port the port to connect to
 * @param error address where an error can be returned.
 * @returns a new transport, or #NULL on failure.
 */
static
DBusTransport*
_dbus_transport_new_for_vmci (const char *cid,
                              const char *port,
                              DBusError  *error)
{
  int fd;
  DBusTransport *transport;
  DBusString address;

  _DBUS_ASSERT_ERROR_IS_CLEAR (error);

  if (!_dbus_string_init (&address))
    {
      dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
      return NULL;
    }

  fd = -1;

  if (!_dbus_string_append (&address, "vmci:cid=") ||
      !_dbus_string_append(&address, cid) ||
      !_dbus_string_append(&address, "port=") ||
      !_dbus_string_append(&address, port)) {
      dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
      goto failed_0;
  }

  fd = _dbus_connect_vmci (cid, port, error);
  if (fd < 0)
    {
      _DBUS_ASSERT_ERROR_IS_SET (error);
      goto failed_0;
    }

  _dbus_verbose ("Successfully connected to vmci stream socket %s:%s\n",
                 cid, port);

  transport = _dbus_transport_new_for_socket (fd, NULL, &address);
  if (transport == NULL)
    {
      dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
      goto failed_1;
    }

  _dbus_string_free (&address);

  return transport;

 failed_1:
  _dbus_close_socket (fd, NULL);
 failed_0:
  _dbus_string_free (&address);
  return NULL;
}

/**
 * Opens a VMCI stream socket transport.
 *
 * @param entry the address entry to try opening as a tcp transport.
 * @param transport_p return location for the opened transport
 * @param error error to be set
 * @returns result of the attempt
 */
DBusTransportOpenResult
_dbus_transport_open_vmci(DBusAddressEntry  *entry,
                            DBusTransport    **transport_p,
                            DBusError         *error)
{
  const char *method;
  const char *cid;
  const char *port;

  method = dbus_address_entry_get_method (entry);
  _dbus_assert (method != NULL);

  if (strcmp (method, "vmci") != 0) {
      _DBUS_ASSERT_ERROR_IS_CLEAR (error);
      return DBUS_TRANSPORT_OPEN_NOT_HANDLED;
  }
  cid = dbus_address_entry_get_value (entry, "cid");
  port = dbus_address_entry_get_value (entry, "port");

  if (0 || port == NULL)
  {
    _dbus_set_bad_address (error, method, "port", NULL);
    return DBUS_TRANSPORT_OPEN_BAD_ADDRESS;
  }

  *transport_p = _dbus_transport_new_for_vmci (cid, port, error);
  if (*transport_p == NULL)
  {
    _DBUS_ASSERT_ERROR_IS_SET (error);
    return DBUS_TRANSPORT_OPEN_DID_NOT_CONNECT;
  }
  else
  {
    _DBUS_ASSERT_ERROR_IS_CLEAR (error);
    return DBUS_TRANSPORT_OPEN_OK;
  }
}

/** @} */
