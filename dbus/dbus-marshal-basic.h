/* -*- mode: C; c-file-style: "gnu" -*- */
/* dbus-marshal-basic.h  Marshalling routines for basic (primitive) types
 *
 * Copyright (C) 2002  CodeFactory AB
 * Copyright (C) 2004  Red Hat, Inc.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef DBUS_MARSHAL_H
#define DBUS_MARSHAL_H

#include <config.h>
#include <dbus/dbus-protocol.h>
#include <dbus/dbus-types.h>
#include <dbus/dbus-arch-deps.h>
#include <dbus/dbus-string.h>

#ifndef PACKAGE
#error "config.h not included here"
#endif

/****************************************************** Remove later */
#undef DBUS_TYPE_INVALID
#undef DBUS_TYPE_NIL
#undef DBUS_TYPE_CUSTOM
#undef DBUS_TYPE_BYTE
#undef DBUS_TYPE_INT32
#undef DBUS_TYPE_UINT32
#undef DBUS_TYPE_INT64
#undef DBUS_TYPE_UINT64
#undef DBUS_TYPE_DOUBLE
#undef DBUS_TYPE_STRING
#undef DBUS_TYPE_OBJECT_PATH
#undef DBUS_TYPE_ARRAY
#undef DBUS_TYPE_DICT
#undef DBUS_TYPE_VARIANT
#undef DBUS_TYPE_STRUCT
#undef DBUS_NUMBER_OF_TYPES


/* Never a legitimate type */
#define DBUS_TYPE_INVALID       ((int) '\0')
#define DBUS_TYPE_INVALID_AS_STRING        "\0"

/* Primitive types */
#define DBUS_TYPE_BYTE          ((int) 'y')
#define DBUS_TYPE_BYTE_AS_STRING           "y"
#define DBUS_TYPE_BOOLEAN       ((int) 'b')
#define DBUS_TYPE_BOOLEAN_AS_STRING        "b"
#define DBUS_TYPE_INT32         ((int) 'i')
#define DBUS_TYPE_INT32_AS_STRING          "i"

#define DBUS_TYPE_UINT32        ((int) 'u')
#define DBUS_TYPE_UINT32_AS_STRING         "u"
#define DBUS_TYPE_INT64         ((int) 'x')
#define DBUS_TYPE_INT64_AS_STRING          "x"
#define DBUS_TYPE_UINT64        ((int) 't')
#define DBUS_TYPE_UINT64_AS_STRING         "t"

#define DBUS_TYPE_DOUBLE        ((int) 'd')
#define DBUS_TYPE_DOUBLE_AS_STRING         "d"
#define DBUS_TYPE_STRING        ((int) 's')
#define DBUS_TYPE_STRING_AS_STRING         "s"
#define DBUS_TYPE_OBJECT_PATH   ((int) 'o')
#define DBUS_TYPE_OBJECT_PATH_AS_STRING    "o"

/* Compound types */
#define DBUS_TYPE_ARRAY         ((int) 'a')
#define DBUS_TYPE_ARRAY_AS_STRING          "a"
#define DBUS_TYPE_DICT          ((int) 'm') /* not parameterized; always map<string,variant> */
#define DBUS_TYPE_DICT_AS_STRING           "m"
#define DBUS_TYPE_VARIANT       ((int) 'v')
#define DBUS_TYPE_VARIANT_AS_STRING        "v"

/* STRUCT is sort of special since its code can't appear in a type string,
 * instead DBUS_STRUCT_BEGIN_CHAR has to appear
 */
#define DBUS_TYPE_STRUCT        ((int) 'r')
#define DBUS_TYPE_STRUCT_AS_STRING         "r"

/* Does not count INVALID */
#define DBUS_NUMBER_OF_TYPES    (13)

/* characters other than typecodes that appear in type signatures */
#define DBUS_STRUCT_BEGIN_CHAR   ((int) '(')
#define DBUS_STRUCT_BEGIN_CHAR_AS_STRING   "("
#define DBUS_STRUCT_END_CHAR     ((int) ')')
#define DBUS_STRUCT_END_CHAR_AS_STRING     ")"

static const char *
_hack_dbus_type_to_string (int type)
{
  switch (type)
    {
    case DBUS_TYPE_INVALID:
      return "invalid";
    case DBUS_TYPE_BOOLEAN:
      return "boolean";
    case DBUS_TYPE_INT32:
      return "int32";
    case DBUS_TYPE_UINT32:
      return "uint32";
    case DBUS_TYPE_DOUBLE:
      return "double";
    case DBUS_TYPE_STRING:
      return "string";
    case DBUS_TYPE_STRUCT:
      return "struct";
    case DBUS_TYPE_ARRAY:
      return "array";
    case DBUS_TYPE_DICT:
      return "dict";
    case DBUS_TYPE_VARIANT:
      return "variant";
    case DBUS_STRUCT_BEGIN_CHAR:
      return "begin_struct";
    case DBUS_STRUCT_END_CHAR:
      return "end_struct";
    default:
      return "unknown";
    }
}

#define _dbus_type_to_string(t) _hack_dbus_type_to_string(t)

/****************************************************** Remove later */

#ifdef WORDS_BIGENDIAN
#define DBUS_COMPILER_BYTE_ORDER DBUS_BIG_ENDIAN
#else
#define DBUS_COMPILER_BYTE_ORDER DBUS_LITTLE_ENDIAN
#endif

#define DBUS_UINT32_SWAP_LE_BE_CONSTANT(val)	((dbus_uint32_t) (      \
    (((dbus_uint32_t) (val) & (dbus_uint32_t) 0x000000ffU) << 24) |     \
    (((dbus_uint32_t) (val) & (dbus_uint32_t) 0x0000ff00U) <<  8) |     \
    (((dbus_uint32_t) (val) & (dbus_uint32_t) 0x00ff0000U) >>  8) |     \
    (((dbus_uint32_t) (val) & (dbus_uint32_t) 0xff000000U) >> 24)))

#ifdef DBUS_HAVE_INT64

#define DBUS_UINT64_SWAP_LE_BE_CONSTANT(val)	((dbus_uint64_t) (              \
      (((dbus_uint64_t) (val) &                                                 \
	(dbus_uint64_t) DBUS_UINT64_CONSTANT (0x00000000000000ff)) << 56) |    \
      (((dbus_uint64_t) (val) &                                                 \
	(dbus_uint64_t) DBUS_UINT64_CONSTANT (0x000000000000ff00)) << 40) |    \
      (((dbus_uint64_t) (val) &                                                 \
	(dbus_uint64_t) DBUS_UINT64_CONSTANT (0x0000000000ff0000)) << 24) |    \
      (((dbus_uint64_t) (val) &                                                 \
	(dbus_uint64_t) DBUS_UINT64_CONSTANT (0x00000000ff000000)) <<  8) |    \
      (((dbus_uint64_t) (val) &                                                 \
	(dbus_uint64_t) DBUS_UINT64_CONSTANT (0x000000ff00000000)) >>  8) |    \
      (((dbus_uint64_t) (val) &                                                 \
	(dbus_uint64_t) DBUS_UINT64_CONSTANT (0x0000ff0000000000)) >> 24) |    \
      (((dbus_uint64_t) (val) &                                                 \
	(dbus_uint64_t) DBUS_UINT64_CONSTANT (0x00ff000000000000)) >> 40) |    \
      (((dbus_uint64_t) (val) &                                                 \
	(dbus_uint64_t) DBUS_UINT64_CONSTANT (0xff00000000000000)) >> 56)))
#endif /* DBUS_HAVE_INT64 */

#define DBUS_UINT32_SWAP_LE_BE(val) (DBUS_UINT32_SWAP_LE_BE_CONSTANT (val))
#define DBUS_INT32_SWAP_LE_BE(val)  ((dbus_int32_t)DBUS_UINT32_SWAP_LE_BE_CONSTANT (val))

#ifdef DBUS_HAVE_INT64
#define DBUS_UINT64_SWAP_LE_BE(val) (DBUS_UINT64_SWAP_LE_BE_CONSTANT (val))
#define DBUS_INT64_SWAP_LE_BE(val)  ((dbus_int64_t)DBUS_UINT64_SWAP_LE_BE_CONSTANT (val))
#endif /* DBUS_HAVE_INT64 */

#ifdef WORDS_BIGENDIAN
#define DBUS_INT32_TO_BE(val)	((dbus_int32_t) (val))
#define DBUS_UINT32_TO_BE(val)	((dbus_uint32_t) (val))
#define DBUS_INT32_TO_LE(val)	(DBUS_INT32_SWAP_LE_BE (val))
#define DBUS_UINT32_TO_LE(val)	(DBUS_UINT32_SWAP_LE_BE (val))
#  ifdef DBUS_HAVE_INT64
#define DBUS_INT64_TO_BE(val)	((dbus_int64_t) (val))
#define DBUS_UINT64_TO_BE(val)	((dbus_uint64_t) (val))
#define DBUS_INT64_TO_LE(val)	(DBUS_INT64_SWAP_LE_BE (val))
#define DBUS_UINT64_TO_LE(val)	(DBUS_UINT64_SWAP_LE_BE (val))
#  endif /* DBUS_HAVE_INT64 */
#else
#define DBUS_INT32_TO_LE(val)	((dbus_int32_t) (val))
#define DBUS_UINT32_TO_LE(val)	((dbus_uint32_t) (val))
#define DBUS_INT32_TO_BE(val)	((dbus_int32_t) DBUS_UINT32_SWAP_LE_BE (val))
#define DBUS_UINT32_TO_BE(val)	(DBUS_UINT32_SWAP_LE_BE (val))
#  ifdef DBUS_HAVE_INT64
#define DBUS_INT64_TO_LE(val)	((dbus_int64_t) (val))
#define DBUS_UINT64_TO_LE(val)	((dbus_uint64_t) (val))
#define DBUS_INT64_TO_BE(val)	((dbus_int64_t) DBUS_UINT64_SWAP_LE_BE (val))
#define DBUS_UINT64_TO_BE(val)	(DBUS_UINT64_SWAP_LE_BE (val))
#  endif /* DBUS_HAVE_INT64 */
#endif

/* The transformation is symmetric, so the FROM just maps to the TO. */
#define DBUS_INT32_FROM_LE(val)	 (DBUS_INT32_TO_LE (val))
#define DBUS_UINT32_FROM_LE(val) (DBUS_UINT32_TO_LE (val))
#define DBUS_INT32_FROM_BE(val)	 (DBUS_INT32_TO_BE (val))
#define DBUS_UINT32_FROM_BE(val) (DBUS_UINT32_TO_BE (val))
#ifdef DBUS_HAVE_INT64
#define DBUS_INT64_FROM_LE(val)	 (DBUS_INT64_TO_LE (val))
#define DBUS_UINT64_FROM_LE(val) (DBUS_UINT64_TO_LE (val))
#define DBUS_INT64_FROM_BE(val)	 (DBUS_INT64_TO_BE (val))
#define DBUS_UINT64_FROM_BE(val) (DBUS_UINT64_TO_BE (val))
#endif /* DBUS_HAVE_INT64 */

void          _dbus_pack_int32    (dbus_int32_t         value,
                                   int                  byte_order,
                                   unsigned char       *data);
dbus_int32_t  _dbus_unpack_int32  (int                  byte_order,
                                   const unsigned char *data);
void          _dbus_pack_uint32   (dbus_uint32_t        value,
                                   int                  byte_order,
                                   unsigned char       *data);
dbus_uint32_t _dbus_unpack_uint32 (int                  byte_order,
                                   const unsigned char *data);
#ifdef DBUS_HAVE_INT64
void          _dbus_pack_int64    (dbus_int64_t         value,
                                   int                  byte_order,
                                   unsigned char       *data);
dbus_int64_t  _dbus_unpack_int64  (int                  byte_order,
                                   const unsigned char *data);
void          _dbus_pack_uint64   (dbus_uint64_t        value,
                                   int                  byte_order,
                                   unsigned char       *data);
dbus_uint64_t _dbus_unpack_uint64 (int                  byte_order,
                                   const unsigned char *data);
#endif /* DBUS_HAVE_INT64 */

void        _dbus_marshal_set_int32  (DBusString       *str,
                                      int               byte_order,
                                      int               offset,
                                      dbus_int32_t      value);
void        _dbus_marshal_set_uint32 (DBusString       *str,
                                      int               byte_order,
                                      int               offset,
                                      dbus_uint32_t     value);
#ifdef DBUS_HAVE_INT64
void        _dbus_marshal_set_int64  (DBusString       *str,
                                      int               byte_order,
                                      int               offset,
                                      dbus_int64_t      value);
void        _dbus_marshal_set_uint64 (DBusString       *str,
                                      int               byte_order,
                                      int               offset,
                                      dbus_uint64_t     value);
#endif /* DBUS_HAVE_INT64 */

dbus_bool_t _dbus_marshal_set_string      (DBusString         *str,
                                           int                 byte_order,
                                           int                 offset,
                                           const DBusString   *value,
                                           int                 len);
void        _dbus_marshal_set_object_path (DBusString         *str,
                                           int                 byte_order,
                                           int                 offset,
                                           const char        **path,
                                           int                 path_len);

dbus_bool_t   _dbus_marshal_int32          (DBusString            *str,
					    int                    byte_order,
					    dbus_int32_t           value);
dbus_bool_t   _dbus_marshal_uint32         (DBusString            *str,
					    int                    byte_order,
					    dbus_uint32_t          value);

#ifdef DBUS_HAVE_INT64
dbus_bool_t   _dbus_marshal_int64          (DBusString            *str,
					    int                    byte_order,
					    dbus_int64_t           value);
dbus_bool_t   _dbus_marshal_uint64         (DBusString            *str,
					    int                    byte_order,
					    dbus_uint64_t          value);
#endif /* DBUS_HAVE_INT64 */
dbus_bool_t   _dbus_marshal_double         (DBusString            *str,
					    int                    byte_order,
					    double                 value);

dbus_bool_t   _dbus_marshal_string         (DBusString            *str,
					    int                    byte_order,
					    const char            *value);
dbus_bool_t   _dbus_marshal_string_len     (DBusString            *str,
					    int                    byte_order,
					    const char            *value,
                                            int                    len);

dbus_bool_t   _dbus_marshal_basic_type     (DBusString            *str,
                                            int                    insert_at,
					    char                   type,
					    const void            *value,
					    int                    byte_order);
dbus_bool_t   _dbus_marshal_basic_type_array (DBusString            *str,
                                              int                    insert_at,
					      char                   element_type,
					      const void	    *value,
					      int                    len,
					      int                    byte_order);
dbus_bool_t   _dbus_marshal_byte_array     (DBusString            *str,
					    int                    byte_order,
					    const unsigned char   *value,
					    int                    len);
dbus_bool_t   _dbus_marshal_int32_array    (DBusString            *str,
					    int                    byte_order,
					    const dbus_int32_t    *value,
					    int                    len);
dbus_bool_t   _dbus_marshal_uint32_array   (DBusString            *str,
					    int                    byte_order,
					    const dbus_uint32_t   *value,
					    int                    len);
#ifdef DBUS_HAVE_INT64
dbus_bool_t   _dbus_marshal_int64_array    (DBusString            *str,
					    int                    byte_order,
					    const dbus_int64_t    *value,
					    int                    len);
dbus_bool_t   _dbus_marshal_uint64_array   (DBusString            *str,
					    int                    byte_order,
					    const dbus_uint64_t   *value,
					    int                    len);
#endif /* DBUS_HAVE_INT64 */
dbus_bool_t   _dbus_marshal_double_array   (DBusString            *str,
					    int                    byte_order,
					    const double          *value,
					    int                    len);
dbus_bool_t   _dbus_marshal_string_array   (DBusString            *str,
					    int                    byte_order,
					    const char           **value,
					    int                    len);
double        _dbus_demarshal_double       (const DBusString      *str,
					    int                    byte_order,
					    int                    pos,
					    int                   *new_pos);
dbus_int32_t  _dbus_demarshal_int32        (const DBusString      *str,
					    int                    byte_order,
					    int                    pos,
					    int                   *new_pos);
dbus_uint32_t _dbus_demarshal_uint32       (const DBusString      *str,
					    int                    byte_order,
					    int                    pos,
					    int                   *new_pos);
#ifdef DBUS_HAVE_INT64
dbus_int64_t  _dbus_demarshal_int64        (const DBusString      *str,
					    int                    byte_order,
					    int                    pos,
					    int                   *new_pos);
dbus_uint64_t _dbus_demarshal_uint64       (const DBusString      *str,
					    int                    byte_order,
					    int                    pos,
					    int                   *new_pos);
#endif /* DBUS_HAVE_INT64 */
void          _dbus_demarshal_basic_type   (const DBusString      *str,
					    int                    type,
					    void                  *value,
					    int                    byte_order,
					    int                   *pos);
char *        _dbus_demarshal_string       (const DBusString      *str,
					    int                    byte_order,
					    int                    pos,
					    int                   *new_pos);
dbus_bool_t   _dbus_demarshal_byte_array   (const DBusString      *str,
					    int                    byte_order,
					    int                    pos,
					    int                   *new_pos,
					    unsigned char        **array,
					    int                   *array_len);
dbus_bool_t   _dbus_demarshal_int32_array  (const DBusString      *str,
					    int                    byte_order,
					    int                    pos,
					    int                   *new_pos,
					    dbus_int32_t         **array,
					    int                   *array_len);
dbus_bool_t   _dbus_demarshal_uint32_array (const DBusString      *str,
					    int                    byte_order,
					    int                    pos,
					    int                   *new_pos,
					    dbus_uint32_t        **array,
					    int                   *array_len);
#ifdef DBUS_HAVE_INT64
dbus_bool_t   _dbus_demarshal_int64_array  (const DBusString      *str,
					    int                    byte_order,
					    int                    pos,
					    int                   *new_pos,
					    dbus_int64_t         **array,
					    int                   *array_len);
dbus_bool_t   _dbus_demarshal_uint64_array (const DBusString      *str,
					    int                    byte_order,
					    int                    pos,
					    int                   *new_pos,
					    dbus_uint64_t        **array,
					    int                   *array_len);
#endif /* DBUS_HAVE_INT64 */
dbus_bool_t   _dbus_demarshal_double_array (const DBusString      *str,
					    int                    byte_order,
					    int                    pos,
					    int                   *new_pos,
					    double               **array,
					    int                   *array_len);
dbus_bool_t   _dbus_demarshal_basic_type_array (const DBusString      *str,
						int                    type,
						void                 **array,
						int                   *array_len,
						int                    byte_order,
						int                   *pos);

dbus_bool_t   _dbus_demarshal_string_array (const DBusString      *str,
					    int                    byte_order,
					    int                    pos,
					    int                   *new_pos,
					    char                ***array,
					    int                   *array_len);
dbus_bool_t   _dbus_decompose_path         (const char*            data,
					    int                    len,
					    char                ***path,
					    int                   *path_len);
dbus_bool_t   _dbus_demarshal_object_path  (const DBusString      *str,
					    int                    byte_order,
					    int                    pos,
                                            int                   *new_pos,
                                            char                ***path,
                                            int                   *path_len);

void         _dbus_marshal_skip_basic_type (const DBusString      *str,
                                            int                    type,
                                            int                    byte_order,
					    int                   *pos);
void         _dbus_marshal_skip_array      (const DBusString      *str,
                                            int                    byte_order,
					    int                   *pos);

dbus_bool_t _dbus_marshal_get_arg_end_pos (const DBusString *str,
                                           int               byte_order,
					   int               type,
                                           int               pos,
                                           int              *end_pos);
dbus_bool_t _dbus_marshal_validate_type   (const DBusString *str,
                                           int               pos,
					   int              *type,
                                           int              *end_pos);
dbus_bool_t _dbus_marshal_validate_arg    (const DBusString *str,
                                           int               depth,
                                           int               byte_order,
					   int               type,
					   int               array_type_pos,
                                           int               pos,
                                           int              *end_pos);

dbus_bool_t _dbus_type_is_valid           (int               typecode);

int         _dbus_type_get_alignment      (int               typecode);

#endif /* DBUS_MARSHAL_H */