
/* Copyright 1998 by the Massachusetts Institute of Technology.
 * Copyright (C) 2019 by Andrew Selivanov
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#include "ares_setup.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
#else
#  include "nameser.h"
#endif
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#  include <arpa/nameser_compat.h>
#endif

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"

int ares_parse_a_reply(const unsigned char *abuf, int alen,
                       struct hostent **host,
                       struct ares_addrttl *addrttls, int *naddrttls)
{
  struct hostent *hostent = NULL;
  struct in_addr *addrs = NULL;
  int naliases = 0, naddrs = 0, naddrttls_size = 0, i;

  int status;
  ares_a_reply *reply = NULL;

  if (naddrttls)
    {
      naddrttls_size = *naddrttls;
      *naddrttls = 0;
    }

  status = ares_parse_a_reply_ex(abuf, alen, &reply);
  if (status != ARES_SUCCESS)
    {
      return status;
    }

  hostent = ares_malloc(sizeof(struct hostent));
  if (!hostent)
    {
      goto enomem;
    }

  memset(hostent, 0, sizeof(struct hostent));

  hostent->h_name = ares_strdup(ares_a_reply_ex_get_name(reply));

  naliases = ares_a_reply_ex_get_alias_count(reply);
  hostent->h_aliases = ares_malloc((naliases + 1) * sizeof(char *));
  if (!hostent->h_aliases)
    {
      goto enomem;
    }

  if (naliases)
    {
      for (i = 0; i < naliases; ++i)
      {
        hostent->h_aliases[i] = ares_strdup(ares_a_reply_ex_get_alias(reply, i));
      }
    }
  hostent->h_aliases[naliases] = NULL;

  hostent->h_addrtype = ares_a_reply_ex_get_addr_type(reply);
  hostent->h_length = ares_a_reply_ex_get_length(reply);

  naddrs = ares_a_reply_ex_get_addr_count(reply);
  hostent->h_addr_list = ares_malloc((naddrs + 1) * sizeof(char *));
  if (!hostent->h_addr_list)
    {
      goto enomem;
    }

  if (naddrs)
    {

      addrs = ares_malloc(naddrs * sizeof(struct in_addr));
      if (!addrs)
        {
          goto enomem;
        }

      for (i = 0; i < naddrs; ++i)
      {
        hostent->h_addr_list[i] = (char *)&addrs[i];
        memcpy(hostent->h_addr_list[i], ares_a_reply_ex_get_addr(reply, i), sizeof(struct in_addr));
      }
    }
  hostent->h_addr_list[naddrs] = NULL;

  if (host)
    {
      *host = hostent;
    }
  else
    {
      ares_free_hostent(hostent);
    }

  if (naddrttls_size)
    {
      for (i = 0; i < naddrs && i < naddrttls_size; ++i)
        {
          memcpy(&addrttls[i].ipaddr.s_addr, ares_a_reply_ex_get_addr(reply, i), ares_a_reply_ex_get_length(reply));
          addrttls[i].ttl = ares_a_reply_ex_get_ttl(reply, i);
        }

      *naddrttls = i;
    }

  ares_free_a_reply(reply);

  return ARES_SUCCESS;

enomem:
  ares_free_a_reply(reply);
  ares_free(hostent);
  return ARES_ENOMEM;
}
