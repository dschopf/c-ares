
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

int ares_parse_a_reply_ex(const unsigned char *abuf, int alen,
                          struct ares_a_reply **rep)
{
  struct ares_addrinfo ai;
  struct ares_addrinfo_node *next;
  struct ares_addrinfo_cname *next_cname;
//   char **aliases = NULL;
  char *question_hostname = NULL;
  struct ares_a_reply *reply = NULL;
  struct in_addr *addrs = NULL;
  int naliases = 0, naddrs = 0, alias = 0, i;
  int cname_ttl = INT_MAX;
  int status;

  if (!rep)
    {
      // is there a better error code? ARES_EINVAL?
      return ARES_EBADQUERY;
    }

  memset(&ai, 0, sizeof(ai));

  status = ares__parse_into_addrinfo2(abuf, alen, &question_hostname, &ai);
  if (status != ARES_SUCCESS)
    {
      ares_free(question_hostname);

      return status;
    }

  next = ai.nodes;
  while (next)
    {
      ++naddrs;
      next = next->ai_next;
    }

  next_cname = ai.cnames;
  while (next_cname)
    {
      if(next_cname->alias)
        ++naliases;
      next_cname = next_cname->next;
    }

  reply = ares_malloc(sizeof(struct ares_a_reply));
  if (!reply)
    {
      goto enomem;
    }

  memset(reply, 0, sizeof(struct ares_a_reply));

  if (ai.cnames)
    {
      reply->name = strdup(ai.cnames->name);
      ares_free(question_hostname);
    }
  else
    {
      reply->name = question_hostname;
    }


  if (naliases)
    {
      reply->aliases = ares_malloc(naliases * sizeof(char *));
      if (!reply->aliases)
        {
          goto enomem;
        }

      next_cname = ai.cnames;
      while (next_cname)
        {
          if(next_cname->alias)
            {
              reply->aliases[alias] = strdup(next_cname->alias);
              if (!reply->aliases[alias])
                {
                  goto enomem;
                }
              else
                {
                  reply->naliases = ++alias;
                }
            }
          if(next_cname->ttl < cname_ttl)
            cname_ttl = next_cname->ttl;
          next_cname = next_cname->next;
        }
    }

  reply->addrtype = AF_INET;
  reply->length = sizeof(struct in_addr);

  if (naddrs)
    {
      reply->addr_list = ares_malloc(naddrs * sizeof(char *));
      if (!reply->addr_list)
        {
          goto enomem;
        }

      reply->ttl = ares_malloc(naddrs * sizeof(int));
      if (!reply->ttl)
        {
          goto enomem;
        }

      addrs = ares_malloc(naddrs * sizeof(struct in_addr));
      if (!addrs)
        {
          goto enomem;
        }

      i = 0;
      next = ai.nodes;
      while (next)
        {
          if (next->ai_family == AF_INET)
            {
              reply->addr_list[i] = (char *)&addrs[i];
              memcpy(reply->addr_list[i],
                     &(((struct sockaddr_in *)next->ai_addr)->sin_addr),
                     sizeof(struct in_addr));
              if (next->ai_ttl > cname_ttl)
                reply->ttl[i] = cname_ttl;
              else
                reply->ttl[i] = next->ai_ttl;
              ++i;
            }
          next = next->ai_next;
        }
      if (i == 0)
        {
          ares_free(addrs);
        }

        reply->naddr_list = naddrs;
    }

  *rep = reply;

  ares__freeaddrinfo_cnames(ai.cnames);
  ares__freeaddrinfo_nodes(ai.nodes);
  return ARES_SUCCESS;

enomem:
  ares_free_a_reply(reply);
  ares__freeaddrinfo_cnames(ai.cnames);
  ares__freeaddrinfo_nodes(ai.nodes);
  ares_free(question_hostname);
  return ARES_ENOMEM;
}

const char* ares_a_reply_ex_get_name(struct ares_a_reply const *reply)
{
  if (!reply)
    return NULL;

  return reply->name;
}

int ares_a_reply_ex_get_alias_count(struct ares_a_reply const *reply)
{
  if (!reply)
    return 0;

  return reply->naliases;
}

const char* ares_a_reply_ex_get_alias(struct ares_a_reply const *reply, int index)
{
  if (!reply || index < 0 || index >= reply->naliases)
    return NULL;

  return reply->aliases[index];
}

int ares_a_reply_ex_get_addr_type(struct ares_a_reply const *reply)
{
  if (!reply)
    return 0;

  return reply->addrtype;
}

int ares_a_reply_ex_get_length(struct ares_a_reply const *reply)
{
  if (!reply)
    return 0;

  return reply->length;
}

int ares_a_reply_ex_get_addr_count(struct ares_a_reply const *reply)
{
  if (!reply)
    return 0;

  return reply->naddr_list;
}

const char* ares_a_reply_ex_get_addr(struct ares_a_reply const *reply, int index)
{
  if (!reply || index < 0 || index >= reply->naddr_list)
    return NULL;

  return reply->addr_list[index];
}

int ares_a_reply_ex_get_ttl(struct ares_a_reply const *reply, int index)
{
  if (!reply || index < 0 || index >= reply->naddr_list)
    return 0;

  return reply->ttl[index];
}

void ares_free_a_reply(struct ares_a_reply* reply)
{
  int i = 0;

  if (!reply)
    return;

  ares_free((reply->name));
  for (i = 0; i < reply->naliases; ++i)
    ares_free(reply->aliases[i]);
  ares_free(reply->aliases);
  if (reply->addr_list)
    ares_free(reply->addr_list[0]); /* no matter if there is one or many entries,
                                 there is only one malloc for all of them */
  ares_free(reply->addr_list);
  ares_free(reply->ttl);
  ares_free(reply);
}
