/*
 * pam_modules that resolves numeric rhost to name
 * 
 * Use case is when the application does not resolve hostnames themself
 * 
 * Only rudimentary error handling, missing debug and address family
 *
 * License: GPL 2+
 *
 */

#include <netdb.h>
#include <stddef.h>
#include <syslog.h>
#include <string.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#include <security/pam_modules.h>
#include <security/pam_ext.h>

static int resolve_rhost(pam_handle_t *pamh, 	 
	int flags, 	 
	int argc, 	 
	const char **argv)
{
int retval;
const char *rhost = NULL;
struct addrinfo *res = NULL;
struct addrinfo *res0 = NULL;
struct addrinfo *rp = NULL;
struct addrinfo hints;
char host[NI_MAXHOST];
char *ap = NULL, *rap = NULL;
int alen;

if ((retval = pam_get_item (pamh, PAM_RHOST, (const void **) &rhost)) != PAM_SUCCESS) {
	pam_syslog (pamh, LOG_ERR, "get rhost failed: %s", pam_strerror (pamh, retval));
	return retval;
}

memset(&hints, 0, sizeof(hints));
hints.ai_flags = AI_NUMERICHOST;
hints.ai_family = AF_UNSPEC;
hints.ai_socktype = SOCK_STREAM; /* we only want one result back */
if ((retval = getaddrinfo(rhost, NULL, &hints, &res))) {
	pam_syslog (pamh, LOG_DEBUG, "rhost %s is not a numeric IP: %s", (rhost == NULL) ? "<NULL>" : rhost, gai_strerror(retval));
	return PAM_SUCCESS;
}
/* res should only have one entry, namely the given address */
if (res->ai_next != NULL) {
	pam_syslog (pamh, LOG_ERR, "%s is more than one entry", rhost);
	freeaddrinfo(res);
	return PAM_SUCCESS;
}

retval = getnameinfo(res->ai_addr, res->ai_addrlen, host, NI_MAXHOST, NULL, 0, NI_NAMEREQD);

if (retval) {
	pam_syslog (pamh, LOG_DEBUG, "address %s does not resolve: %s", rhost, gai_strerror(retval));
	freeaddrinfo(res);
	return PAM_SUCCESS;
}
/* no numeric result */
memset(&hints, 0, sizeof(hints));
hints.ai_flags = AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST;
hints.ai_family = res->ai_addr->sa_family;
hints.ai_socktype = SOCK_STREAM;
retval = getaddrinfo(host, NULL, &hints, &res0);
if (!retval) {
	pam_syslog (pamh, LOG_DEBUG, "address %s resolves to non-FDQN %s", rhost, host);
	freeaddrinfo(res0);
	freeaddrinfo(res);
	return PAM_SUCCESS;
}
/* Now do backward resolve and compare addresses */
memset(&hints, 0, sizeof(hints));
hints.ai_flags = AI_PASSIVE | AI_CANONNAME;
hints.ai_family = res->ai_addr->sa_family;
hints.ai_socktype = SOCK_STREAM;
retval = getaddrinfo(host, NULL, &hints, &res0);
if (retval) {
	pam_syslog (pamh, LOG_DEBUG, "%s resolves to %s does not resolve: %s", rhost, host, gai_strerror(retval));
	freeaddrinfo(res);
	return PAM_SUCCESS;
}
if ((res0->ai_canonname == NULL || strcasecmp(host, res0->ai_canonname)) 
	&& strcasecmp(host, "localhost")) {
	pam_syslog (pamh, LOG_DEBUG, "%s resolves to %s does not match %s",
		rhost, host, (res0->ai_canonname == NULL)? "<NULL>" : res0->ai_canonname);
	freeaddrinfo(res0);
	freeaddrinfo(res);
	return PAM_SUCCESS;
}

/* Now compare addresses */
switch (res->ai_family) {
case AF_INET:
	ap = (char *)&((struct sockaddr_in *)res->ai_addr)->sin_addr;
	alen = sizeof(struct in_addr);
	break;
case AF_INET6:
	ap = (char *)&((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
	alen = sizeof(struct in6_addr);
	break;
default:
	pam_syslog (pamh, LOG_ERR, "unknown address family found for %s: %d", rhost, res->ai_family);
	freeaddrinfo(res0);
	freeaddrinfo(res);
	return PAM_SUCCESS;
}
for (rp = res0; rp; rp = rp->ai_next) {
if (rp->ai_family == res->ai_family) {
	rap = NULL;
	switch (rp->ai_family) {
	case AF_INET:
		rap = (char *)&((struct sockaddr_in *)rp->ai_addr)->sin_addr;
		break;
	case AF_INET6:
		if (((struct sockaddr_in6 *)res->ai_addr)->sin6_scope_id ==
			((struct sockaddr_in6 *)rp->ai_addr)->sin6_scope_id) {
			rap = (char *)&((struct sockaddr_in6 *)rp->ai_addr)->sin6_addr;
		}
		break;
	default:
		pam_syslog (pamh, LOG_ERR, "unknown address family found for %s, %d", host, rp->ai_family);
		freeaddrinfo(res0);
		freeaddrinfo(res);
		return PAM_SUCCESS;
		break;
	}
	if (memcmp(rap, ap, alen) == 0) { /* found it */
		pam_syslog (pamh, LOG_DEBUG, "%s resolves to %s, address matches,  keep it", rhost, host);
		freeaddrinfo(res0);
		freeaddrinfo(res);
		/* Good exit */
		return pam_set_item(pamh, PAM_RHOST, host);
	}
}
}
/* failure case */
pam_syslog (pamh, LOG_DEBUG, "%s resolves to %s, no address match", rhost, host);
freeaddrinfo(res0);
freeaddrinfo(res);
return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, 	 
	int flags, 	 
	int argc, 	 
	const char **argv)
{
return resolve_rhost(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t	*pamh, 	 
	int flags, 	 
 	int argc, 	 
 	const char **argv)
{
return resolve_rhost(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, 	 
	int flags, 	 
 	int argc, 	 
 	const char **argv)
{
	return (PAM_IGNORE);
}
