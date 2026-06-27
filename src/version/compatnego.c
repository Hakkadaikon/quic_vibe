#include "version/compatnego.h"
#include "version/compat.h"

/* RFC 9368 2.2 */
int quic_version_compat_switch_ok(u32 original, u32 negotiated)
{
    return quic_version_compatible(original, negotiated);
}

/* RFC 9368 2.2 */
int quic_version_needs_retry(u32 original, u32 negotiated)
{
    return !quic_version_compatible(original, negotiated);
}
