/*
 * xpc_probe: attempt an XPC mach service connection and emit a tiny JSON result.
 *
 * Usage: xpc_probe <service>
 */
#include <xpc/xpc.h>
#include <stdio.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <service>\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }
    const char *service = argv[1];
    xpc_connection_t conn = xpc_connection_create_mach_service(service, NULL, 0);
    if (!conn) {
        fprintf(stderr, "xpc_connection_create_mach_service failed\n");
        return 1;
    }

    xpc_connection_set_event_handler(conn, ^(xpc_object_t obj) {
        (void)obj;
    });
    xpc_connection_resume(conn);

    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(conn, msg);

    int status = 1;
    if (reply) {
        xpc_type_t reply_type = xpc_get_type(reply);
        if (reply_type != XPC_TYPE_ERROR) {
            status = 0;
        }
        xpc_release(reply);
    }

    xpc_release(msg);
    xpc_release(conn);
    printf("{\"status\":%d}\n", status);
    return status;
}
