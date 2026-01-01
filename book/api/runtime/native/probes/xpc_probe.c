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

static const char *xpc_error_name(xpc_object_t obj) {
    if (obj == XPC_ERROR_CONNECTION_INVALID) {
        return "connection_invalid";
    }
    if (obj == XPC_ERROR_CONNECTION_INTERRUPTED) {
        return "connection_interrupted";
    }
    if (obj == XPC_ERROR_TERMINATION_IMMINENT) {
        return "termination_imminent";
    }
    return "unknown";
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }
    const char *service = argv[1];
    xpc_connection_t conn = xpc_connection_create_mach_service(service, NULL, 0);
    if (!conn) {
        printf(
            "SBL_PROBE_DETAILS {\"operation\":\"mach-lookup\",\"connected\":false,"
            "\"reply_present\":false,\"reply_type\":\"none\",\"xpc_error\":\"connection_create_failed\"}\n"
        );
        fprintf(stderr, "xpc_connection_create_mach_service failed\n");
        return 1;
    }

    xpc_connection_set_event_handler(conn, ^(xpc_object_t obj) {
        (void)obj;
    });
    xpc_connection_resume(conn);

    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(conn, msg);

    const char *reply_type_name = "none";
    const char *xpc_error = NULL;
    int reply_present = 0;
    int status = 1;
    if (reply) {
        reply_present = 1;
        xpc_type_t reply_type = xpc_get_type(reply);
        if (reply_type != XPC_TYPE_ERROR) {
            status = 0;
            reply_type_name = (reply_type == XPC_TYPE_DICTIONARY) ? "dictionary" : "other";
        } else {
            reply_type_name = "error";
            xpc_error = xpc_error_name(reply);
        }
        xpc_release(reply);
    }

    xpc_release(msg);
    xpc_release(conn);
    printf(
        "SBL_PROBE_DETAILS {\"operation\":\"mach-lookup\",\"connected\":true,\"reply_present\":%s,"
        "\"reply_type\":\"%s\"",
        reply_present ? "true" : "false",
        reply_type_name
    );
    if (xpc_error) {
        printf(",\"xpc_error\":\"%s\"", xpc_error);
    }
    printf("}\n");
    printf("{\"status\":%d}\n", status);
    return status;
}
