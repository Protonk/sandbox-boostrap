#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char **items;
    size_t len;
    size_t cap;
} StrList;

static void list_append(StrList *list, char *value) {
    if (list->len + 1 > list->cap) {
        size_t next = list->cap == 0 ? 8 : list->cap * 2;
        char **items = (char **)realloc(list->items, next * sizeof(char *));
        if (!items) {
            fprintf(stderr, "frida_attach_helper: out of memory\n");
            exit(1);
        }
        list->items = items;
        list->cap = next;
    }
    list->items[list->len++] = value;
}

static void usage(void) {
    fprintf(stderr, "usage: frida_attach_helper [--python-exec PATH] [--python-path PATH ...] [--] <driver args>\n");
}

static char *join_python_path(const StrList *paths, const char *existing) {
    if (paths->len == 0 && (!existing || !*existing)) {
        return NULL;
    }
    size_t total = 0;
    for (size_t i = 0; i < paths->len; i++) {
        total += strlen(paths->items[i]) + 1;
    }
    if (existing && *existing) {
        total += strlen(existing) + 1;
    }
    char *buf = (char *)calloc(total + 1, 1);
    if (!buf) {
        fprintf(stderr, "frida_attach_helper: out of memory\n");
        exit(1);
    }
    size_t offset = 0;
    for (size_t i = 0; i < paths->len; i++) {
        size_t len = strlen(paths->items[i]);
        memcpy(buf + offset, paths->items[i], len);
        offset += len;
        buf[offset++] = ':';
    }
    if (existing && *existing) {
        size_t len = strlen(existing);
        memcpy(buf + offset, existing, len);
        offset += len;
        buf[offset++] = ':';
    }
    if (offset > 0) {
        buf[offset - 1] = '\0';
    }
    return buf;
}

int main(int argc, char **argv) {
    const char *python_exec = NULL;
    StrList python_paths = {0};
    StrList forward_args = {0};

    int i = 1;
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--python-exec") == 0) {
            if (i + 1 >= argc) {
                usage();
                return 2;
            }
            python_exec = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--python-path") == 0) {
            if (i + 1 >= argc) {
                usage();
                return 2;
            }
            list_append(&python_paths, argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage();
            return 0;
        }
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        list_append(&forward_args, argv[i]);
    }
    for (; i < argc; i++) {
        list_append(&forward_args, argv[i]);
    }

    char *python_path = join_python_path(&python_paths, getenv("PYTHONPATH"));
    if (python_path) {
        setenv("PYTHONPATH", python_path, 1);
        free(python_path);
    }

    const char *argv0 = python_exec ? python_exec : argv[0];
    int py_argc = 3 + (int)forward_args.len;
    char **py_argv = (char **)calloc((size_t)py_argc + 1, sizeof(char *));
    if (!py_argv) {
        fprintf(stderr, "frida_attach_helper: out of memory\n");
        return 1;
    }
    py_argv[0] = (char *)argv0;
    py_argv[1] = "-m";
    py_argv[2] = "book.api.frida.native.attach_helper.driver";
    for (size_t j = 0; j < forward_args.len; j++) {
        py_argv[3 + j] = forward_args.items[j];
    }

    wchar_t **wargv = (wchar_t **)PyMem_RawMalloc(sizeof(wchar_t *) * ((size_t)py_argc + 1));
    if (!wargv) {
        fprintf(stderr, "frida_attach_helper: out of memory\n");
        return 1;
    }
    for (int j = 0; j < py_argc; j++) {
        wargv[j] = Py_DecodeLocale(py_argv[j], NULL);
        if (!wargv[j]) {
            fprintf(stderr, "frida_attach_helper: unable to decode argv\n");
            return 1;
        }
    }
    wargv[py_argc] = NULL;

    int rc = Py_Main(py_argc, wargv);

    for (int j = 0; j < py_argc; j++) {
        PyMem_RawFree(wargv[j]);
    }
    PyMem_RawFree(wargv);
    free(py_argv);
    free(python_paths.items);
    free(forward_args.items);
    return rc;
}
