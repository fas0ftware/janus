/*
 * Unit test helper for the JSON string escaping in output.c.
 *
 * print_json_string() is 'static' (private to output.c), so this file
 * includes output.c directly to reach it. It prints a JSON array of
 * tricky strings; run_tests.sh parses it with Python's json module and
 * checks that every string survives the round trip unchanged.
 */

#include "../src/output.c"

int main(void)
{
    const char *samples[] = {
        "plain",
        "quote \" inside",
        "back\\slash",
        "new\nline and tab\t and cr\r",
        "bell \a and escape \x1b and unit separator \x1f",
        "backspace \b and form feed \f",
        "utf-8: \xc4\x9f\xc3\xbc\xc5\x9f",
        "",
    };
    size_t count = sizeof samples / sizeof samples[0];

    putchar('[');
    for (size_t i = 0; i < count; i++) {
        print_json_string(samples[i]);
        if (i + 1 < count) {
            putchar(',');
        }
    }
    puts("]");
    return 0;
}
