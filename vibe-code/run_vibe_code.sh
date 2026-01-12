gcc_output=$(
  gcc -B/usr/libexec/gcc/x86_64-linux-gnu/14/ -B/usr/bin/ \
      -o /tmp/a.out -Wall -Wextra -Wpedantic -Werror $1 2>&1
)

if [ -z "$gcc_output" ]; then
  /tmp/a.out
else
  echo "GCC Error"
  exit 1
fi